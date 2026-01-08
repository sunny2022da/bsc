package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/parlia"
	"github.com/ethereum/go-ethereum/core"
	mir "github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler/MIR"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

func isSystemTx(engine consensus.Engine, tx *types.Transaction, header *types.Header) bool {
	posa, ok := engine.(consensus.PoSA)
	if !ok || posa == nil || header == nil || tx == nil {
		return false
	}
	isSys, err := posa.IsSystemTransaction(tx, header)
	if err != nil {
		return false
	}
	return isSys
}

func openChainDB(chaindata string, readonly bool) (ethdb.Database, func(), error) {
	kv, err := pebble.New(chaindata, 512, 512, "mirreplay", readonly)
	if err != nil {
		return nil, nil, err
	}
	ancient := filepath.Join(chaindata, "ancient")
	db, err := rawdb.Open(kv, rawdb.OpenOptions{
		Ancient:          ancient,
		MetricsNamespace: "mirreplay",
		ReadOnly:         readonly,
	})
	if err != nil {
		_ = kv.Close()
		return nil, nil, err
	}
	cleanup := func() {
		_ = db.Close()
	}
	return db, cleanup, nil
}

type replayEnv struct {
	db        ethdb.Database
	cfg       *params.ChainConfig
	genesis   common.Hash
	engine    consensus.Engine
	chain     *core.HeaderChain
	processor *core.StateProcessor
	statedb   *state.StateDB
}

func newReplayEnvWithState(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, statedb *state.StateDB) (*replayEnv, error) {
	engine := parlia.New(cfg, db, nil, genesisHash)
	chain, err := core.NewHeaderChain(db, cfg, engine, func() bool { return false })
	if err != nil {
		return nil, fmt.Errorf("NewHeaderChain: %w", err)
	}
	processor := core.NewStateProcessor(cfg, chain)
	return &replayEnv{
		db:        db,
		cfg:       cfg,
		genesis:   genesisHash,
		engine:    engine,
		chain:     chain,
		processor: processor,
		statedb:   statedb,
	}, nil
}

// newReplayEnv constructs a replay environment with a clean genesis state reconstructed from the
// persisted genesis alloc spec. This is the most robust mode, but requires the datadir to contain
// blocks from genesis and is slower to reach high blocks.
func newReplayEnv(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash) (*replayEnv, error) {
	genHeader := rawdb.ReadHeader(db, genesisHash, 0)
	if genHeader == nil {
		return nil, fmt.Errorf("missing genesis header %s", genesisHash)
	}

	allocBlob := rawdb.ReadGenesisStateSpec(db, genesisHash)
	if len(allocBlob) == 0 {
		return nil, fmt.Errorf("missing genesis allocation spec for %s", genesisHash)
	}
	var alloc types.GenesisAlloc
	if err := alloc.UnmarshalJSON(allocBlob); err != nil {
		return nil, fmt.Errorf("unmarshal genesis alloc: %w", err)
	}
	stateDB := rawdb.NewMemoryDatabase()
	stateTrieDB := triedb.NewDatabase(stateDB, triedb.HashDefaults)
	root, err := flushAllocForReplay(&alloc, stateTrieDB)
	if err != nil {
		return nil, fmt.Errorf("flush genesis alloc: %w", err)
	}
	if root != genHeader.Root {
		return nil, fmt.Errorf("genesis root mismatch: computed=%s header=%s", root, genHeader.Root)
	}
	statedb, err := state.New(root, state.NewDatabase(stateTrieDB, nil))
	if err != nil {
		return nil, fmt.Errorf("state.New(genesisRoot): %w", err)
	}
	return newReplayEnvWithState(db, cfg, genesisHash, statedb)
}

// newReplayEnvAtBlockState initializes statedb directly from the on-disk state root of block `n`.
// This is much faster for investigating a specific block range, but requires the datadir to have
// the necessary trie nodes for that state root.
func newReplayEnvAtBlockState(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, n uint64) (*replayEnv, error) {
	h := rawdb.ReadCanonicalHash(db, n)
	if h == (common.Hash{}) {
		return nil, fmt.Errorf("missing canonical hash for block %d", n)
	}
	header := rawdb.ReadHeader(db, h, n)
	if header == nil {
		return nil, fmt.Errorf("missing header for block %d (%s)", n, h)
	}
	// Auto-detect hash/path scheme based on db metadata.
	tdb := triedb.NewDatabase(db, nil)
	statedb, err := state.New(header.Root, state.NewDatabase(tdb, nil))
	if err != nil {
		return nil, fmt.Errorf("state.New(root @%d %s): %w", n, header.Root, err)
	}
	return newReplayEnvWithState(db, cfg, genesisHash, statedb)
}

func (e *replayEnv) runUpTo(target uint64, enableMIR bool, progress bool) error {
	vmCfg := vm.Config{
		EnableOpcodeOptimizations: false,
		EnableMIR:                 enableMIR,
	}
	for n := uint64(1); n <= target; n++ {
		h := rawdb.ReadCanonicalHash(e.db, n)
		if h == (common.Hash{}) {
			return fmt.Errorf("missing canonical hash for block %d", n)
		}
		blk := rawdb.ReadBlock(e.db, h, n)
		if blk == nil {
			return fmt.Errorf("missing block %d (%s)", n, h)
		}
		if _, err := e.processor.Process(blk, e.statedb, vmCfg); err != nil {
			return fmt.Errorf("Process block %d (%s): %w", n, h, err)
		}
		if progress && (n == 1 || n == 10 || n == 50 || n == 80 || n == target) {
			fmt.Printf("ok: processed block %d\n", n)
		}
	}
	return nil
}

type txRun struct {
	receiptsByIndex map[int]*types.Receipt
	cumGasByIndex   map[int]uint64
	rootByIndex     map[int]common.Hash
	totalGasUsed    uint64
	finalRoot       common.Hash
}

func processCommonTxsOnly(engine consensus.Engine, chain *core.HeaderChain, cfg *params.ChainConfig, statedb *state.StateDB, blk *types.Block, enableMIR bool) (*txRun, error) {
	header := blk.Header()
	blockHash := blk.Hash()
	blockNumber := blk.Number()

	// Mirror state_processor preamble that can affect system contracts.
	lastBlock := chain.GetHeaderByHash(blk.ParentHash())
	if lastBlock == nil {
		return nil, fmt.Errorf("missing parent header %s", blk.ParentHash())
	}
	systemcontracts.TryUpdateBuildInSystemContract(cfg, blockNumber, lastBlock.Time, blk.Time(), statedb, true)

	ctx := core.NewEVMBlockContext(header, chain, nil)
	evm := vm.NewEVM(ctx, statedb, cfg, vm.Config{
		EnableOpcodeOptimizations: false,
		EnableMIR:                 enableMIR,
	})
	if enableMIR {
		evm.SetMIRRunner(mir.NewEVMRunner(evm))
	}

	signer := types.MakeSigner(cfg, header.Number, header.Time)
	gp := new(core.GasPool).AddGas(blk.GasLimit())
	usedGas := new(uint64)

	out := &txRun{
		receiptsByIndex: make(map[int]*types.Receipt, 8),
		cumGasByIndex:   make(map[int]uint64, 8),
		rootByIndex:     make(map[int]common.Hash, 8),
	}

	for i, tx := range blk.Transactions() {
		if isSystemTx(engine, tx, header) {
			continue
		}
		msg, err := core.TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("TransactionToMessage idx=%d hash=%s: %w", i, tx.Hash(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := core.ApplyTransactionWithEVM(msg, gp, statedb, header.Number, blockHash, header.Time, tx, usedGas, evm)
		if err != nil {
			return nil, fmt.Errorf("ApplyTransaction idx=%d hash=%s: %w", i, tx.Hash(), err)
		}
		out.receiptsByIndex[i] = receipt
		out.cumGasByIndex[i] = *usedGas
		out.rootByIndex[i] = statedb.IntermediateRoot(cfg.IsEIP158(header.Number))
	}
	out.totalGasUsed = *usedGas
	out.finalRoot = statedb.IntermediateRoot(cfg.IsEIP158(header.Number))
	return out, nil
}

func fmtReceipt(r *types.Receipt) string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("status=%d gasUsed=%d cumGas=%d logs=%d", r.Status, r.GasUsed, r.CumulativeGasUsed, len(r.Logs))
}

type evmStep struct {
	pc    uint64
	op    byte
	gas   uint64
	cost  uint64
	depth int
	err   error
}

type mirStep struct {
	evmPC   uint
	evmOp   byte
	op      mir.MirOperation
	gasLeft uint64
}

type pcOp struct {
	pc uint64
	op byte
}

func isIgnorableBaseOp(op byte) bool {
	// MIR does not emit runtime MIR for these stack/marker ops; they are modeled structurally.
	// We skip them when aligning native EVM opcode stream against MIR's step stream.
	if op == 0x5b { // JUMPDEST
		return true
	}
	if op >= 0x60 && op <= 0x7f { // PUSH1..PUSH32
		return true
	}
	if op >= 0x80 && op <= 0x8f { // DUP1..DUP16
		return true
	}
	if op >= 0x90 && op <= 0x9f { // SWAP1..SWAP16
		return true
	}
	return false
}

func trimHex(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	s := fmt.Sprintf("%x", b)
	if max > 0 && len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func applyTxWithResult(evm *vm.EVM, statedb *state.StateDB, header *types.Header, tx *types.Transaction, idx int, usedGas *uint64, gp *core.GasPool) (*types.Receipt, *core.ExecutionResult, error) {
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(evm.ChainConfig(), header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	statedb.SetTxContext(tx.Hash(), idx)
	res, err := core.ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, res, err
	}
	var root []byte
	if evm.ChainConfig().IsByzantium(header.Number) {
		evm.StateDB.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(evm.ChainConfig().IsEIP158(header.Number)).Bytes()
	}
	*usedGas += res.UsedGas
	receipt := core.MakeReceipt(evm, res, statedb, header.Number, header.Hash(), header.Time, tx, *usedGas, root)
	return receipt, res, nil
}

func debugOneTx(engine consensus.Engine, chain *core.HeaderChain, cfg *params.ChainConfig, preState *state.StateDB, blk *types.Block, txIndex int) string {
	header := blk.Header()
	blockHash := blk.Hash()
	_ = blockHash

	var sb strings.Builder
	tx := blk.Transactions()[txIndex]
	signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
	from, _ := types.Sender(signer, tx)
	to := "<create>"
	if tx.To() != nil {
		to = tx.To().Hex()
	}
	sb.WriteString(fmt.Sprintf("=== Debug tx idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s ===\n",
		txIndex, tx.Hash(), from, to, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value()))
	lastBlock := chain.GetHeaderByHash(blk.ParentHash())
	if lastBlock == nil {
		sb.WriteString("missing parent header\n")
		return sb.String()
	}

	// Prepare base (native) EVM run with tracer ring buffer.
	baseState := preState.Copy()
	systemcontracts.TryUpdateBuildInSystemContract(cfg, blk.Number(), lastBlock.Time, blk.Time(), baseState, true)
	baseTrace := make([]evmStep, 0, 64)
	baseCalls := make([]string, 0, 32)
	baseOperands := make([]string, 0, 64)
	baseArith := make([]string, 0, 32)
	baseMstore40 := make([]string, 0, 8)
	baseAdd3393 := make([]string, 0, 8)
	baseLoopJumps := make([]string, 0, 32)
	baseWin280 := make([]string, 0, 128)
	baseStateChg := make([]string, 0, 128)
	baseLogs := make([]string, 0, 64)
	baseOps := make([]pcOp, 0, 4096)
	var lastBasePC uint64
	var lastBaseOp byte
	curBasePC := uint64(0)
	pushBaseChg := func(s string) {
		if len(baseStateChg) == cap(baseStateChg) {
			copy(baseStateChg, baseStateChg[1:])
			baseStateChg = baseStateChg[:cap(baseStateChg)-1]
		}
		baseStateChg = append(baseStateChg, s)
	}
	pushBaseLog := func(s string) {
		if len(baseLogs) == cap(baseLogs) {
			copy(baseLogs, baseLogs[1:])
			baseLogs = baseLogs[:cap(baseLogs)-1]
		}
		baseLogs = append(baseLogs, s)
	}
	baseTracer := &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, _ []byte, depth int, err error) {
		lastBasePC, lastBaseOp = pc, op
		if depth == 1 {
			curBasePC = pc
		}
		// Record only the top-level contract frame (depth==1) so we can align vs MIR (which runs at depth 0).
		if depth == 1 && len(baseOps) < cap(baseOps) {
			baseOps = append(baseOps, pcOp{pc: pc, op: op})
		}
		// Capture JUMP/JUMPI/SSTORE/OR/SLOAD/STATICCALL operands from the native EVM stack at depth==1.
		if depth == 1 && scope != nil && (op == 0x56 || op == 0x57 || op == 0x55 || op == 0x17 || op == 0x54 || op == 0xfa) {
			st := scope.StackData()
			// Keep a small ring
			if len(baseOperands) == cap(baseOperands) {
				copy(baseOperands, baseOperands[1:])
				baseOperands = baseOperands[:cap(baseOperands)-1]
			}
			if op == 0x56 {
				// JUMP: dest is top-of-stack
				if len(st) > 0 {
					d := st[len(st)-1]
					baseOperands = append(baseOperands, fmt.Sprintf("JUMP  pc=%d dest=0x%s stackLen=%d", pc, d.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("JUMP  pc=%d <empty stack>", pc))
				}
			} else if op == 0x55 {
				// SSTORE: key is top, value is next.
				if len(st) > 1 {
					k := st[len(st)-1]
					v := st[len(st)-2]
					baseOperands = append(baseOperands, fmt.Sprintf("SSTORE pc=%d k=0x%s v=0x%s stackLen=%d", pc, k.Hex(), v.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("SSTORE pc=%d <short stack len=%d>", pc, len(st)))
				}
			} else if op == 0x17 {
				// OR: pops a, b (a=top), pushes a|b
				if len(st) > 1 {
					a := st[len(st)-1]
					b := st[len(st)-2]
					baseOperands = append(baseOperands, fmt.Sprintf("OR    pc=%d a=0x%s b=0x%s stackLen=%d", pc, a.Hex(), b.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("OR    pc=%d <short stack len=%d>", pc, len(st)))
				}
			} else if op == 0x54 {
				// SLOAD: key is top-of-stack
				if len(st) > 0 {
					k := st[len(st)-1]
					baseOperands = append(baseOperands, fmt.Sprintf("SLOAD pc=%d k=0x%s stackLen=%d", pc, k.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("SLOAD pc=%d <empty stack>", pc))
				}
			} else if op == 0xfa {
				// STATICCALL: pops gas, to, inOff, inSize, outOff, outSize (outSize is top-of-stack)
				if len(st) >= 6 {
					outSz := st[len(st)-1]
					outOff := st[len(st)-2]
					inSz := st[len(st)-3]
					inOff := st[len(st)-4]
					to := st[len(st)-5]
					g := st[len(st)-6]
					baseOperands = append(baseOperands, fmt.Sprintf("STATICCALL pc=%d gas=0x%s to=0x%s inOff=0x%s inSz=0x%s outOff=0x%s outSz=0x%s stackLen=%d",
						pc, g.Hex(), to.Hex(), inOff.Hex(), inSz.Hex(), outOff.Hex(), outSz.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("STATICCALL pc=%d <short stack len=%d>", pc, len(st)))
				}
			} else {
				// JUMPI: dest is top, cond is next
				if len(st) > 1 {
					d := st[len(st)-1]
					c := st[len(st)-2]
					baseOperands = append(baseOperands, fmt.Sprintf("JUMPI pc=%d dest=0x%s cond=0x%s stackLen=%d", pc, d.Hex(), c.Hex(), len(st)))
				} else if len(st) == 1 {
					d := st[len(st)-1]
					baseOperands = append(baseOperands, fmt.Sprintf("JUMPI pc=%d dest=0x%s <missing cond> stackLen=%d", pc, d.Hex(), len(st)))
				} else {
					baseOperands = append(baseOperands, fmt.Sprintf("JUMPI pc=%d <empty stack>", pc))
				}
			}
		}
		// Capture arithmetic operands (tail) to help diagnose stack-math divergences.
		if depth == 1 && scope != nil && op == 0x03 { // SUB
			st := scope.StackData()
			if len(st) >= 2 {
				x := st[len(st)-1] // top
				y := st[len(st)-2] // next
				if len(baseArith) == cap(baseArith) {
					copy(baseArith, baseArith[1:])
					baseArith = baseArith[:cap(baseArith)-1]
				}
				baseArith = append(baseArith, fmt.Sprintf("SUB pc=%d x(top)=0x%s y(next)=0x%s stackLen=%d", pc, x.Hex(), y.Hex(), len(st)))
			}
		}
		// Capture writes to memory slot 0x40 (free memory pointer).
		if depth == 1 && scope != nil && op == 0x52 { // MSTORE
			st := scope.StackData()
			// EVM MSTORE pops offset (top), value (next)
			if len(st) >= 2 {
				off := st[len(st)-1]
				val := st[len(st)-2]
				if off.IsUint64() && off.Uint64() == 0x40 {
					if len(baseMstore40) == cap(baseMstore40) {
						copy(baseMstore40, baseMstore40[1:])
						baseMstore40 = baseMstore40[:cap(baseMstore40)-1]
					}
					baseMstore40 = append(baseMstore40, fmt.Sprintf("MSTORE pc=%d off=0x40 val=0x%s", pc, val.Hex()))
				}
			}
		}
		// Targeted capture: the ADD feeding the free-memory update in this bad block.
		if depth == 1 && scope != nil && op == 0x01 && pc == 3393 { // ADD @3393
			st := scope.StackData()
			if len(st) >= 2 {
				x := st[len(st)-1]
				y := st[len(st)-2]
				if len(baseAdd3393) == cap(baseAdd3393) {
					copy(baseAdd3393, baseAdd3393[1:])
					baseAdd3393 = baseAdd3393[:cap(baseAdd3393)-1]
				}
				baseAdd3393 = append(baseAdd3393, fmt.Sprintf("ADD pc=3393 x(top)=0x%s y(next)=0x%s", x.Hex(), y.Hex()))
			}
		}
		// Capture control-flow around the memory allocator region.
		if depth == 1 && scope != nil && pc >= 3300 && pc <= 3500 && (op == 0x56 || op == 0x57) {
			st := scope.StackData()
			if op == 0x56 && len(st) >= 1 {
				d := st[len(st)-1]
				if len(baseLoopJumps) == cap(baseLoopJumps) {
					copy(baseLoopJumps, baseLoopJumps[1:])
					baseLoopJumps = baseLoopJumps[:cap(baseLoopJumps)-1]
				}
				baseLoopJumps = append(baseLoopJumps, fmt.Sprintf("JUMP  pc=%d dest=0x%s stackLen=%d", pc, d.Hex(), len(st)))
			}
			if op == 0x57 && len(st) >= 2 {
				d := st[len(st)-1]
				c := st[len(st)-2]
				if len(baseLoopJumps) == cap(baseLoopJumps) {
					copy(baseLoopJumps, baseLoopJumps[1:])
					baseLoopJumps = baseLoopJumps[:cap(baseLoopJumps)-1]
				}
				baseLoopJumps = append(baseLoopJumps, fmt.Sprintf("JUMPI pc=%d dest=0x%s cond=0x%s stackLen=%d", pc, d.Hex(), c.Hex(), len(st)))
			}
		}
		// Capture a small window around the failing STATICCALL arg-prep for this bug class.
		if depth == 1 && scope != nil && pc >= 280 && pc <= 310 {
			st := scope.StackData()
			top := func(i int) string {
				if i <= 0 || len(st) < i {
					return ""
				}
				return st[len(st)-i].Hex()
			}
			if len(baseWin280) == cap(baseWin280) {
				copy(baseWin280, baseWin280[1:])
				baseWin280 = baseWin280[:cap(baseWin280)-1]
			}
			baseWin280 = append(baseWin280, fmt.Sprintf("pc=%d op=0x%02x top1=0x%s top2=0x%s top3=0x%s top4=0x%s stackLen=%d",
				pc, op, top(1), top(2), top(3), top(4), len(st)))
		}
		if len(baseTrace) == cap(baseTrace) {
			copy(baseTrace, baseTrace[1:])
			baseTrace = baseTrace[:cap(baseTrace)-1]
		}
		baseTrace = append(baseTrace, evmStep{pc: pc, op: op, gas: gas, cost: cost, depth: depth, err: err})
	}, OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
		pushBaseChg(fmt.Sprintf("BAL  pc=%d addr=%s prev=%s new=%s reason=%v", curBasePC, addr, prev, new, reason))
	}, OnNonceChange: func(addr common.Address, prev, new uint64) {
		pushBaseChg(fmt.Sprintf("NONCE pc=%d addr=%s prev=%d new=%d", curBasePC, addr, prev, new))
	}, OnCodeChange: func(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
		pushBaseChg(fmt.Sprintf("CODE pc=%d addr=%s prevHash=%s newHash=%s prevLen=%d newLen=%d", curBasePC, addr, prevCodeHash, codeHash, len(prevCode), len(code)))
	}, OnStorageChange: func(addr common.Address, slot common.Hash, prev, new common.Hash) {
		pushBaseChg(fmt.Sprintf("SLOT pc=%d addr=%s slot=%s prev=%s new=%s", curBasePC, addr, slot, prev, new))
	}, OnLog: func(l *types.Log) {
		if l == nil {
			return
		}
		t0 := common.Hash{}
		if len(l.Topics) > 0 {
			t0 = l.Topics[0]
		}
		pushBaseLog(fmt.Sprintf("LOG  pc=%d addr=%s topics=%d t0=%s data=%d", curBasePC, l.Address, len(l.Topics), t0, len(l.Data)))
	}, OnEnter: func(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
		// keep a small ring
		if len(baseCalls) == cap(baseCalls) {
			copy(baseCalls, baseCalls[1:])
			baseCalls = baseCalls[:cap(baseCalls)-1]
		}
		baseCalls = append(baseCalls, fmt.Sprintf("enter depth=%d typ=0x%02x from=%s to=%s gas=%d input=%d value=%s", depth, typ, from, to, gas, len(input), value))
	}, OnExit: func(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
		if len(baseCalls) == cap(baseCalls) {
			copy(baseCalls, baseCalls[1:])
			baseCalls = baseCalls[:cap(baseCalls)-1]
		}
		baseCalls = append(baseCalls, fmt.Sprintf("exit  depth=%d gasUsed=%d reverted=%v err=%v output=%d", depth, gasUsed, reverted, err, len(output)))
	}}
	// Apply preceding common txs first to get correct nonce/state context for this txIndex.
	{
		prefixEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), baseState, cfg, vm.Config{EnableMIR: false})
		prefixGP := new(core.GasPool).AddGas(blk.GasLimit())
		prefixUsed := uint64(0)
		for i := 0; i < txIndex; i++ {
			ptx := blk.Transactions()[i]
			if isSystemTx(engine, ptx, header) {
				continue
			}
			_, _, _ = applyTxWithResult(prefixEVM, baseState, header, ptx, i, &prefixUsed, prefixGP)
		}
	}
	// Wrap statedb to receive state-change callbacks (balance/storage/nonce/code).
	baseHooked := state.NewHookedState(baseState, baseTracer)
	baseEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), baseHooked, cfg, vm.Config{EnableMIR: false, Tracer: baseTracer})
	baseGP := new(core.GasPool).AddGas(blk.GasLimit())
	baseUsed := uint64(0)
	baseReceipt, baseRes, baseErr := applyTxWithResult(baseEVM, baseState, header, tx, txIndex, &baseUsed, baseGP)
	sb.WriteString(fmt.Sprintf("BASE: err=%v res.Err=%v usedGas=%d maxUsedGas=%d receipt={%s} revert=%s\n", baseErr, func() any {
		if baseRes == nil {
			return nil
		}
		return baseRes.Err
	}(), func() uint64 {
		if baseRes == nil {
			return 0
		}
		return baseRes.UsedGas
	}(), func() uint64 {
		if baseRes == nil {
			return 0
		}
		return baseRes.MaxUsedGas
	}(), fmtReceipt(baseReceipt), trimHex(func() []byte {
		if baseRes == nil {
			return nil
		}
		return baseRes.Revert()
	}(), 160)))

	// Prepare MIR run with step hook ring buffer.
	mirState := preState.Copy()
	systemcontracts.TryUpdateBuildInSystemContract(cfg, blk.Number(), lastBlock.Time, blk.Time(), mirState, true)
	mirTrace := make([]mirStep, 0, 256)
	mirCalls := make([]string, 0, 32)
	mirOperands := make([]string, 0, 64)
	mirCallArgs := make([]string, 0, 16)
	mirMstore40 := make([]string, 0, 8)
	mirAdd3393 := make([]string, 0, 8)
	mirLoopJumps := make([]string, 0, 32)
	mirPhi := make([]string, 0, 64)
	mirStateChg := make([]string, 0, 128)
	mirLogs := make([]string, 0, 64)
	// If MIR internally falls back into the native interpreter (e.g. due to an error + retry),
	// these opcodes will show up here. Pure MIR execution should NOT produce OnOpcode events.
	mirFallbackOps := make([]evmStep, 0, 64)
	mirOps := make([]pcOp, 0, 4096)
	var lastMirPC uint
	var lastMirOp byte
	pushMirChg := func(s string) {
		if len(mirStateChg) == cap(mirStateChg) {
			copy(mirStateChg, mirStateChg[1:])
			mirStateChg = mirStateChg[:cap(mirStateChg)-1]
		}
		mirStateChg = append(mirStateChg, s)
	}
	pushMirLog := func(s string) {
		if len(mirLogs) == cap(mirLogs) {
			copy(mirLogs, mirLogs[1:])
			mirLogs = mirLogs[:cap(mirLogs)-1]
		}
		mirLogs = append(mirLogs, s)
	}
	mirTracer := &tracing.Hooks{
		OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, _ []byte, depth int, err error) {
			// Record only top-level frame to keep signal clean.
			if depth != 1 {
				return
			}
			if len(mirFallbackOps) == cap(mirFallbackOps) {
				copy(mirFallbackOps, mirFallbackOps[1:])
				mirFallbackOps = mirFallbackOps[:cap(mirFallbackOps)-1]
			}
			mirFallbackOps = append(mirFallbackOps, evmStep{pc: pc, op: op, gas: gas, cost: cost, depth: depth, err: err})
		},
		OnBalanceChange: func(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {
			pushMirChg(fmt.Sprintf("BAL  pc=%d addr=%s prev=%s new=%s reason=%v", lastMirPC, addr, prev, new, reason))
		},
		OnNonceChange: func(addr common.Address, prev, new uint64) {
			pushMirChg(fmt.Sprintf("NONCE pc=%d addr=%s prev=%d new=%d", lastMirPC, addr, prev, new))
		},
		OnCodeChange: func(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte) {
			pushMirChg(fmt.Sprintf("CODE pc=%d addr=%s prevHash=%s newHash=%s prevLen=%d newLen=%d", lastMirPC, addr, prevCodeHash, codeHash, len(prevCode), len(code)))
		},
		OnStorageChange: func(addr common.Address, slot common.Hash, prev, new common.Hash) {
			pushMirChg(fmt.Sprintf("SLOT pc=%d addr=%s slot=%s prev=%s new=%s", lastMirPC, addr, slot, prev, new))
		},
		OnLog: func(l *types.Log) {
			if l == nil {
				return
			}
			t0 := common.Hash{}
			if len(l.Topics) > 0 {
				t0 = l.Topics[0]
			}
			pushMirLog(fmt.Sprintf("LOG  pc=%d addr=%s topics=%d t0=%s data=%d", lastMirPC, l.Address, len(l.Topics), t0, len(l.Data)))
		},
		OnEnter: func(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
			if len(mirCalls) == cap(mirCalls) {
				copy(mirCalls, mirCalls[1:])
				mirCalls = mirCalls[:cap(mirCalls)-1]
			}
			mirCalls = append(mirCalls, fmt.Sprintf("enter depth=%d typ=0x%02x from=%s to=%s gas=%d input=%d value=%s", depth, typ, from, to, gas, len(input), value))
		},
		OnExit: func(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
			if len(mirCalls) == cap(mirCalls) {
				copy(mirCalls, mirCalls[1:])
				mirCalls = mirCalls[:cap(mirCalls)-1]
			}
			mirCalls = append(mirCalls, fmt.Sprintf("exit  depth=%d gasUsed=%d reverted=%v err=%v output=%d", depth, gasUsed, reverted, err, len(output)))
		},
	}
	// Apply preceding common txs first (with MIR enabled) so the sender nonces match the real block.
	{
		prefixEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), mirState, cfg, vm.Config{EnableMIR: true})
		prefixRunner := mir.NewEVMRunner(prefixEVM)
		prefixEVM.SetMIRRunner(prefixRunner)
		prefixGP := new(core.GasPool).AddGas(blk.GasLimit())
		prefixUsed := uint64(0)
		for i := 0; i < txIndex; i++ {
			ptx := blk.Transactions()[i]
			if isSystemTx(engine, ptx, header) {
				continue
			}
			_, _, _ = applyTxWithResult(prefixEVM, mirState, header, ptx, i, &prefixUsed, prefixGP)
		}
	}

	mirHooked := state.NewHookedState(mirState, mirTracer)
	mirEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), mirHooked, cfg, vm.Config{EnableMIR: true, Tracer: mirTracer})
	runner := mir.NewEVMRunner(mirEVM)
	runner.SetMIRStepHookFactory(func(it *mir.MIRInterpreter) func(evmPC uint, evmOp byte, op mir.MirOperation) {
		// Capture key control-flow operands (JUMP/JUMPI dest + cond) with def provenance.
		// This is critical for debugging bad blocks caused by invalid jumpdest/CFG issues.
		if it != nil {
			it.SetDebugPhiHook(func(curFirstPC uint, prevFirstPC uint, phiPC uint, phiStackIndex int, incomingLen int, incomingIdx int, val uint256.Int) {
				// Keep a small ring buffer.
				if len(mirPhi) == cap(mirPhi) {
					copy(mirPhi, mirPhi[1:])
					mirPhi = mirPhi[:cap(mirPhi)-1]
				}
				// Focus: PHI near the failing region, but keep generic formatting.
				mirPhi = append(mirPhi, fmt.Sprintf("PHI phiPC=%d curBB=%d prevBB=%d phiIdx=%d inLen=%d inIdx=%d val=0x%s", phiPC, curFirstPC, prevFirstPC, phiStackIndex, incomingLen, incomingIdx, val.Hex()))
			})
			it.SetDebugOperandHookEx(func(evmPC uint, evmOp byte, op mir.MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp mir.MirOperation, bDefOp mir.MirOperation) {
				// Keep a small ring buffer.
				if len(mirOperands) == cap(mirOperands) {
					copy(mirOperands, mirOperands[1:])
					mirOperands = mirOperands[:cap(mirOperands)-1]
				}
				switch op {
				case mir.MirAND:
					mirOperands = append(mirOperands, fmt.Sprintf("AND   evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSLOAD:
					mirOperands = append(mirOperands, fmt.Sprintf("SLOAD evmPC=%d k=0x%s kDefPC=%d kDefOp=%s", evmPC, a.Hex(), aDefPC, aDefOp.String()))
				case mir.MirMLOAD:
					// For MLOAD we encode: a=offset, b=loadedWord (best-effort).
					mirOperands = append(mirOperands, fmt.Sprintf("MLOAD evmPC=%d off=0x%s loaded=0x%s offDefPC=%d offDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String()))
				case mir.MirMSTORE:
					mirOperands = append(mirOperands, fmt.Sprintf("MSTORE evmPC=%d off=0x%s val=0x%s offDefPC=%d offDefOp=%s valDefPC=%d valDefOp=%s",
						evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if a.IsUint64() && a.Uint64() == 0x40 {
						if len(mirMstore40) == cap(mirMstore40) {
							copy(mirMstore40, mirMstore40[1:])
							mirMstore40 = mirMstore40[:cap(mirMstore40)-1]
						}
						mirMstore40 = append(mirMstore40, fmt.Sprintf("MSTORE evmPC=%d off=0x40 val=0x%s valDefPC=%d valDefOp=%s", evmPC, b.Hex(), bDefPC, bDefOp.String()))
					}
				case mir.MirADD:
					mirOperands = append(mirOperands, fmt.Sprintf("ADD   evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if evmPC == 3393 {
						if len(mirAdd3393) == cap(mirAdd3393) {
							copy(mirAdd3393, mirAdd3393[1:])
							mirAdd3393 = mirAdd3393[:cap(mirAdd3393)-1]
						}
						var sum uint256.Int
						sum.Add(&a, &b)
						mirAdd3393 = append(mirAdd3393, fmt.Sprintf("ADD evmPC=3393 a=0x%s b=0x%s sum=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s",
							a.Hex(), b.Hex(), sum.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					}
				case mir.MirSTATICCALL:
					mirOperands = append(mirOperands, fmt.Sprintf("STATICCALL evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s",
						evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSUB:
					mirOperands = append(mirOperands, fmt.Sprintf("SUB   evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirOR:
					mirOperands = append(mirOperands, fmt.Sprintf("OR    evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSSTORE:
					mirOperands = append(mirOperands, fmt.Sprintf("SSTORE evmPC=%d k=0x%s v=0x%s kDefPC=%d kDefOp=%s vDefPC=%d vDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirJUMP:
					mirOperands = append(mirOperands, fmt.Sprintf("JUMP  evmPC=%d a(dest)=0x%s aDefPC=%d aDefOp=%s", evmPC, a.Hex(), aDefPC, aDefOp.String()))
					if evmPC >= 3300 && evmPC <= 3500 {
						if len(mirLoopJumps) == cap(mirLoopJumps) {
							copy(mirLoopJumps, mirLoopJumps[1:])
							mirLoopJumps = mirLoopJumps[:cap(mirLoopJumps)-1]
						}
						mirLoopJumps = append(mirLoopJumps, fmt.Sprintf("JUMP  evmPC=%d dest=0x%s aDefPC=%d aDefOp=%s", evmPC, a.Hex(), aDefPC, aDefOp.String()))
					}
				case mir.MirJUMPI:
					mirOperands = append(mirOperands, fmt.Sprintf("JUMPI evmPC=%d a(dest)=0x%s b(cond)=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if evmPC >= 3300 && evmPC <= 3500 {
						if len(mirLoopJumps) == cap(mirLoopJumps) {
							copy(mirLoopJumps, mirLoopJumps[1:])
							mirLoopJumps = mirLoopJumps[:cap(mirLoopJumps)-1]
						}
						mirLoopJumps = append(mirLoopJumps, fmt.Sprintf("JUMPI evmPC=%d dest=0x%s cond=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					}
				default:
					// Other ops are ignored for now.
				}
			})
			it.SetDebugCallArgsHook(func(evmPC uint, evmOp byte, op mir.MirOperation, gasReq uint256.Int, to common.Address,
				inOff uint256.Int, inOffDefPC uint, inOffDefOp mir.MirOperation,
				inSz uint256.Int, inSzDefPC uint, inSzDefOp mir.MirOperation,
				outOff uint256.Int, outOffDefPC uint, outOffDefOp mir.MirOperation,
				outSz uint256.Int, outSzDefPC uint, outSzDefOp mir.MirOperation,
				inOffOv bool, inSzOv bool, outOffOv bool, outSzOv bool) {
				if len(mirCallArgs) == cap(mirCallArgs) {
					copy(mirCallArgs, mirCallArgs[1:])
					mirCallArgs = mirCallArgs[:cap(mirCallArgs)-1]
				}
				mirCallArgs = append(mirCallArgs, fmt.Sprintf("%s evmPC=%d evmOp=0x%02x to=%s gas=0x%s inOff=0x%s(inDefPC=%d inDefOp=%s) inSz=0x%s(szDefPC=%d szDefOp=%s) outOff=0x%s(outDefPC=%d outDefOp=%s) outSz=0x%s(outSzDefPC=%d outSzDefOp=%s) ov(inOff,inSz,outOff,outSz)=%v,%v,%v,%v",
					op.String(), evmPC, evmOp, to.Hex(), gasReq.Hex(),
					inOff.Hex(), inOffDefPC, inOffDefOp.String(),
					inSz.Hex(), inSzDefPC, inSzDefOp.String(),
					outOff.Hex(), outOffDefPC, outOffDefOp.String(),
					outSz.Hex(), outSzDefPC, outSzDefOp.String(),
					inOffOv, inSzOv, outOffOv, outSzOv))
			})
		}
		return func(evmPC uint, evmOp byte, op mir.MirOperation) {
			lastMirPC, lastMirOp = evmPC, evmOp
			// Skip JUMPDEST markers (MIR can attribute PHIs to a block's entry JUMPDEST).
			if evmOp != 0x5b && len(mirOps) < cap(mirOps) {
				mirOps = append(mirOps, pcOp{pc: uint64(evmPC), op: evmOp})
			}
			if len(mirTrace) == cap(mirTrace) {
				copy(mirTrace, mirTrace[1:])
				mirTrace = mirTrace[:cap(mirTrace)-1]
			}
			gasLeft := uint64(0)
			if it != nil {
				if it.GasLimit() == 0 {
					gasLeft = ^uint64(0)
				} else if it.GasUsed() >= it.GasLimit() {
					gasLeft = 0
				} else {
					gasLeft = it.GasLimit() - it.GasUsed()
				}
			}
			mirTrace = append(mirTrace, mirStep{evmPC: evmPC, evmOp: evmOp, op: op, gasLeft: gasLeft})
		}
	})
	mirEVM.SetMIRRunner(runner)
	mirGP := new(core.GasPool).AddGas(blk.GasLimit())
	mirUsed := uint64(0)
	mirReceipt, mirRes, mirErr := applyTxWithResult(mirEVM, mirState, header, tx, txIndex, &mirUsed, mirGP)
	sb.WriteString(fmt.Sprintf("MIR : err=%v res.Err=%v usedGas=%d maxUsedGas=%d receipt={%s} revert=%s\n", mirErr, func() any {
		if mirRes == nil {
			return nil
		}
		return mirRes.Err
	}(), func() uint64 {
		if mirRes == nil {
			return 0
		}
		return mirRes.UsedGas
	}(), func() uint64 {
		if mirRes == nil {
			return 0
		}
		return mirRes.MaxUsedGas
	}(), fmtReceipt(mirReceipt), trimHex(func() []byte {
		if mirRes == nil {
			return nil
		}
		return mirRes.Revert()
	}(), 160)))
	sb.WriteString(fmt.Sprintf("BASE last opcode pc=%d op=0x%02x | MIR last evmPC=%d evmOp=0x%02x\n", lastBasePC, lastBaseOp, lastMirPC, lastMirOp))

	// Best-effort: find first divergence in (pc,op) stream. Note MIR stream is sourced from MIR step hook
	// and may omit optimized-away opcodes.
	if len(baseOps) > 0 && len(mirOps) > 0 {
		// Two-pointer alignment: advance base over ignorable ops (PUSH/DUP/SWAP/JUMPDEST) until it matches MIR.
		i, j := 0, 0
		matched := 0
		for i < len(baseOps) && j < len(mirOps) {
			if baseOps[i].pc == mirOps[j].pc && baseOps[i].op == mirOps[j].op {
				i++
				j++
				matched++
				continue
			}
			if isIgnorableBaseOp(baseOps[i].op) {
				i++
				continue
			}
			sb.WriteString(fmt.Sprintf("First opcode divergence (aligned) at mirStep=%d: base(pc=%d op=0x%02x) != mir(pc=%d op=0x%02x)\n",
				j, baseOps[i].pc, baseOps[i].op, mirOps[j].pc, mirOps[j].op))
			// Print small windows around the mismatch for quick diagnosis.
			b0 := i - 10
			if b0 < 0 {
				b0 = 0
			}
			b1 := i + 10
			if b1 > len(baseOps) {
				b1 = len(baseOps)
			}
			m0 := j - 10
			if m0 < 0 {
				m0 = 0
			}
			m1 := j + 10
			if m1 > len(mirOps) {
				m1 = len(mirOps)
			}
			sb.WriteString("Base ops window:\n")
			for k := b0; k < b1; k++ {
				sb.WriteString(fmt.Sprintf("  [%d] pc=%d op=0x%02x\n", k, baseOps[k].pc, baseOps[k].op))
			}
			sb.WriteString("MIR ops window:\n")
			for k := m0; k < m1; k++ {
				sb.WriteString(fmt.Sprintf("  [%d] pc=%d op=0x%02x\n", k, mirOps[k].pc, mirOps[k].op))
			}
			break
		}
		// If one stream ended without a mismatch, report the first point where the other has extra ops.
		if i >= len(baseOps) && j < len(mirOps) {
			sb.WriteString(fmt.Sprintf("Opcode streams diverged by length after %d matches: base ended at i=%d, mir has remaining %d ops starting at (pc=%d op=0x%02x)\n",
				matched, i, len(mirOps)-j, mirOps[j].pc, mirOps[j].op))
		} else if j >= len(mirOps) && i < len(baseOps) {
			// Advance base over ignorable ops for a fair comparison.
			for i < len(baseOps) && isIgnorableBaseOp(baseOps[i].op) {
				i++
			}
			if i < len(baseOps) {
				sb.WriteString(fmt.Sprintf("Opcode streams diverged by length after %d matches: mir ended at j=%d, base has remaining %d ops starting at (pc=%d op=0x%02x)\n",
					matched, j, len(baseOps)-i, baseOps[i].pc, baseOps[i].op))
			}
		}
	}

	sb.WriteString("\n--- BASE last opcodes (tail) ---\n")
	for _, s := range baseTrace {
		sb.WriteString(fmt.Sprintf("pc=%d op=0x%02x gas=%d cost=%d depth=%d err=%v\n", s.pc, s.op, s.gas, s.cost, s.depth, s.err))
	}
	sb.WriteString("\n--- BASE call frames (tail) ---\n")
	for _, c := range baseCalls {
		sb.WriteString(c + "\n")
	}
	if len(baseOperands) > 0 {
		sb.WriteString("\n--- BASE jump operands (tail) ---\n")
		for _, s := range baseOperands {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseMstore40) > 0 {
		sb.WriteString("\n--- BASE mstore(0x40) (tail) ---\n")
		for _, s := range baseMstore40 {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseAdd3393) > 0 {
		sb.WriteString("\n--- BASE add@3393 (tail) ---\n")
		for _, s := range baseAdd3393 {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseLoopJumps) > 0 {
		sb.WriteString("\n--- BASE loop jumps [3300..3500] (tail) ---\n")
		for _, s := range baseLoopJumps {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseWin280) > 0 {
		sb.WriteString("\n--- BASE window [280..310] (tail) ---\n")
		for _, s := range baseWin280 {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseArith) > 0 {
		sb.WriteString("\n--- BASE arithmetic operands (tail) ---\n")
		for _, s := range baseArith {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseLogs) > 0 {
		sb.WriteString("\n--- BASE logs (tail) ---\n")
		for _, s := range baseLogs {
			sb.WriteString(s + "\n")
		}
	}
	if len(baseStateChg) > 0 {
		sb.WriteString("\n--- BASE state changes (tail) ---\n")
		for _, s := range baseStateChg {
			sb.WriteString(s + "\n")
		}
	}
	sb.WriteString("\n--- MIR last steps (tail) ---\n")
	for _, s := range mirTrace {
		sb.WriteString(fmt.Sprintf("evmPC=%d evmOp=0x%02x mirOp=%s gasLeft=%d\n", s.evmPC, s.evmOp, s.op.String(), s.gasLeft))
	}
	sb.WriteString("\n--- MIR call frames (tail) ---\n")
	for _, c := range mirCalls {
		sb.WriteString(c + "\n")
	}
	if len(mirOperands) > 0 {
		sb.WriteString("\n--- MIR jump operands (tail) ---\n")
		for _, s := range mirOperands {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirMstore40) > 0 {
		sb.WriteString("\n--- MIR mstore(0x40) (tail) ---\n")
		for _, s := range mirMstore40 {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirAdd3393) > 0 {
		sb.WriteString("\n--- MIR add@3393 (tail) ---\n")
		for _, s := range mirAdd3393 {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirLoopJumps) > 0 {
		sb.WriteString("\n--- MIR loop jumps [3300..3500] (tail) ---\n")
		for _, s := range mirLoopJumps {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirCallArgs) > 0 {
		sb.WriteString("\n--- MIR call args (tail) ---\n")
		for _, s := range mirCallArgs {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirPhi) > 0 {
		sb.WriteString("\n--- MIR PHI resolution (tail) ---\n")
		for _, s := range mirPhi {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirFallbackOps) > 0 {
		sb.WriteString("\n--- MIR fallback native opcodes (tail) ---\n")
		for _, st := range mirFallbackOps {
			sb.WriteString(fmt.Sprintf("pc=%d op=0x%02x gas=%d cost=%d depth=%d err=%v\n", st.pc, st.op, st.gas, st.cost, st.depth, st.err))
		}
	}
	if len(mirLogs) > 0 {
		sb.WriteString("\n--- MIR logs (tail) ---\n")
		for _, s := range mirLogs {
			sb.WriteString(s + "\n")
		}
	}
	if len(mirStateChg) > 0 {
		sb.WriteString("\n--- MIR state changes (tail) ---\n")
		for _, s := range mirStateChg {
			sb.WriteString(s + "\n")
		}
	}
	return sb.String()
}

func diffBlockCommonTxs(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, target uint64, doFullBlock bool) error {
	env, err := newReplayEnv(db, cfg, genesisHash)
	if err != nil {
		return err
	}
	if target == 0 {
		return fmt.Errorf("target must be > 0")
	}
	if err := env.runUpTo(target-1, false, true); err != nil {
		return fmt.Errorf("prep state through block %d: %w", target-1, err)
	}

	h := rawdb.ReadCanonicalHash(db, target)
	if h == (common.Hash{}) {
		return fmt.Errorf("missing canonical hash for block %d", target)
	}
	blk := rawdb.ReadBlock(db, h, target)
	if blk == nil {
		return fmt.Errorf("missing block %d (%s)", target, h)
	}
	if blk.Header() != nil {
		bf := "<nil>"
		if blk.Header().BaseFee != nil {
			bf = blk.Header().BaseFee.String()
		}
		fmt.Printf("Block %d header.BaseFee=%s cfg.IsLondon=%v\n", target, bf, cfg.IsLondon(blk.Number()))
	}
	// Debug helper: for investigations, print a small summary of the first few txs.
	if target == 751500 {
		limit := 6
		if len(blk.Transactions()) < limit {
			limit = len(blk.Transactions())
		}
		fmt.Printf("Block %d tx summary (first %d):\n", target, limit)
		for i := 0; i < limit; i++ {
			tx := blk.Transactions()[i]
			to := "<create>"
			if tx.To() != nil {
				to = tx.To().Hex()
			}
			fmt.Printf("  idx=%d hash=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s isSystem=%v\n",
				i, tx.Hash(), to, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(), isSystemTx(env.engine, tx, blk.Header()))
		}
	}

	baseState := env.statedb.Copy()
	mirState := env.statedb.Copy()

	baseRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, baseState, blk, false)
	if err != nil {
		return fmt.Errorf("base common-tx run failed: %w", err)
	}
	mirRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, mirState, blk, true)
	if err != nil {
		return fmt.Errorf("mir common-tx run failed: %w", err)
	}

	signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
	for i, tx := range blk.Transactions() {
		if isSystemTx(env.engine, tx, blk.Header()) {
			continue
		}
		br := baseRun.receiptsByIndex[i]
		mr := mirRun.receiptsByIndex[i]
		if br == nil || mr == nil {
			return fmt.Errorf("missing receipt at idx=%d baseNil=%v mirNil=%v", i, br == nil, mr == nil)
		}
		if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) {
			from, _ := types.Sender(signer, tx)
			to := "<create>"
			if tx.To() != nil {
				to = tx.To().Hex()
			}
			// Print a detailed single-tx diagnosis on the first mismatch.
			fmt.Print(debugOneTx(env.engine, env.chain, cfg, env.statedb, blk, i))
			return fmt.Errorf("tx receipt mismatch idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s\n  base: %s root=%s cumGas=%d\n  mir : %s root=%s cumGas=%d",
				i, tx.Hash(), from, to, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(),
				fmtReceipt(br), baseRun.rootByIndex[i], baseRun.cumGasByIndex[i],
				fmtReceipt(mr), mirRun.rootByIndex[i], mirRun.cumGasByIndex[i],
			)
		}
		if baseRun.rootByIndex[i] != mirRun.rootByIndex[i] {
			// Print a detailed single-tx diagnosis on the first state-root mismatch too.
			fmt.Print(debugOneTx(env.engine, env.chain, cfg, env.statedb, blk, i))
			return fmt.Errorf("state root mismatch after tx idx=%d hash=%s\n  base root=%s\n  mir  root=%s", i, tx.Hash(), baseRun.rootByIndex[i], mirRun.rootByIndex[i])
		}
	}

	if baseRun.finalRoot != mirRun.finalRoot {
		return fmt.Errorf("post-common-txs state root mismatch\n  base=%s\n  mir=%s", baseRun.finalRoot, mirRun.finalRoot)
	}
	if baseRun.totalGasUsed != mirRun.totalGasUsed {
		return fmt.Errorf("post-common-txs gasUsed mismatch base=%d mir=%d", baseRun.totalGasUsed, mirRun.totalGasUsed)
	}
	if doFullBlock {
		// Full block processing (includes system txs + Parlia Finalize).
		//
		// NOTE: Parlia epoch processing may require a fully wired ethapi.BlockChainAPI
		// for validator-set contract calls. Scan-mode can skip this by passing doFullBlock=false.
		// Keep an immutable pre-state snapshot for debug printing when full-block receipts diverge.
		// (We must not pass a mutated statedb into debugOneTx.)
		preStateForDebug := env.statedb.Copy()
		baseState2 := env.statedb.Copy()
		mirState2 := env.statedb.Copy()
		// IMPORTANT: some consensus/processor paths may mutate the in-memory block/tx list while processing
		// (e.g. system-tx verification helpers). Always give base and MIR their own block objects.
		blkBase := rawdb.ReadBlock(db, blk.Hash(), target)
		blkMir := rawdb.ReadBlock(db, blk.Hash(), target)
		if blkBase == nil || blkMir == nil {
			return fmt.Errorf("missing block %d (%s) for full processing clone baseNil=%v mirNil=%v", target, blk.Hash(), blkBase == nil, blkMir == nil)
		}
		baseRes, baseErr := env.processor.Process(blkBase, baseState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false})
		mirRes, mirErr := env.processor.Process(blkMir, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
		if (baseErr == nil) != (mirErr == nil) {
			return fmt.Errorf("full block Process error mismatch: baseErr=%v mirErr=%v", baseErr, mirErr)
		}
		if baseErr != nil {
			if baseErr.Error() != mirErr.Error() {
				return fmt.Errorf("full block Process error msg mismatch: baseErr=%v mirErr=%v", baseErr, mirErr)
			}
			return fmt.Errorf("full block Process failed (both): %v", baseErr)
		}
		if baseRes == nil || mirRes == nil {
			return fmt.Errorf("full block Process returned nil result baseNil=%v mirNil=%v", baseRes == nil, mirRes == nil)
		}
		baseReceipts := baseRes.Receipts
		mirReceipts := mirRes.Receipts
		if len(baseReceipts) != len(mirReceipts) {
			return fmt.Errorf("full block receipts length mismatch: base=%d mir=%d", len(baseReceipts), len(mirReceipts))
		}
		for i := 0; i < len(baseReceipts); i++ {
			br, mr := baseReceipts[i], mirReceipts[i]
			if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) {
				kind := "common"
				if i < len(blk.Transactions()) && isSystemTx(env.engine, blk.Transactions()[i], blk.Header()) {
					kind = "system"
				}
				dbg := ""
				// For transaction receipts (not Parlia-finalize pseudo receipts), print a detailed tx diff.
				if i < len(blk.Transactions()) {
					dbg = "\n\n" + debugOneTx(env.engine, env.chain, cfg, preStateForDebug, blk, i)
				}
				return fmt.Errorf("full block receipt mismatch txIdx=%d kind=%s\n  base: %s root=%s\n  mir : %s root=%s%s",
					i, kind, fmtReceipt(br), baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number())), fmtReceipt(mr), mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number())), dbg)
			}
		}
		baseRoot := baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
		mirRoot := mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
		if baseRoot != mirRoot {
			return fmt.Errorf("full block post-state root mismatch\n  base=%s\n  mir =%s", baseRoot, mirRoot)
		}
		fmt.Printf("OK: full block %d matches (including system txs + Finalize)\n", target)
	}
	return nil
}

// scanRange runs an O(N) scan by reusing a single replay environment and advancing state incrementally.
// This avoids the O(N^2) behavior of rebuilding genesis and replaying 0..(n-1) for each block n.
func scanRange(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, from, to uint64, doFullBlock bool, fastState bool) error {
	if from == 0 {
		// Block 0 is genesis and contains no transactions to compare.
		from = 1
	}
	if to < from {
		return fmt.Errorf("bad range: to (%d) < from (%d)", to, from)
	}
	var env *replayEnv
	var err error
	if fastState {
		// Initialize state from on-disk parent root at (from-1) to avoid replaying from genesis.
		// This requires the datadir to contain trie nodes for that state root.
		if from == 0 {
			return fmt.Errorf("--faststate requires --from > 0")
		}
		env, err = newReplayEnvAtBlockState(db, cfg, genesisHash, from-1)
	} else {
		env, err = newReplayEnv(db, cfg, genesisHash)
	}
	if err != nil {
		return err
	}
	// Advance state once to the pre-state of `from` (genesis-replay mode only).
	if !fastState && from > 1 {
		if err := env.runUpTo(from-1, false, true); err != nil {
			return fmt.Errorf("prep state through block %d: %w", from-1, err)
		}
	}
	baseVmCfg := vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false}

	for n := from; n <= to; n++ {
		h := rawdb.ReadCanonicalHash(db, n)
		if h == (common.Hash{}) {
			return fmt.Errorf("missing canonical hash for block %d", n)
		}
		blk := rawdb.ReadBlock(db, h, n)
		if blk == nil {
			return fmt.Errorf("missing block %d (%s)", n, h)
		}

		// Diff common txs (MIR off/on) from the same pre-state using StateDB copies.
		// Note: this keeps scan correctness without reprocessing 0..(n-1) every iteration.
		baseState := env.statedb.Copy()
		mirState := env.statedb.Copy()
		baseRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, baseState, blk, false)
		if err != nil {
			return fmt.Errorf("block %d base common-tx run failed: %w", n, err)
		}
		mirRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, mirState, blk, true)
		if err != nil {
			return fmt.Errorf("block %d mir common-tx run failed: %w", n, err)
		}

		signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
		for i, tx := range blk.Transactions() {
			if isSystemTx(env.engine, tx, blk.Header()) {
				continue
			}
			br := baseRun.receiptsByIndex[i]
			mr := mirRun.receiptsByIndex[i]
			if br == nil || mr == nil {
				return fmt.Errorf("block %d missing receipt at idx=%d baseNil=%v mirNil=%v", n, i, br == nil, mr == nil)
			}
			if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) {
				fromAddr, _ := types.Sender(signer, tx)
				toAddr := "<create>"
				if tx.To() != nil {
					toAddr = tx.To().Hex()
				}
				fmt.Print(debugOneTx(env.engine, env.chain, cfg, env.statedb, blk, i))
				return fmt.Errorf("block %d tx receipt mismatch idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s\n  base: %s root=%s cumGas=%d\n  mir : %s root=%s cumGas=%d",
					n, i, tx.Hash(), fromAddr, toAddr, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(),
					fmtReceipt(br), baseRun.rootByIndex[i], baseRun.cumGasByIndex[i],
					fmtReceipt(mr), mirRun.rootByIndex[i], mirRun.cumGasByIndex[i],
				)
			}
			if baseRun.rootByIndex[i] != mirRun.rootByIndex[i] {
				return fmt.Errorf("block %d state root mismatch after tx idx=%d hash=%s\n  base root=%s\n  mir  root=%s", n, i, tx.Hash(), baseRun.rootByIndex[i], mirRun.rootByIndex[i])
			}
		}
		if baseRun.finalRoot != mirRun.finalRoot {
			return fmt.Errorf("block %d post-common-txs state root mismatch\n  base=%s\n  mir=%s", n, baseRun.finalRoot, mirRun.finalRoot)
		}
		if baseRun.totalGasUsed != mirRun.totalGasUsed {
			return fmt.Errorf("block %d post-common-txs gasUsed mismatch base=%d mir=%d", n, baseRun.totalGasUsed, mirRun.totalGasUsed)
		}

		if doFullBlock {
			// Full block processing diff (system txs + Finalize) from the same pre-state.
			baseState2 := env.statedb.Copy()
			mirState2 := env.statedb.Copy()
			// IMPORTANT: avoid sharing a mutable in-memory block object across runs.
			blkBase := rawdb.ReadBlock(db, blk.Hash(), n)
			blkMir := rawdb.ReadBlock(db, blk.Hash(), n)
			if blkBase == nil || blkMir == nil {
				return fmt.Errorf("missing block %d (%s) for full processing clone baseNil=%v mirNil=%v", n, blk.Hash(), blkBase == nil, blkMir == nil)
			}
			baseRes, baseErr := env.processor.Process(blkBase, baseState2, baseVmCfg)
			mirRes, mirErr := env.processor.Process(blkMir, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
			if (baseErr == nil) != (mirErr == nil) {
				return fmt.Errorf("block %d full Process error mismatch: baseErr=%v mirErr=%v", n, baseErr, mirErr)
			}
			if baseErr != nil {
				if baseErr.Error() != mirErr.Error() {
					return fmt.Errorf("block %d full Process error msg mismatch: baseErr=%v mirErr=%v", n, baseErr, mirErr)
				}
				return fmt.Errorf("block %d full Process failed (both): %v", n, baseErr)
			}
			if baseRes == nil || mirRes == nil {
				return fmt.Errorf("block %d full Process returned nil result baseNil=%v mirNil=%v", n, baseRes == nil, mirRes == nil)
			}
			if len(baseRes.Receipts) != len(mirRes.Receipts) {
				return fmt.Errorf("block %d full receipts length mismatch: base=%d mir=%d", n, len(baseRes.Receipts), len(mirRes.Receipts))
			}
			for i := 0; i < len(baseRes.Receipts); i++ {
				br, mr := baseRes.Receipts[i], mirRes.Receipts[i]
				if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) {
					kind := "common"
					if i < len(blk.Transactions()) && isSystemTx(env.engine, blk.Transactions()[i], blk.Header()) {
						kind = "system"
					}
					return fmt.Errorf("block %d full receipt mismatch txIdx=%d kind=%s\n  base: %s root=%s\n  mir : %s root=%s",
						n, i, kind, fmtReceipt(br), baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number())), fmtReceipt(mr), mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number())))
				}
			}
			baseRoot := baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
			mirRoot := mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
			if baseRoot != mirRoot {
				return fmt.Errorf("block %d full post-state root mismatch\n  base=%s\n  mir =%s", n, baseRoot, mirRoot)
			}
		}

		// Advance canonical state for the next block by processing the full block (base interpreter).
		if _, err := env.processor.Process(blk, env.statedb, baseVmCfg); err != nil {
			return fmt.Errorf("advance state Process block %d (%s): %w", n, h, err)
		}
		if n == from || n == to || n%100 == 0 {
			fmt.Printf("OK: block %d matches (common txs)%s\n", n, func() string {
				if doFullBlock {
					return " + full"
				}
				return ""
			}())
		}
	}
	return nil
}

func runUpTo(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, target uint64, enableMIR bool) error {
	genHeader := rawdb.ReadHeader(db, genesisHash, 0)
	if genHeader == nil {
		return fmt.Errorf("missing genesis header %s", genesisHash)
	}

	// IMPORTANT: We cannot rely on historical tries being present in a pruned/path-scheme DB.
	// Build genesis state trie from the persisted genesis allocation spec (JSON), then execute forward.
	allocBlob := rawdb.ReadGenesisStateSpec(db, genesisHash)
	if len(allocBlob) == 0 {
		return fmt.Errorf("missing genesis allocation spec for %s", genesisHash)
	}
	var alloc types.GenesisAlloc
	if err := alloc.UnmarshalJSON(allocBlob); err != nil {
		return fmt.Errorf("unmarshal genesis alloc: %w", err)
	}
	stateDB := rawdb.NewMemoryDatabase()
	stateTrieDB := triedb.NewDatabase(stateDB, triedb.HashDefaults)
	root, err := flushAllocForReplay(&alloc, stateTrieDB)
	if err != nil {
		return fmt.Errorf("flush genesis alloc: %w", err)
	}
	if root != genHeader.Root {
		return fmt.Errorf("genesis root mismatch: computed=%s header=%s", root, genHeader.Root)
	}
	statedb, err := state.New(root, state.NewDatabase(stateTrieDB, nil))
	if err != nil {
		return fmt.Errorf("state.New(genesisRoot): %w", err)
	}

	engine := parlia.New(cfg, db, nil, genesisHash)
	chain, err := core.NewHeaderChain(db, cfg, engine, func() bool { return false })
	if err != nil {
		return fmt.Errorf("NewHeaderChain: %w", err)
	}
	processor := core.NewStateProcessor(cfg, chain)

	vmCfg := vm.Config{
		EnableOpcodeOptimizations: false,
		EnableMIR:                 enableMIR,
	}

	for n := uint64(1); n <= target; n++ {
		h := rawdb.ReadCanonicalHash(db, n)
		if h == (common.Hash{}) {
			return fmt.Errorf("missing canonical hash for block %d", n)
		}
		blk := rawdb.ReadBlock(db, h, n)
		if blk == nil {
			return fmt.Errorf("missing block %d (%s)", n, h)
		}
		if _, err := processor.Process(blk, statedb, vmCfg); err != nil {
			return fmt.Errorf("Process block %d (%s): %w", n, h, err)
		}
		if n == 1 || n == 10 || n == 50 || n == 80 || n == target {
			fmt.Printf("ok: processed block %d\n", n)
		}
	}
	return nil
}

// flushAllocForReplay is a copy of core.flushAlloc logic (unexported in core),
// used to materialize the genesis state trie into a supplied triedb for replay.
func flushAllocForReplay(ga *types.GenesisAlloc, tdb *triedb.Database) (common.Hash, error) {
	emptyRoot := types.EmptyRootHash
	if tdb.IsVerkle() {
		emptyRoot = types.EmptyVerkleHash
	}
	statedb, err := state.New(emptyRoot, state.NewDatabase(tdb, nil))
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance), 0)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, 0)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root, err := statedb.Commit(0, false, false)
	if err != nil {
		return common.Hash{}, err
	}
	if root != types.EmptyRootHash {
		if err := tdb.Commit(root, true); err != nil {
			return common.Hash{}, err
		}
	}
	return root, nil
}

func main() {
	var (
		datadir = flag.String("datadir", "", "Geth datadir (e.g. /path/to/node_nomir)")
		blockN  = flag.Uint64("block", 90, "Block number to replay (single-block mode)")
		fromN   = flag.Uint64("from", 0, "Start block number to scan (inclusive). If set, scan mode is enabled.")
		toN     = flag.Uint64("to", 0, "End block number to scan (inclusive). If set with --from, scan mode is enabled.")
		full    = flag.Bool("full", false, "In scan mode, also run full block processing (system txs + Finalize).")
		fast    = flag.Bool("faststate", false, "In scan mode, initialize pre-state from the on-disk parent state root (from-1) instead of replaying from genesis. Requires the datadir to contain trie nodes for that root.")
	)
	flag.Parse()
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "missing --datadir")
		os.Exit(2)
	}
	chaindata := filepath.Join(*datadir, "geth", "chaindata")
	// Make geth's log.Crit/Error visible (rawdb.Open and state DB code may use it).
	h := ethlog.NewTerminalHandlerWithLevel(os.Stdout, ethlog.LevelInfo, false)
	ethlog.SetDefault(ethlog.NewLogger(h))

	// NOTE: must open read-write because triedb/pathdb may attempt to maintain
	// state-history metadata at startup (even for historical reads).
	db, closeDB, err := openChainDB(chaindata, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db %s: %v\n", chaindata, err)
		os.Exit(1)
	}
	defer closeDB()
	fmt.Printf("Opened chaindata: %s\n", chaindata)

	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	cfg := rawdb.ReadChainConfig(db, genesisHash)
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "missing chain config for genesis hash %s\n", genesisHash)
		os.Exit(1)
	}
	fmt.Printf("ChainID=%v genesis=%s\n", cfg.ChainID, genesisHash)

	// Scan mode: --from/--to set.
	if *fromN != 0 || *toN != 0 {
		start := *fromN
		end := *toN
		if start == 0 {
			start = 1
		}
		if end == 0 {
			end = start
		}
		if end < start {
			fmt.Fprintf(os.Stderr, "bad range: --to (%d) < --from (%d)\n", end, start)
			os.Exit(2)
		}
		fmt.Printf("Scanning blocks [%d..%d] (MIR off/on)...\n", start, end)
		if err := scanRange(db, cfg, genesisHash, start, end, *full, *fast); err != nil {
			fmt.Fprintf(os.Stderr, "DIFF in scan %d..%d: %v\n", start, end, err)
			os.Exit(1)
		}
		fmt.Printf("OK: blocks [%d..%d] match\n", start, end)
		return
	}

	// Single-block mode
	fmt.Printf("Diffing block %d common txs (MIR off/on)...\n", *blockN)
	// In single-block mode, run full block processing too.
	if err := diffBlockCommonTxs(db, cfg, genesisHash, *blockN, true); err != nil {
		fmt.Fprintf(os.Stderr, "DIFF: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: common txs match for block %d\n", *blockN)
}
