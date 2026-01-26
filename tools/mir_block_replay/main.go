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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
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

func openTrieDB(disk ethdb.Database, readonly bool) *triedb.Database {
	// triedb.NewDatabase defaults PathDB.Config.ReadOnly=false even if the underlying kv is read-only.
	// For tooling that opens a live datadir with --readonlydb, propagate it down so pathdb/history
	// won't attempt to truncate/repair the freezer.
	if disk == nil {
		return triedb.NewDatabase(disk, nil)
	}
	if rawdb.ReadStateScheme(disk) != rawdb.PathScheme {
		return triedb.NewDatabase(disk, nil)
	}
	cfg := *pathdb.Defaults
	cfg.ReadOnly = readonly
	return triedb.NewDatabase(disk, &triedb.Config{PathDB: &cfg})
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
func newReplayEnvAtBlockState(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, n uint64, readonly bool) (*replayEnv, error) {
	h := rawdb.ReadCanonicalHash(db, n)
	if h == (common.Hash{}) {
		return nil, fmt.Errorf("missing canonical hash for block %d", n)
	}
	header := rawdb.ReadHeader(db, h, n)
	if header == nil {
		return nil, fmt.Errorf("missing header for block %d (%s)", n, h)
	}
	// Auto-detect hash/path scheme based on db metadata.
	tdb := openTrieDB(db, readonly)
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

func applyTxWithResult(evm *vm.EVM, statedb *state.StateDB, header *types.Header, blockHash common.Hash, tx *types.Transaction, idx int, usedGas *uint64, gp *core.GasPool) (*types.Receipt, *core.ExecutionResult, error) {
	// IMPORTANT: use the same path as real block processing (ApplyTransactionWithEVM),
	// not just ApplyMessage. This includes intrinsic gas, nonce checks, gas buy, etc.
	msg, err := core.TransactionToMessage(tx, types.MakeSigner(evm.ChainConfig(), header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	statedb.SetTxContext(tx.Hash(), idx)
	receipt, err := core.ApplyTransactionWithEVM(msg, gp, statedb, header.Number, blockHash, header.Time, tx, usedGas, evm)
	if err != nil {
		return receipt, nil, err
	}
	// ApplyTransactionWithEVM doesn't return core.ExecutionResult. Tracers still capture opcode-level detail.
	return receipt, nil, nil
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
	// Block 7753 focus: snapshot a couple of committed/current storage slots to ensure base vs MIR prestate matches.
	if tx != nil && tx.To() != nil && preState != nil {
		slotB := common.BigToHash(big.NewInt(0xb))
		slotC := common.BigToHash(big.NewInt(0xc))
		sb.WriteString(fmt.Sprintf("PRESTATE: to=%s base(committed[0xb]=%s cur[0xb]=%s committed[0xc]=%s cur[0xc]=%s)\n",
			tx.To().Hex(),
			baseState.GetCommittedState(*tx.To(), slotB), baseState.GetState(*tx.To(), slotB),
			baseState.GetCommittedState(*tx.To(), slotC), baseState.GetState(*tx.To(), slotC),
		))
	}
	baseTrace := make([]evmStep, 0, 64)
	baseCalls := make([]string, 0, 32)
	baseOperands := make([]string, 0, 64)
	baseArith := make([]string, 0, 32)
	baseMstore40 := make([]string, 0, 8)
	baseAdd3393 := make([]string, 0, 8)
	baseLoopJumps := make([]string, 0, 32)
	baseWin280 := make([]string, 0, 128)
	baseStateChg := make([]string, 0, 128)
	baseLogs := make([]string, 0, 256)
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
		// Record SSTORE gas/cost at top-level for quick base vs MIR gas delta debugging.
		if depth == 1 && scope != nil && op == 0x55 {
			st := scope.StackData()
			k := "<empty>"
			v := "<empty>"
			if len(st) > 0 {
				k = st[len(st)-1].Hex()
			}
			if len(st) > 1 {
				v = st[len(st)-2].Hex()
			}
			pushBaseLog(fmt.Sprintf("BASE_SSTORE pc=%d gas=%d cost=%d key=%s val=%s", pc, gas, cost, k, v))
		}
		// Bad block 7753 focus: capture base gas/cost + top stack around key sites:
		// - pc~2932: early SSTORE
		// - pc~6630-6655: block that contains the problematic SSTORE@6645
		// - pc~9350: later SSTORE where MIR OOGs after overcharging earlier
		if depth == 1 && scope != nil && ((pc >= 2918 && pc <= 2940) || (pc >= 6580 && pc <= 6660) || (pc >= 9330 && pc <= 9360)) {
			st := scope.StackData()
			// Dump up to top12 stack items for easier comparison with MIR incoming snapshots.
			topN := func(n int) string {
				if n <= 0 {
					return ""
				}
				if len(st) == 0 {
					return "<empty>"
				}
				if n > len(st) {
					n = len(st)
				}
				var parts []string
				for i := 0; i < n; i++ {
					parts = append(parts, "0x"+st[len(st)-1-i].Hex())
				}
				return strings.Join(parts, ",")
			}
			pushBaseLog(fmt.Sprintf("WATCH_BASE_7753 pc=%d op=0x%02x gas=%d cost=%d stackLen=%d top12=%s",
				pc, op, gas, cost, len(st), topN(12)))
		}
		// Extra watchpoint for bad block 37894 debugging: log stack top around the divergent dispatcher
		// sequence in the top-level contract (depth==1).
		if depth == 1 && scope != nil && pc >= 10664 && pc <= 10676 {
			st := scope.StackData()
			// Keep a small ring
			if len(baseOperands) == cap(baseOperands) {
				copy(baseOperands, baseOperands[1:])
				baseOperands = baseOperands[:cap(baseOperands)-1]
			}
			top := "<empty>"
			top2 := "<empty>"
			if len(st) > 0 {
				top = st[len(st)-1].Hex()
			}
			if len(st) > 1 {
				top2 = st[len(st)-2].Hex()
			}
			baseOperands = append(baseOperands, fmt.Sprintf("WATCH_BASE pc=%d op=0x%02x top=%s top2=%s stackLen=%d", pc, op, top, top2, len(st)))
		}
		// Bad block 139161 focus: dump stack top2 around the divergent LT/ISZERO/JUMPI region.
		// pc=16398 is LT, pc=16399 is ISZERO, pc=16403 is JUMPI.
		if depth == 1 && scope != nil && pc >= 16395 && pc <= 16405 {
			st := scope.StackData()
			// Keep a small ring
			if len(baseOperands) == cap(baseOperands) {
				copy(baseOperands, baseOperands[1:])
				baseOperands = baseOperands[:cap(baseOperands)-1]
			}
			top := "<empty>"
			top2 := "<empty>"
			if len(st) > 0 {
				top = st[len(st)-1].Hex()
			}
			if len(st) > 1 {
				top2 = st[len(st)-2].Hex()
			}
			baseOperands = append(baseOperands, fmt.Sprintf("WATCH_BASE_139161 pc=%d op=0x%02x top=%s top2=%s stackLen=%d", pc, op, top, top2, len(st)))
		}
		// Bad block 139161 focus: the failing MIR path hits an invalid jumpdest 0x0 at pc=10284.
		// Capture the base stack top around this site to see the expected jump destination.
		if depth == 1 && scope != nil && pc >= 10280 && pc <= 10284 {
			st := scope.StackData()
			if len(baseOperands) == cap(baseOperands) {
				copy(baseOperands, baseOperands[1:])
				baseOperands = baseOperands[:cap(baseOperands)-1]
			}
			top := "<empty>"
			top2 := "<empty>"
			if len(st) > 0 {
				top = st[len(st)-1].Hex()
			}
			if len(st) > 1 {
				top2 = st[len(st)-2].Hex()
			}
			baseOperands = append(baseOperands, fmt.Sprintf("WATCH_BASE_139161 pc=%d op=0x%02x top=%s top2=%s stackLen=%d", pc, op, top, top2, len(st)))
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
			_, _, _ = applyTxWithResult(prefixEVM, baseState, header, blockHash, ptx, i, &prefixUsed, prefixGP)
		}
	}
	// Wrap statedb to receive state-change callbacks (balance/storage/nonce/code).
	baseHooked := state.NewHookedState(baseState, baseTracer)
	baseEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), baseHooked, cfg, vm.Config{EnableMIR: false, Tracer: baseTracer})
	baseGP := new(core.GasPool).AddGas(blk.GasLimit())
	baseUsed := uint64(0)
	baseReceipt, baseRes, baseErr := applyTxWithResult(baseEVM, baseState, header, blockHash, tx, txIndex, &baseUsed, baseGP)
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
	// Block 7753 focus: snapshot a couple of committed/current storage slots for MIR prestate too.
	if tx != nil && tx.To() != nil && preState != nil {
		slotB := common.BigToHash(big.NewInt(0xb))
		slotC := common.BigToHash(big.NewInt(0xc))
		sb.WriteString(fmt.Sprintf("PRESTATE: to=%s mir (committed[0xb]=%s cur[0xb]=%s committed[0xc]=%s cur[0xc]=%s)\n",
			tx.To().Hex(),
			mirState.GetCommittedState(*tx.To(), slotB), mirState.GetState(*tx.To(), slotB),
			mirState.GetCommittedState(*tx.To(), slotC), mirState.GetState(*tx.To(), slotC),
		))
	}
	mirTrace := make([]mirStep, 0, 256)
	mirCalls := make([]string, 0, 32)
	mirOperands := make([]string, 0, 256)
	mirCallArgs := make([]string, 0, 16)
	mirMstore40 := make([]string, 0, 8)
	mirAdd3393 := make([]string, 0, 8)
	mirLoopJumps := make([]string, 0, 32)
	mirPhi := make([]string, 0, 64)
	mirStateChg := make([]string, 0, 128)
	mirLogs := make([]string, 0, 256)
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
			_, _, _ = applyTxWithResult(prefixEVM, mirState, header, blockHash, ptx, i, &prefixUsed, prefixGP)
		}
	}

	mirHooked := state.NewHookedState(mirState, mirTracer)
	mirEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), mirHooked, cfg, vm.Config{EnableMIR: true, Tracer: mirTracer})
	runner := mir.NewEVMRunner(mirEVM)

	// Dump MIR for the top-level callee around the common free-memory-pointer update region.
	// This helps diagnose stack-model bugs that manifest as wrong return sizes or copy lengths.
	if tx != nil && tx.To() != nil && preState != nil {
		code := preState.GetCode(*tx.To())
		if len(code) > 0 {
			codeHash := crypto.Keccak256Hash(code)
			tmp := mir.NewCFG(codeHash, code)
			if err := tmp.Parse(); err == nil {
				mirLogs = append(mirLogs, strings.TrimRight(mir.DebugDumpMIRForEvmPCRange(tmp, 180, 260), "\n"))
				// Bad block 7753 focus: dump the region around the problematic SSTORE sequence.
				if blk != nil && blk.NumberU64() == 7753 && len(code) > 6665 {
					mirLogs = append(mirLogs, strings.TrimRight(mir.DebugDumpMIRForEvmPCRange(tmp, 6620, 6665), "\n"))
				}
			}
		}
	}

	// Track which contract addresses we've already emitted a runtime CFG dump for.
	var mirDumped map[string]bool

	runner.SetMIRStepHookFactory(func(it *mir.MIRInterpreter) func(evmPC uint, evmOp byte, op mir.MirOperation) {
		// Capture key control-flow operands (JUMP/JUMPI dest + cond) with def provenance.
		// This is critical for debugging bad blocks caused by invalid jumpdest/CFG issues.
		if it != nil {
			// Dump the *actual runtime CFG* once per contract, to diagnose rebuild/caching issues.
			// (This can differ from a fresh Parse() due to runtime rebuilds.)
			//
			// Note: The dump is appended to mirLogs to keep it in the report.
			// We keep a small set to avoid repeated dumps.
			//
			// This closure is invoked once per interpreter instance.
			{
				// lazy init the set the first time we enter
				if mirDumped == nil {
					mirDumped = make(map[string]bool, 8)
				}
				addr := it.ContractAddress().Hex()
				if !mirDumped[addr] {
					mirDumped[addr] = true
					mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(180, 260), "\n"))
				}
			}

			it.SetDebugPhiHook(func(curFirstPC uint, prevFirstPC uint, phiPC uint, phiStackIndex int, incomingLen int, incomingIdx int, val uint256.Int) {
				// Keep a small ring buffer.
				if len(mirPhi) == cap(mirPhi) {
					copy(mirPhi, mirPhi[1:])
					mirPhi = mirPhi[:cap(mirPhi)-1]
				}
				// Focus: PHI near the failing region, but keep generic formatting.
				mirPhi = append(mirPhi, fmt.Sprintf("PHI phiPC=%d curBB=%d prevBB=%d phiIdx=%d inLen=%d inIdx=%d val=0x%s", phiPC, curFirstPC, prevFirstPC, phiStackIndex, incomingLen, incomingIdx, val.Hex()))
			})
			it.SetDebugOperandHook(func(evmPC uint, evmOp byte, op mir.MirOperation, a uint256.Int, b uint256.Int) {
				// Keep a small ring buffer.
				if len(mirOperands) == cap(mirOperands) {
					copy(mirOperands, mirOperands[1:])
					mirOperands = mirOperands[:cap(mirOperands)-1]
				}
				addr := "<nil>"
				if it != nil {
					addr = it.ContractAddress().Hex()
				}
				// Bad block 139161: capture LT operands feeding the loop condition.
				if op == mir.MirLT && evmPC == 16398 {
					mirOperands = append(mirOperands, fmt.Sprintf("LT    addr=%s evmPC=16398 a=0x%s b=0x%s", addr, a.Hex(), b.Hex()))
				}
			})
			it.SetDebugOperandHookEx(func(evmPC uint, evmOp byte, op mir.MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp mir.MirOperation, bDefOp mir.MirOperation) {
				// Keep a small ring buffer.
				if len(mirOperands) == cap(mirOperands) {
					copy(mirOperands, mirOperands[1:])
					mirOperands = mirOperands[:cap(mirOperands)-1]
				}
				addr := "<nil>"
				if it != nil {
					addr = it.ContractAddress().Hex()
				}
				switch op {
				case mir.MirLT:
					mirOperands = append(mirOperands, fmt.Sprintf("LT    addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirAND:
					mirOperands = append(mirOperands, fmt.Sprintf("AND   addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSLOAD:
					mirOperands = append(mirOperands, fmt.Sprintf("SLOAD addr=%s evmPC=%d k=0x%s kDefPC=%d kDefOp=%s", addr, evmPC, a.Hex(), aDefPC, aDefOp.String()))
				case mir.MirMLOAD:
					// For MLOAD we encode: a=offset, b=loadedWord (best-effort).
					mirOperands = append(mirOperands, fmt.Sprintf("MLOAD addr=%s evmPC=%d off=0x%s loaded=0x%s offDefPC=%d offDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String()))
				case mir.MirMSTORE:
					mirOperands = append(mirOperands, fmt.Sprintf("MSTORE addr=%s evmPC=%d off=0x%s val=0x%s offDefPC=%d offDefOp=%s valDefPC=%d valDefOp=%s",
						addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if a.IsUint64() && a.Uint64() == 0x40 {
						if len(mirMstore40) == cap(mirMstore40) {
							copy(mirMstore40, mirMstore40[1:])
							mirMstore40 = mirMstore40[:cap(mirMstore40)-1]
						}
						mirMstore40 = append(mirMstore40, fmt.Sprintf("MSTORE addr=%s evmPC=%d off=0x40 val=0x%s valDefPC=%d valDefOp=%s", addr, evmPC, b.Hex(), bDefPC, bDefOp.String()))
					}
				case mir.MirADD:
					mirOperands = append(mirOperands, fmt.Sprintf("ADD   addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if evmPC == 3393 {
						if len(mirAdd3393) == cap(mirAdd3393) {
							copy(mirAdd3393, mirAdd3393[1:])
							mirAdd3393 = mirAdd3393[:cap(mirAdd3393)-1]
						}
						var sum uint256.Int
						sum.Add(&a, &b)
						mirAdd3393 = append(mirAdd3393, fmt.Sprintf("ADD addr=%s evmPC=3393 a=0x%s b=0x%s sum=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s",
							addr,
							a.Hex(), b.Hex(), sum.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					}
				case mir.MirSTATICCALL:
					mirOperands = append(mirOperands, fmt.Sprintf("STATICCALL addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s",
						addr,
						evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSUB:
					mirOperands = append(mirOperands, fmt.Sprintf("SUB   addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirCALLDATACOPY:
					// We encode: a=dest, b=size
					mirOperands = append(mirOperands, fmt.Sprintf("CALLDATACOPY addr=%s evmPC=%d dest=0x%s size=0x%s destDefPC=%d destDefOp=%s sizeDefPC=%d sizeDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirRETURNDATACOPY:
					// We encode: a=dest, b=size
					mirOperands = append(mirOperands, fmt.Sprintf("RETURNDATACOPY addr=%s evmPC=%d dest=0x%s size=0x%s destDefPC=%d destDefOp=%s sizeDefPC=%d sizeDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirOR:
					mirOperands = append(mirOperands, fmt.Sprintf("OR    addr=%s evmPC=%d a=0x%s b=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
				case mir.MirSSTORE:
					mirOperands = append(mirOperands, fmt.Sprintf("SSTORE addr=%s evmPC=%d k=0x%s v=0x%s kDefPC=%d kDefOp=%s vDefPC=%d vDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if evmPC == 6645 || evmPC == 6650 {
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH_MIR_SSTORE_7753 addr=%s evmPC=%d k=0x%s v=0x%s kDefPC=%d kDefOp=%s vDefPC=%d vDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
						if evmPC == 6645 {
							// Dump local MIR and incoming stacks for the block containing this SSTORE.
							if mirDumped == nil {
								mirDumped = make(map[string]bool, 16)
							}
							k := addr + ":evmPC6620_6665"
							if !mirDumped[k] {
								mirDumped[k] = true
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(6620, 6665), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpCodeHexRange(6620, 6665), "\n"))
								// Dump the predecessor region leading into the JUMPDEST at 6630 (0x19e6).
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(6590, 6635), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpCodeHexRange(6590, 6635), "\n"))
								// pcToBlock is keyed by basic-block firstPC (JUMPDEST). For this snippet the JUMPDEST
								// is at 6620+10 = 6630.
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpIncomingStacksForPC(6630, 12), "\n"))
								// Also dump the predecessor's incoming stacks; computeExitSnapshotForEdge depends on them.
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpIncomingStacksForPC(0x19ce, 12), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpIncomingStacksForPC(0x19bb, 12), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpIncomingStacksForPC(0x2faf, 12), "\n"))
								// Dump cached static entry/exit stacks for predecessor and target blocks.
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEntryExitStacksForPC(0x19ce, 12), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEntryExitStacksForPC(0x19e6, 12), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEntryExitStacksForPC(0x19bb, 12), "\n"))
								mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEntryExitStacksForPC(0x2faf, 12), "\n"))
							}
						}
					}
				case mir.MirJUMP:
					mirOperands = append(mirOperands, fmt.Sprintf("JUMP  addr=%s evmPC=%d a(dest)=0x%s aDefPC=%d aDefOp=%s", addr, evmPC, a.Hex(), aDefPC, aDefOp.String()))
					// Hot watchpoint for bad block debugging (37894): capture the computed destination at a
					// known divergent JUMP site.
					if evmPC == 10676 {
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH: MIR JUMP addr=%s evmPC=10676 dest=%s aDefPC=%d aDefOp=%s", addr, a.Hex(), aDefPC, aDefOp.String()))
						// Also dump a focused window around the divergent JUMP once per contract to see whether
						// the destination is constant (K) or computed (V) in the runtime MIR.
						if mirDumped == nil {
							mirDumped = make(map[string]bool, 8)
						}
						k := addr + ":evmPC10650_10710"
						if !mirDumped[k] {
							mirDumped[k] = true
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(10650, 10710), "\n"))
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpCodeHexRange(10650, 10710), "\n"))
						}
					}
					// Bad block 139161: runtime invalid jumpdest seems to come from JUMP at evmPC=10284.
					// Dump a focused window around it to understand why the destination becomes 0.
					if evmPC == 10284 {
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH: MIR JUMP addr=%s evmPC=10284 dest=%s aDefPC=%d aDefOp=%s", addr, a.Hex(), aDefPC, aDefOp.String()))
						if mirDumped == nil {
							mirDumped = make(map[string]bool, 8)
						}
						k := addr + ":evmPC10260_10310"
						if !mirDumped[k] {
							mirDumped[k] = true
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(10260, 10310), "\n"))
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpCodeHexRange(10260, 10310), "\n"))
						}
					}
					// Block 2143 focus: internal-call trampoline return address issue around JUMP@2991 -> 0x100e
					// and return JUMP@4117 which should go back to 2992.
					if evmPC == 2991 || evmPC == 4117 {
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH: MIR JUMP addr=%s evmPC=%d dest=%s aDefPC=%d aDefOp=%s", addr, evmPC, a.Hex(), aDefPC, aDefOp.String()))
						if mirDumped == nil {
							mirDumped = make(map[string]bool, 16)
						}
						k := fmt.Sprintf("%s:evmPC%d_win", addr, evmPC)
						if !mirDumped[k] {
							mirDumped[k] = true
							start := uint(0)
							end := uint(0)
							if evmPC == 2991 {
								start, end = 2975, 3035
							} else {
								start, end = 4105, 4125
							}
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(start, end), "\n"))
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpCodeHexRange(start, end), "\n"))
							// Dump the incoming stack snapshots for the internal-call trampoline block.
							// This is where the return-address PHI should be created.
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpIncomingStacksForPC(0x100e, 8), "\n"))
						}
					}
					// Block 7753 focus: log MIR gas accounting around the final SSTORE site (pc~9350).
					if evmPC >= 9330 && evmPC <= 9360 {
						gUsed := uint64(0)
						gLim := uint64(0)
						if it != nil {
							gUsed = it.GasUsed()
							gLim = it.GasLimit()
						}
						gLeft := uint64(0)
						if gLim == 0 || gUsed > gLim {
							gLeft = 0
						} else {
							gLeft = gLim - gUsed
						}
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH_MIR_7753 evmPC=%d evmOp=0x%02x mirOp=%s gasUsed=%d gasLeft=%d", evmPC, evmOp, op.String(), gUsed, gLeft))
					}
					if evmPC >= 3300 && evmPC <= 3500 {
						if len(mirLoopJumps) == cap(mirLoopJumps) {
							copy(mirLoopJumps, mirLoopJumps[1:])
							mirLoopJumps = mirLoopJumps[:cap(mirLoopJumps)-1]
						}
						mirLoopJumps = append(mirLoopJumps, fmt.Sprintf("JUMP  addr=%s evmPC=%d dest=0x%s aDefPC=%d aDefOp=%s", addr, evmPC, a.Hex(), aDefPC, aDefOp.String()))
					}
				case mir.MirJUMPI:
					mirOperands = append(mirOperands, fmt.Sprintf("JUMPI addr=%s evmPC=%d a(dest)=0x%s b(cond)=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
					if evmPC == 16403 {
						mirLogs = append(mirLogs, fmt.Sprintf("WATCH: MIR JUMPI addr=%s evmPC=16403 dest=%s cond=%s bDefPC=%d bDefOp=%s", addr, a.Hex(), b.Hex(), bDefPC, bDefOp.String()))
						if mirDumped == nil {
							mirDumped = make(map[string]bool, 8)
						}
						k := addr + ":evmPC16390_16450"
						if !mirDumped[k] {
							mirDumped[k] = true
							mirLogs = append(mirLogs, strings.TrimRight(it.DebugDumpEvmPCRange(16390, 16450), "\n"))
						}
					}
					if evmPC >= 3300 && evmPC <= 3500 {
						if len(mirLoopJumps) == cap(mirLoopJumps) {
							copy(mirLoopJumps, mirLoopJumps[1:])
							mirLoopJumps = mirLoopJumps[:cap(mirLoopJumps)-1]
						}
						mirLoopJumps = append(mirLoopJumps, fmt.Sprintf("JUMPI addr=%s evmPC=%d dest=0x%s cond=0x%s aDefPC=%d aDefOp=%s bDefPC=%d bDefOp=%s", addr, evmPC, a.Hex(), b.Hex(), aDefPC, aDefOp.String(), bDefPC, bDefOp.String()))
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

			// Bad block 7753 focus: log MIR gasLeft around key sites.
			if (evmPC >= 2918 && evmPC <= 2940) || (evmPC >= 6628 && evmPC <= 6660) || (evmPC >= 9330 && evmPC <= 9360) {
				pushMirLog(fmt.Sprintf("WATCH_MIR_7753 evmPC=%d evmOp=0x%02x mirOp=%s gasLeft=%d", evmPC, evmOp, op.String(), gasLeft))
			}
			if evmOp == 0x55 {
				pushMirLog(fmt.Sprintf("MIR_SSTORE evmPC=%d mirOp=%s gasLeft=%d", evmPC, op.String(), gasLeft))
			}
		}
	})
	mirEVM.SetMIRRunner(runner)
	mirGP := new(core.GasPool).AddGas(blk.GasLimit())
	mirUsed := uint64(0)
	mirReceipt, mirRes, mirErr := applyTxWithResult(mirEVM, mirState, header, blockHash, tx, txIndex, &mirUsed, mirGP)
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

func diffBlockCommonTxs(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, target uint64, doFullBlock bool, warmup bool, readonly bool) error {
	if target == 0 {
		return fmt.Errorf("target must be > 0")
	}

	h := rawdb.ReadCanonicalHash(db, target)
	if h == (common.Hash{}) {
		return fmt.Errorf("missing canonical hash for block %d", target)
	}
	blk := rawdb.ReadBlock(db, h, target)
	if blk == nil {
		return fmt.Errorf("missing block %d (%s)", target, h)
	}
	return diffBlockCommonTxsWithBlock(db, cfg, genesisHash, blk, doFullBlock, true, warmup, readonly)
}

func cloneBlockForFullProcessing(blk *types.Block) (*types.Block, error) {
	if blk == nil {
		return nil, fmt.Errorf("nil block")
	}
	// Use RLP roundtrip to avoid accidental sharing/mutation between base and MIR runs.
	blob, err := rlp.EncodeToBytes(blk)
	if err != nil {
		return nil, err
	}
	var out types.Block
	if err := rlp.DecodeBytes(blob, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// diffBlockCommonTxsWithBlock compares MIR-off vs MIR-on execution for a specific block object.
// If prepProgress is true and we must replay from genesis, prints progress markers.
func diffBlockCommonTxsWithBlock(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, blk *types.Block, doFullBlock bool, prepProgress bool, warmup bool, readonly bool) error {
	if blk == nil || blk.Header() == nil {
		return fmt.Errorf("nil block/header")
	}
	target := blk.NumberU64()

	// Prefer initializing pre-state directly from the on-disk parent state root (fast path).
	// This is especially important when the target block is a "bad block" and/or not on the
	// canonical chain (fork). In that case, canonical (N-1) is the wrong pre-state.
	var env *replayEnv
	var err error
	isCanonParent := false
	if target > 0 {
		if target == 1 {
			env, err = newReplayEnv(db, cfg, genesisHash)
		} else {
			// Check whether the block's parent hash matches the canonical hash at N-1.
			canonParent := rawdb.ReadCanonicalHash(db, target-1)
			if canonParent == blk.ParentHash() && canonParent != (common.Hash{}) {
				// Canonical parent: use the fast canonical state-root path.
				isCanonParent = true
				env, err = newReplayEnvAtBlockState(db, cfg, genesisHash, target-1, readonly)
			} else {
				// Non-canonical parent: initialize state from the parent header referenced by this block.
				parentHeader := rawdb.ReadHeader(db, blk.ParentHash(), target-1)
				if parentHeader == nil {
					return fmt.Errorf("missing parent header for non-canonical block parent=%s number=%d", blk.ParentHash().Hex(), target-1)
				}
				tdb := openTrieDB(db, readonly)
				statedb, err2 := state.New(parentHeader.Root, state.NewDatabase(tdb, nil))
				if err2 != nil {
					return fmt.Errorf("state.New(parentRoot @%d %s): %w", target-1, parentHeader.Root, err2)
				}
				env, err = newReplayEnvWithState(db, cfg, genesisHash, statedb)
			}
			if err != nil && prepProgress {
				// Fallback: reconstruct state by replaying from genesis (canonical chain only).
				env, err = newReplayEnv(db, cfg, genesisHash)
				if err == nil {
					if err2 := env.runUpTo(target-1, false, true); err2 != nil {
						return fmt.Errorf("prep state through block %d: %w", target-1, err2)
					}
				}
			}
		}
	} else {
		return fmt.Errorf("target must be > 0")
	}
	if err != nil {
		return err
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

	// If warmup is requested and this block builds on the canonical chain, also warm up the
	// *state* for both base and MIR by replaying blocks [1..target-1] in each mode. This more
	// closely matches a fullnode where MIR has been active for prior blocks.
	if warmup && target > 1 && isCanonParent {
		baseEnv, err := newReplayEnv(db, cfg, genesisHash)
		if err != nil {
			return fmt.Errorf("base warm env: %w", err)
		}
		if err := baseEnv.runUpTo(target-1, false, false); err != nil {
			return fmt.Errorf("base warm prep through block %d: %w", target-1, err)
		}
		mirEnv, err := newReplayEnv(db, cfg, genesisHash)
		if err != nil {
			return fmt.Errorf("mir warm env: %w", err)
		}
		if err := mirEnv.runUpTo(target-1, true, false); err != nil {
			return fmt.Errorf("mir warm prep through block %d: %w", target-1, err)
		}
		// Use the warmed base environment as the canonical pre-state provider for this diff.
		env = baseEnv
		baseState := baseEnv.statedb.Copy()
		mirState := mirEnv.statedb.Copy()

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
				fmt.Print(debugOneTx(env.engine, env.chain, cfg, env.statedb, blk, i))
				return fmt.Errorf("tx receipt mismatch idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s\n  base: %s root=%s cumGas=%d\n  mir : %s root=%s cumGas=%d",
					i, tx.Hash(), from, to, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(),
					fmtReceipt(br), baseRun.rootByIndex[i], baseRun.cumGasByIndex[i],
					fmtReceipt(mr), mirRun.rootByIndex[i], mirRun.cumGasByIndex[i],
				)
			}
			if baseRun.rootByIndex[i] != mirRun.rootByIndex[i] {
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
			preStateForDebug := env.statedb.Copy()
			baseState2 := env.statedb.Copy()
			mirState2 := env.statedb.Copy()
			blkBase, err := cloneBlockForFullProcessing(blk)
			if err != nil {
				return fmt.Errorf("clone block for base: %w", err)
			}
			blkMir, err := cloneBlockForFullProcessing(blk)
			if err != nil {
				return fmt.Errorf("clone block for mir: %w", err)
			}
			baseRes, baseErr := env.processor.Process(blkBase, baseState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false})
			mirRes, mirErr := env.processor.Process(blkMir, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
			if (baseErr == nil) != (mirErr == nil) {
				if len(blk.Transactions()) > 0 {
					fmt.Print(debugOneTx(env.engine, env.chain, cfg, preStateForDebug, blk, 0))
				}
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
			// Receipt-by-receipt compare
			if len(baseRes.Receipts) != len(mirRes.Receipts) {
				return fmt.Errorf("full receipts length mismatch base=%d mir=%d", len(baseRes.Receipts), len(mirRes.Receipts))
			}
			for i := range baseRes.Receipts {
				br := baseRes.Receipts[i]
				mr := mirRes.Receipts[i]
				if br == nil || mr == nil {
					return fmt.Errorf("full receipt nil mismatch idx=%d baseNil=%v mirNil=%v", i, br == nil, mr == nil)
				}
				if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) {
					kind := "common"
					if isSystemTx(env.engine, blk.Transactions()[i], blk.Header()) {
						kind = "system"
					}
					return fmt.Errorf("full receipt mismatch txIdx=%d kind=%s\n  base: %s\n  mir : %s", i, kind, fmtReceipt(br), fmtReceipt(mr))
				}
			}
			baseRoot := baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
			mirRoot := mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number()))
			if baseRoot != mirRoot {
				return fmt.Errorf("full post-state root mismatch\n  base=%s\n  mir =%s", baseRoot, mirRoot)
			}
		}
		return nil
	}

	// Default (non-warmup or fork-parent) path: diff from the same pre-state snapshot.
	baseState := env.statedb.Copy()
	mirState := env.statedb.Copy()

	// IMPORTANT: deep-clone the block for base vs MIR runs.
	// Some execution paths cache sender/signature data or otherwise mutate transaction objects,
	// and sharing the same *types.Block between the two runs can create cache-dependent divergences.
	blkBase, err := cloneBlockForFullProcessing(blk)
	if err != nil {
		return fmt.Errorf("clone block for base: %w", err)
	}
	blkMir, err := cloneBlockForFullProcessing(blk)
	if err != nil {
		return fmt.Errorf("clone block for mir: %w", err)
	}

	baseRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, baseState, blkBase, false)
	if err != nil {
		return fmt.Errorf("base common-tx run failed: %w", err)
	}
	mirRun, err := processCommonTxsOnly(env.engine, env.chain, cfg, mirState, blkMir, true)
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
		blkBase, err := cloneBlockForFullProcessing(blk)
		if err != nil {
			return fmt.Errorf("clone block for base: %w", err)
		}
		blkMir, err := cloneBlockForFullProcessing(blk)
		if err != nil {
			return fmt.Errorf("clone block for mir: %w", err)
		}
		baseRes, baseErr := env.processor.Process(blkBase, baseState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false})
		mirRes, mirErr := env.processor.Process(blkMir, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
		if (baseErr == nil) != (mirErr == nil) {
			// Helpful diagnosis: if full block processing diverges, print tx0 debug
			// (this is typically where fee/state differences originate).
			if len(blk.Transactions()) > 0 {
				fmt.Print(debugOneTx(env.engine, env.chain, cfg, preStateForDebug, blk, 0))
			}
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
func scanRange(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, from, to uint64, doFullBlock bool, fastState bool, readonly bool) error {
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
		env, err = newReplayEnvAtBlockState(db, cfg, genesisHash, from-1, readonly)
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

// findFirstDivergence executes canonical blocks [1..to] in lockstep (base vs MIR) using two
// independent replay environments. It stops at the first mismatch and returns a descriptive error.
func findFirstDivergence(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, to uint64) error {
	if to == 0 {
		return fmt.Errorf("to must be > 0")
	}
	baseEnv, err := newReplayEnv(db, cfg, genesisHash)
	if err != nil {
		return err
	}
	mirEnv, err := newReplayEnv(db, cfg, genesisHash)
	if err != nil {
		return err
	}
	baseCfg := vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false}
	mirCfg := vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true}

	for n := uint64(1); n <= to; n++ {
		h := rawdb.ReadCanonicalHash(db, n)
		if h == (common.Hash{}) {
			return fmt.Errorf("missing canonical hash for block %d", n)
		}
		blk := rawdb.ReadBlock(db, h, n)
		if blk == nil {
			return fmt.Errorf("missing block %d (%s)", n, h)
		}
		// Work on independent StateDB copies so we can preserve clean pre-state for debugging
		// if this block is the first divergence.
		preBase := baseEnv.statedb
		preMir := mirEnv.statedb
		if preBase == nil || preMir == nil {
			return fmt.Errorf("nil pre-state at block %d", n)
		}
		baseWork := preBase.Copy()
		mirWork := preMir.Copy()

		blkBase, err := cloneBlockForFullProcessing(blk)
		if err != nil {
			return fmt.Errorf("clone block %d for base: %w", n, err)
		}
		blkMir, err := cloneBlockForFullProcessing(blk)
		if err != nil {
			return fmt.Errorf("clone block %d for mir: %w", n, err)
		}

		_, baseErr := baseEnv.processor.Process(blkBase, baseWork, baseCfg)
		_, mirErr := mirEnv.processor.Process(blkMir, mirWork, mirCfg)
		if (baseErr == nil) != (mirErr == nil) {
			// Try to localize the mismatch inside common txs (often leads to system-tx mismatch later).
			baseRun, berr := processCommonTxsOnly(baseEnv.engine, baseEnv.chain, cfg, preBase.Copy(), blk, false)
			mirRun, merr := processCommonTxsOnly(mirEnv.engine, mirEnv.chain, cfg, preMir.Copy(), blk, true)
			if berr == nil && merr == nil {
				signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
				for i, tx := range blk.Transactions() {
					if isSystemTx(baseEnv.engine, tx, blk.Header()) {
						continue
					}
					br := baseRun.receiptsByIndex[i]
					mr := mirRun.receiptsByIndex[i]
					if br == nil || mr == nil {
						return fmt.Errorf("block %d missing receipt at idx=%d baseNil=%v mirNil=%v (baseErr=%v mirErr=%v)", n, i, br == nil, mr == nil, baseErr, mirErr)
					}
					if br.Status != mr.Status || br.GasUsed != mr.GasUsed || br.CumulativeGasUsed != mr.CumulativeGasUsed || len(br.Logs) != len(mr.Logs) || baseRun.rootByIndex[i] != mirRun.rootByIndex[i] {
						fromAddr, _ := types.Sender(signer, tx)
						toAddr := "<create>"
						if tx.To() != nil {
							toAddr = tx.To().Hex()
						}
						fmt.Print(debugOneTx(baseEnv.engine, baseEnv.chain, cfg, preBase.Copy(), blk, i))
						return fmt.Errorf("block %d tx mismatch idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s\n  base: %s root=%s\n  mir : %s root=%s\n  full: baseErr=%v mirErr=%v",
							n, i, tx.Hash(), fromAddr, toAddr, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(),
							fmtReceipt(br), baseRun.rootByIndex[i],
							fmtReceipt(mr), mirRun.rootByIndex[i],
							baseErr, mirErr,
						)
					}
				}
			}
			return fmt.Errorf("block %d Process error mismatch: baseErr=%v mirErr=%v", n, baseErr, mirErr)
		}
		if baseErr != nil {
			if baseErr.Error() != mirErr.Error() {
				return fmt.Errorf("block %d Process error msg mismatch: baseErr=%v mirErr=%v", n, baseErr, mirErr)
			}
			return fmt.Errorf("block %d Process failed (both): %v", n, baseErr)
		}

		baseRoot := baseWork.IntermediateRoot(cfg.IsEIP158(blk.Number()))
		mirRoot := mirWork.IntermediateRoot(cfg.IsEIP158(blk.Number()))
		if baseRoot != mirRoot {
			return fmt.Errorf("block %d post-state root mismatch: base=%s mir=%s", n, baseRoot, mirRoot)
		}
		// Advance environments to the post-state for the next block.
		baseEnv.statedb = baseWork
		mirEnv.statedb = mirWork
		if n == 1 || n == to || n%1000 == 0 {
			fmt.Printf("ok: processed %d\n", n)
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
		datadir      = flag.String("datadir", "", "Geth datadir (e.g. /path/to/node_nomir)")
		blockN       = flag.Uint64("block", 90, "Block number to replay (single-block mode)")
		hashS        = flag.String("blockhash", "", "Optional block hash (0x...) to replay. If the block is not canonical, this will try the bad-blocks store.")
		roDB         = flag.Bool("readonlydb", true, "Open the chain database in read-only mode (useful when the node is running and holds the DB lock).")
		clearBB      = flag.Bool("clearbadblocks", false, "Delete the persisted bad-block cache (rawdb InvalidBlock key) in this datadir and exit.")
		listBB       = flag.Bool("listbadblocks", false, "List persisted bad blocks (number/hash) stored under rawdb InvalidBlock key and exit.")
		warmup       = flag.Bool("warmup", false, "Warm up both base and MIR by replaying blocks [1..target-1] in each mode before diffing the target block (helps catch cache-dependent divergences seen in fullnodes).")
		mirUpTo      = flag.Uint64("mirupto", 0, "Execute canonical blocks [1..N] using MIR only and exit (useful to find the first MIR-only failure).")
		baseUpTo     = flag.Uint64("baseupto", 0, "Execute canonical blocks [1..N] using base EVM only and exit (sanity check).")
		firstDiverge = flag.Uint64("firstdiverge", 0, "Execute canonical blocks [1..N] in lockstep (base vs MIR) and exit at the first divergence (error, receipt, or post-state root).")
		fromN        = flag.Uint64("from", 0, "Start block number to scan (inclusive). If set, scan mode is enabled.")
		toN          = flag.Uint64("to", 0, "End block number to scan (inclusive). If set with --from, scan mode is enabled.")
		full         = flag.Bool("full", false, "In scan mode, also run full block processing (system txs + Finalize).")
		fast         = flag.Bool("faststate", false, "In scan mode, initialize pre-state from the on-disk parent state root (from-1) instead of replaying from genesis. Requires the datadir to contain trie nodes for that root.")
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
	//
	// In practice this prevents opening the DB while a fullnode is running. For debug tooling,
	// allow a read-only mode that is safe to run alongside a node.
	readonly := *roDB
	if *clearBB {
		// Clearing bad-block cache requires write access.
		readonly = false
	}
	if *listBB {
		// Listing can be read-only.
		readonly = true
	}
	db, closeDB, err := openChainDB(chaindata, readonly)
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

	if *listBB {
		bads := rawdb.ReadAllBadBlocks(db)
		if len(bads) == 0 {
			fmt.Printf("Bad blocks: none\n")
			return
		}
		fmt.Printf("Bad blocks (%d):\n", len(bads))
		for _, b := range bads {
			if b == nil || b.Header() == nil {
				continue
			}
			fmt.Printf("  number=%d hash=%s\n", b.NumberU64(), b.Hash())
		}
		return
	}
	if *clearBB {
		// Delete persisted bad blocks so a restarted fullnode will retry importing them.
		prev := rawdb.ReadAllBadBlocks(db)
		rawdb.DeleteBadBlocks(db)
		fmt.Printf("Cleared bad blocks: removed %d entries\n", len(prev))
		return
	}

	if *baseUpTo != 0 || *mirUpTo != 0 {
		n := *baseUpTo
		enableMIR := false
		label := "base"
		if *mirUpTo != 0 {
			n = *mirUpTo
			enableMIR = true
			label = "MIR"
		}
		fmt.Printf("Running %s up to block %d...\n", label, n)
		if err := runUpTo(db, cfg, genesisHash, n, enableMIR); err != nil {
			fmt.Fprintf(os.Stderr, "%s upTo(%d) FAILED: %v\n", label, n, err)
			os.Exit(1)
		}
		fmt.Printf("OK: %s up to block %d\n", label, n)
		return
	}

	if *firstDiverge != 0 {
		n := *firstDiverge
		fmt.Printf("Searching first divergence in [1..%d]...\n", n)
		if err := findFirstDivergence(db, cfg, genesisHash, n); err != nil {
			fmt.Fprintf(os.Stderr, "first divergence: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("OK: no divergence in [1..%d]\n", n)
		return
	}

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
		if err := scanRange(db, cfg, genesisHash, start, end, *full, *fast, readonly); err != nil {
			fmt.Fprintf(os.Stderr, "DIFF in scan %d..%d: %v\n", start, end, err)
			os.Exit(1)
		}
		fmt.Printf("OK: blocks [%d..%d] match\n", start, end)
		return
	}

	// Hash mode: --blockhash set.
	if strings.TrimSpace(*hashS) != "" {
		hh := common.HexToHash(strings.TrimSpace(*hashS))
		if hh == (common.Hash{}) {
			fmt.Fprintf(os.Stderr, "bad --blockhash: %q\n", *hashS)
			os.Exit(2)
		}
		blk := rawdb.ReadBlock(db, hh, 0)
		if blk == nil {
			blk = rawdb.ReadBadBlock(db, hh)
		}
		if blk == nil || blk.Header() == nil {
			fmt.Fprintf(os.Stderr, "missing block for hash %s (not canonical and not found in bad blocks)\n", hh.Hex())
			os.Exit(1)
		}
		fmt.Printf("Diffing block by hash %s number=%d common txs (MIR off/on)...\n", hh.Hex(), blk.NumberU64())
		if err := diffBlockCommonTxsWithBlock(db, cfg, genesisHash, blk, true, true, *warmup, readonly); err != nil {
			fmt.Fprintf(os.Stderr, "DIFF: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("OK: full block %d matches (including system txs + Finalize)\n", blk.NumberU64())
		return
	}

	// Single-block mode
	fmt.Printf("Diffing block %d common txs (MIR off/on)...\n", *blockN)
	// In single-block mode, run full block processing too.
	if err := diffBlockCommonTxs(db, cfg, genesisHash, *blockN, true, *warmup, readonly); err != nil {
		fmt.Fprintf(os.Stderr, "DIFF: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: common txs match for block %d\n", *blockN)
}
