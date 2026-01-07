package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
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
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

func isBSCSystemTx(tx *types.Transaction) bool {
	to := tx.To()
	if to == nil {
		return false
	}
	// BSC system contracts (legacy, still present on testnet):
	// - 0x...1000 validator set/system
	// - 0x...1002 system reward
	if *to == common.HexToAddress("0x0000000000000000000000000000000000001000") {
		return true
	}
	if *to == common.HexToAddress("0x0000000000000000000000000000000000001002") {
		return true
	}
	return false
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
	chain     *core.HeaderChain
	processor *core.StateProcessor
	statedb   *state.StateDB
}

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
		chain:     chain,
		processor: processor,
		statedb:   statedb,
	}, nil
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

func processCommonTxsOnly(chain *core.HeaderChain, cfg *params.ChainConfig, statedb *state.StateDB, blk *types.Block, enableMIR bool) (*txRun, error) {
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
		if isBSCSystemTx(tx) {
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

func debugOneTx(chain *core.HeaderChain, cfg *params.ChainConfig, preState *state.StateDB, blk *types.Block, txIndex int) string {
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
	// Dump a tiny opcode window around the suspected REVERT block for quick sanity checks.
	if tx.To() != nil && preState != nil {
		code := preState.GetCode(*tx.To())
		if len(code) > 13025 {
			start := 13010
			end := 13025
			sb.WriteString(fmt.Sprintf("CODE[%d:%d] bytes: 0x%x\n", start, end, code[start:end]))
		}
	}

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
	baseOps := make([]pcOp, 0, 4096)
	var lastBasePC uint64
	var lastBaseOp byte
	var baseGTEndTop, baseGTEndBelow, baseGT0, baseGT1 string
	var baseJUMPIEndTop, baseJUMPIEndBelow, baseJUMPI0, baseJUMPI1 string
	var baseADD3595Top, baseADD3595Below string
	var baseADD3533Top, baseADD3533Below string
	var baseADD3591Top, baseADD3591Below string
	var baseKeccak3581Off, baseKeccak3581Sz string
	var baseKeccak3581Data string
	var baseKeccak3581Hash string
	var baseJump6048Tail []string
	var baseJump6048Count int
	baseJUMPIWindowCounts := make(map[uint64]int)
	baseJUMPIWindowLast := make(map[uint64]string)
	baseJumpdestCounts := make(map[uint64]int)
	baseJumpdestSeq := make([]uint64, 0, 64)
	// Block-976 targeted capture (pc=13015 JUMPI -> 13020 else 13019 REVERT).
	var baseJUMPI13015Dest, baseJUMPI13015Cond string
	var baseJUMPI13015Count int
	var baseLT13010Top, baseLT13010Below string
	var baseLT13010Count int
	var baseSSTORE9282Key, baseSSTORE9282Val string
	var baseKECCAK9308 string
	var baseSLOAD9309Key string
	var baseSLOAD9162Key string
	var baseSLOAD9263Key string
	var baseSLOAD9285Key string
	var baseJUMP9324Dest string
	var baseJUMP9324Count int
	var baseJUMP9324Last string
	var baseJUMP9278Dest string
	var baseJUMP13026Dest string
	baseTracer := &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, _ []byte, depth int, err error) {
		lastBasePC, lastBaseOp = pc, op
		// Record only the top-level contract frame (depth==1) so we can align vs MIR (which runs at depth 0).
		if depth == 1 && len(baseOps) < cap(baseOps) {
			baseOps = append(baseOps, pcOp{pc: pc, op: op})
		}
		// Capture operands at the divergence site in the top-level frame.
		// GT at pc=3598 uses stack top as x and below-top as y (x,y := pop(), peek()).
		if depth == 1 && pc == 3598 && op == 0x11 && scope != nil {
			st := scope.StackData()
			if len(st) >= 2 {
				endTop := st[len(st)-1].Bytes32()
				endBelow := st[len(st)-2].Bytes32()
				baseGTEndTop = fmt.Sprintf("0x%x", endTop)
				baseGTEndBelow = fmt.Sprintf("0x%x", endBelow)
				baseGT0 = fmt.Sprintf("0x%x", st[0].Bytes32())
				baseGT1 = fmt.Sprintf("0x%x", st[1].Bytes32())
			}
		}
		// JUMPI at pc=3602 uses stack top as dest and below-top as cond (pos,cond := pop2()).
		if depth == 1 && pc == 3602 && op == 0x57 && scope != nil {
			st := scope.StackData()
			if len(st) >= 2 {
				endTop := st[len(st)-1].Bytes32()
				endBelow := st[len(st)-2].Bytes32()
				baseJUMPIEndTop = fmt.Sprintf("0x%x", endTop)
				baseJUMPIEndBelow = fmt.Sprintf("0x%x", endBelow)
				baseJUMPI0 = fmt.Sprintf("0x%x", st[0].Bytes32())
				baseJUMPI1 = fmt.Sprintf("0x%x", st[1].Bytes32())
			}
		}
		// Block-976: capture JUMPI operands at pc=13015.
		if depth == 1 && pc == 13015 && op == 0x57 && scope != nil {
			baseJUMPI13015Count++
			st := scope.StackData()
			if len(st) >= 2 {
				// EVM JUMPI pops (dest, cond) from stack where dest is top.
				baseJUMPI13015Dest = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseJUMPI13015Cond = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// Block-976: capture LT operands at pc=13010 (x=top, y=below).
		if depth == 1 && pc == 13010 && op == 0x10 && scope != nil {
			baseLT13010Count++
			st := scope.StackData()
			if len(st) >= 2 {
				baseLT13010Top = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseLT13010Below = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// Block-976: capture SSTORE operands at pc=9282 (key=top, val=below).
		if depth == 1 && pc == 9282 && op == 0x55 && scope != nil && baseSSTORE9282Key == "" {
			st := scope.StackData()
			if len(st) >= 2 {
				baseSSTORE9282Key = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseSSTORE9282Val = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// Block-976: capture KECCAK input at pc=9308 (off=top, size=below) + first 64 bytes.
		if depth == 1 && pc == 9308 && op == 0x20 && scope != nil && baseKECCAK9308 == "" {
			st := scope.StackData()
			mem := scope.MemoryData()
			if len(st) >= 2 {
				off := st[len(st)-1].Uint64()
				sz := st[len(st)-2].Uint64()
				snip := int(sz)
				if snip > 64 {
					snip = 64
				}
				var data []byte
				if mem != nil && int(off)+snip <= len(mem) && snip > 0 {
					data = mem[int(off) : int(off)+snip]
				}
				baseKECCAK9308 = fmt.Sprintf("off=%d sz=%d data(64)=0x%x", off, sz, data)
			}
		}
		// Block-976: capture SLOAD key at pc=9309.
		if depth == 1 && pc == 9309 && op == 0x54 && scope != nil && baseSLOAD9309Key == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseSLOAD9309Key = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		// Block-976: capture other SLOAD keys that participate in the same flow.
		if depth == 1 && pc == 9162 && op == 0x54 && scope != nil && baseSLOAD9162Key == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseSLOAD9162Key = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		if depth == 1 && pc == 9263 && op == 0x54 && scope != nil && baseSLOAD9263Key == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseSLOAD9263Key = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		if depth == 1 && pc == 9285 && op == 0x54 && scope != nil && baseSLOAD9285Key == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseSLOAD9285Key = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		// Block-976: capture JUMP dest at pc=9324.
		if depth == 1 && pc == 9324 && op == 0x56 && scope != nil {
			st := scope.StackData()
			if len(st) >= 1 {
				baseJUMP9324Count++
				baseJUMP9324Last = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				if baseJUMP9324Dest == "" {
					baseJUMP9324Dest = baseJUMP9324Last
				}
			}
		}
		// Block-976: capture other key JUMP destinations.
		if depth == 1 && pc == 9278 && op == 0x56 && scope != nil && baseJUMP9278Dest == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseJUMP9278Dest = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		if depth == 1 && pc == 13026 && op == 0x56 && scope != nil && baseJUMP13026Dest == "" {
			st := scope.StackData()
			if len(st) >= 1 {
				baseJUMP13026Dest = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
			}
		}
		// Track JUMPDEST visits for a coarse control-flow signature.
		if depth == 1 && op == 0x5b {
			baseJumpdestCounts[pc]++
			baseJumpdestSeq = append(baseJumpdestSeq, pc)
			if len(baseJumpdestSeq) > 64 {
				baseJumpdestSeq = baseJumpdestSeq[len(baseJumpdestSeq)-64:]
			}
		}
		// ADD at pc=3595 (op=0x01): capture top two stack items (x=top, y=below).
		if depth == 1 && pc == 3595 && op == 0x01 && scope != nil && baseADD3595Top == "" {
			st := scope.StackData()
			if len(st) >= 2 {
				baseADD3595Top = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseADD3595Below = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// ADD at pc=3533 (op=0x01)
		if depth == 1 && pc == 3533 && op == 0x01 && scope != nil && baseADD3533Top == "" {
			st := scope.StackData()
			if len(st) >= 2 {
				baseADD3533Top = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseADD3533Below = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// ADD at pc=3591 (op=0x01)
		if depth == 1 && pc == 3591 && op == 0x01 && scope != nil && baseADD3591Top == "" {
			st := scope.StackData()
			if len(st) >= 2 {
				baseADD3591Top = fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseADD3591Below = fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
			}
		}
		// KECCAK256 at pc=3581 (op=0x20): capture offset/size and first bytes of input.
		if depth == 1 && pc == 3581 && op == 0x20 && scope != nil && baseKeccak3581Off == "" {
			st := scope.StackData()
			mem := scope.MemoryData()
			if len(st) >= 2 {
				off := st[len(st)-1].Uint64()
				sz := st[len(st)-2].Uint64()
				baseKeccak3581Off = fmt.Sprintf("%d", off)
				baseKeccak3581Sz = fmt.Sprintf("%d", sz)
				snip := int(sz)
				if snip > 64 {
					snip = 64
				}
				if snip < 0 {
					snip = 0
				}
				if mem != nil && int(off) >= 0 && int(off)+snip <= len(mem) {
					slice := mem[int(off) : int(off)+snip]
					baseKeccak3581Data = fmt.Sprintf("0x%x", slice)
					if snip == int(sz) {
						h := crypto.Keccak256Hash(slice)
						baseKeccak3581Hash = fmt.Sprintf("0x%x", h[:])
					}
				}
			}
		}
		// Track JUMP dest at pc=6048 (tail window).
		if depth == 1 && pc == 6048 && op == 0x56 && scope != nil {
			baseJump6048Count++
			st := scope.StackData()
			if len(st) >= 1 {
				dest := fmt.Sprintf("0x%x", st[len(st)-1].Bytes32())
				baseJump6048Tail = append(baseJump6048Tail, dest)
				if len(baseJump6048Tail) > 5 {
					baseJump6048Tail = baseJump6048Tail[len(baseJump6048Tail)-5:]
				}
			}
		}
		// Track JUMPI conditions in the hot loop region (wide window).
		if depth == 1 && op == 0x57 && pc >= 5900 && pc <= 6200 && scope != nil {
			st := scope.StackData()
			if len(st) >= 2 {
				cond := fmt.Sprintf("0x%x", st[len(st)-2].Bytes32())
				baseJUMPIWindowCounts[pc]++
				baseJUMPIWindowLast[pc] = cond
			}
		}
		if len(baseTrace) == cap(baseTrace) {
			copy(baseTrace, baseTrace[1:])
			baseTrace = baseTrace[:cap(baseTrace)-1]
		}
		baseTrace = append(baseTrace, evmStep{pc: pc, op: op, gas: gas, cost: cost, depth: depth, err: err})
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
			if isBSCSystemTx(ptx) {
				continue
			}
			_, _, _ = applyTxWithResult(prefixEVM, baseState, header, ptx, i, &prefixUsed, prefixGP)
		}
	}
	baseEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), baseState, cfg, vm.Config{EnableMIR: false, Tracer: baseTracer})
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
	mirOps := make([]pcOp, 0, 4096)
	var lastMirPC uint
	var lastMirOp byte
	var mirGTA, mirGTB string
	var mirJUMPIDest2, mirJUMPICond2 string
	var mirGTASrc, mirGTBSrc string
	var mirADD3595A, mirADD3595B, mirADD3595ASrc, mirADD3595BSrc string
	var mirADD3533A, mirADD3533B, mirADD3533ASrc, mirADD3533BSrc string
	var mirADD3591A, mirADD3591B, mirADD3591ASrc, mirADD3591BSrc string
	var mirKeccak3581 string
	var mirKeccak3581Hash string
	var mirJump6048Tail []string
	var mirJump6048Count int
	mirJUMPIWindowCounts := make(map[uint64]int)
	mirJUMPIWindowLast := make(map[uint64]string)
	var mirLastBlockPC uint = ^uint(0)
	mirBlockEnterCounts := make(map[uint]uint32)
	mirBlockSeq := make([]uint, 0, 64)
	mirBlockEnterNotes := make([]string, 0, 64)
	mirResolveTail := make([]string, 0, 64)
	// Block-976 targeted capture
	var mirJUMPI13015Dest, mirJUMPI13015Cond string
	var mirJUMPI13015Count int
	var mirLT13010A, mirLT13010B string
	var mirLT13010Count int
	var mirSSTORE9282Key, mirSSTORE9282Val string
	var mirSLOAD9309Key string
	var mirSLOAD9309Val string
	var mirSLOAD9162Key, mirSLOAD9162Val string
	var mirSLOAD9263Key, mirSLOAD9263Val string
	var mirSLOAD9285Key, mirSLOAD9285Val string
	var mirKECCAK9308 string
	var mirJUMP9324Dest string
	var mirJUMP9324Count int
	var mirJUMP9324Last string
	var mirJUMP9278Dest string
	var mirJUMP13026Dest string
	mirTracer := &tracing.Hooks{OnEnter: func(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
		if len(mirCalls) == cap(mirCalls) {
			copy(mirCalls, mirCalls[1:])
			mirCalls = mirCalls[:cap(mirCalls)-1]
		}
		mirCalls = append(mirCalls, fmt.Sprintf("enter depth=%d typ=0x%02x from=%s to=%s gas=%d input=%d value=%s", depth, typ, from, to, gas, len(input), value))
	}, OnExit: func(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
		if len(mirCalls) == cap(mirCalls) {
			copy(mirCalls, mirCalls[1:])
			mirCalls = mirCalls[:cap(mirCalls)-1]
		}
		mirCalls = append(mirCalls, fmt.Sprintf("exit  depth=%d gasUsed=%d reverted=%v err=%v output=%d", depth, gasUsed, reverted, err, len(output)))
	}}
	// Apply preceding common txs first (with MIR enabled) so the sender nonces match the real block.
	{
		prefixEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), mirState, cfg, vm.Config{EnableMIR: true})
		prefixRunner := mir.NewEVMRunner(prefixEVM)
		prefixEVM.SetMIRRunner(prefixRunner)
		prefixGP := new(core.GasPool).AddGas(blk.GasLimit())
		prefixUsed := uint64(0)
		for i := 0; i < txIndex; i++ {
			ptx := blk.Transactions()[i]
			if isBSCSystemTx(ptx) {
				continue
			}
			_, _, _ = applyTxWithResult(prefixEVM, mirState, header, ptx, i, &prefixUsed, prefixGP)
		}
	}

	mirEVM := vm.NewEVM(core.NewEVMBlockContext(header, chain, nil), mirState, cfg, vm.Config{EnableMIR: true, Tracer: mirTracer})
	runner := mir.NewEVMRunner(mirEVM)
	runner.SetMIRStepHookFactory(func(it *mir.MIRInterpreter) func(evmPC uint, evmOp byte, op mir.MirOperation) {
		// Attach operand hook for this run.
		if it != nil {
			it.SetDebugOperandHook(func(evmPC uint, evmOp byte, op mir.MirOperation, a uint256.Int, b uint256.Int) {
				if evmPC == 3591 && op == mir.MirADD && mirADD3591A == "" {
					aa := a.Bytes32()
					bb := b.Bytes32()
					mirADD3591A = fmt.Sprintf("0x%x", aa)
					mirADD3591B = fmt.Sprintf("0x%x", bb)
				}
				if evmPC == 3533 && op == mir.MirADD && mirADD3533A == "" {
					aa := a.Bytes32()
					bb := b.Bytes32()
					mirADD3533A = fmt.Sprintf("0x%x", aa)
					mirADD3533B = fmt.Sprintf("0x%x", bb)
				}
				if evmPC == 3595 && op == mir.MirADD && mirADD3595A == "" {
					aa := a.Bytes32()
					bb := b.Bytes32()
					mirADD3595A = fmt.Sprintf("0x%x", aa)
					mirADD3595B = fmt.Sprintf("0x%x", bb)
				}
				if evmPC == 6048 && op == mir.MirJUMP {
					mirJump6048Count++
					dd := a.Bytes32()
					mirJump6048Tail = append(mirJump6048Tail, fmt.Sprintf("0x%x", dd))
					if len(mirJump6048Tail) > 5 {
						mirJump6048Tail = mirJump6048Tail[len(mirJump6048Tail)-5:]
					}
				}
				if evmPC == 3598 && op == mir.MirGT {
					aa := a.Bytes32()
					bb := b.Bytes32()
					mirGTA = fmt.Sprintf("0x%x", aa)
					mirGTB = fmt.Sprintf("0x%x", bb)
				}
				if evmPC == 3602 && op == mir.MirJUMPI {
					dd := a.Bytes32()
					cc := b.Bytes32()
					mirJUMPIDest2 = fmt.Sprintf("0x%x", dd)
					mirJUMPICond2 = fmt.Sprintf("0x%x", cc)
				}
				if evmOp == 0x57 && op == mir.MirJUMPI && evmPC >= 5900 && evmPC <= 6200 {
					mirJUMPIWindowCounts[uint64(evmPC)]++
					mirJUMPIWindowLast[uint64(evmPC)] = fmt.Sprintf("0x%x", b.Bytes32())
				}
				// Block-976: capture JUMPI operands at pc=13015.
				if evmPC == 13015 && op == mir.MirJUMPI {
					mirJUMPI13015Count++
					mirJUMPI13015Dest = fmt.Sprintf("0x%x", a.Bytes32())
					mirJUMPI13015Cond = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 13010 && op == mir.MirLT {
					mirLT13010Count++
					mirLT13010A = fmt.Sprintf("0x%x", a.Bytes32())
					mirLT13010B = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9282 && op == mir.MirSSTORE && mirSSTORE9282Key == "" {
					mirSSTORE9282Key = fmt.Sprintf("0x%x", a.Bytes32())
					mirSSTORE9282Val = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9309 && op == mir.MirSLOAD {
					if mirSLOAD9309Key == "" {
						mirSLOAD9309Key = fmt.Sprintf("0x%x", a.Bytes32())
					}
					// After-read hook populates b with the loaded value.
					mirSLOAD9309Val = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9162 && op == mir.MirSLOAD {
					if mirSLOAD9162Key == "" {
						mirSLOAD9162Key = fmt.Sprintf("0x%x", a.Bytes32())
					}
					mirSLOAD9162Val = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9263 && op == mir.MirSLOAD {
					if mirSLOAD9263Key == "" {
						mirSLOAD9263Key = fmt.Sprintf("0x%x", a.Bytes32())
					}
					mirSLOAD9263Val = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9285 && op == mir.MirSLOAD {
					if mirSLOAD9285Key == "" {
						mirSLOAD9285Key = fmt.Sprintf("0x%x", a.Bytes32())
					}
					mirSLOAD9285Val = fmt.Sprintf("0x%x", b.Bytes32())
				}
				if evmPC == 9324 && op == mir.MirJUMP && mirJUMP9324Dest == "" {
					mirJUMP9324Count++
					mirJUMP9324Last = fmt.Sprintf("0x%x", a.Bytes32())
					mirJUMP9324Dest = mirJUMP9324Last
				} else if evmPC == 9324 && op == mir.MirJUMP {
					mirJUMP9324Count++
					mirJUMP9324Last = fmt.Sprintf("0x%x", a.Bytes32())
				}
				if evmPC == 9278 && op == mir.MirJUMP && mirJUMP9278Dest == "" {
					mirJUMP9278Dest = fmt.Sprintf("0x%x", a.Bytes32())
				}
				if evmPC == 13026 && op == mir.MirJUMP && mirJUMP13026Dest == "" {
					mirJUMP13026Dest = fmt.Sprintf("0x%x", a.Bytes32())
				}
			})
			it.SetDebugOperandHookEx(func(evmPC uint, evmOp byte, op mir.MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp mir.MirOperation, bDefOp mir.MirOperation) {
				if evmPC == 3591 && op == mir.MirADD && mirADD3591ASrc == "" {
					mirADD3591ASrc = fmt.Sprintf("aDef=(pc=%d op=%s)", aDefPC, aDefOp.String())
					mirADD3591BSrc = fmt.Sprintf("bDef=(pc=%d op=%s)", bDefPC, bDefOp.String())
				}
				if evmPC == 3533 && op == mir.MirADD && mirADD3533ASrc == "" {
					mirADD3533ASrc = fmt.Sprintf("aDef=(pc=%d op=%s)", aDefPC, aDefOp.String())
					mirADD3533BSrc = fmt.Sprintf("bDef=(pc=%d op=%s)", bDefPC, bDefOp.String())
				}
				if evmPC == 3595 && op == mir.MirADD && mirADD3595ASrc == "" {
					mirADD3595ASrc = fmt.Sprintf("aDef=(pc=%d op=%s)", aDefPC, aDefOp.String())
					mirADD3595BSrc = fmt.Sprintf("bDef=(pc=%d op=%s)", bDefPC, bDefOp.String())
				}
				if evmPC == 3598 && op == mir.MirGT {
					mirGTASrc = fmt.Sprintf("aDef=(pc=%d op=%s)", aDefPC, aDefOp.String())
					mirGTBSrc = fmt.Sprintf("bDef=(pc=%d op=%s)", bDefPC, bDefOp.String())
				}
			})
			it.SetDebugKeccakHook(func(evmPC uint, off uint64, sz uint64, data []byte) {
				if evmPC == 3581 && mirKeccak3581 == "" {
					mirKeccak3581 = fmt.Sprintf("off=%d sz=%d data(64)=0x%x", off, sz, data)
					if uint64(len(data)) == sz {
						h := crypto.Keccak256Hash(data)
						mirKeccak3581Hash = fmt.Sprintf("0x%x", h[:])
					}
				}
				if evmPC == 9308 && mirKECCAK9308 == "" {
					mirKECCAK9308 = fmt.Sprintf("off=%d sz=%d data(64)=0x%x", off, sz, data)
				}
			})
			it.SetResolveHook(func(fromFirstPC uint, fromEvmPC uint, targetPC uint, resolvedFirstPC uint, existed bool) {
				// Keep a small tail buffer; focus on the suspicious region.
				if targetPC < 9000 {
					return
				}
				entry := fmt.Sprintf("resolve fromBB=%d fromEvmPC=%d -> target=%d resolvedBB=%d existed=%v", fromFirstPC, fromEvmPC, targetPC, resolvedFirstPC, existed)
				mirResolveTail = append(mirResolveTail, entry)
				if len(mirResolveTail) > 32 {
					mirResolveTail = mirResolveTail[len(mirResolveTail)-32:]
				}
			})
		}
		return func(evmPC uint, evmOp byte, op mir.MirOperation) {
			lastMirPC, lastMirOp = evmPC, evmOp
			if it != nil {
				bpc := it.CurrentBlockFirstPC()
				if bpc != mirLastBlockPC {
					mirLastBlockPC = bpc
					mirBlockEnterCounts[bpc]++
					mirBlockSeq = append(mirBlockSeq, bpc)
					if len(mirBlockSeq) > 64 {
						mirBlockSeq = mirBlockSeq[len(mirBlockSeq)-64:]
					}
					// For a couple of suspicious blocks, record the terminator MIR op (if any).
					if bpc == 9279 || bpc == 13002 || bpc == 13016 {
						b := it.CurrentBlock()
						note := fmt.Sprintf("pc=%d term=<nil>", bpc)
						if b != nil {
							ins := b.Instructions()
							if len(ins) > 0 && ins[len(ins)-1] != nil {
								last := ins[len(ins)-1]
								note = fmt.Sprintf("pc=%d term=%s evmPC=%d evmOp=0x%02x", bpc, last.Op().String(), last.EvmPC(), last.EvmOp())
							} else {
								note = fmt.Sprintf("pc=%d term=<empty>", bpc)
							}
						}
						mirBlockEnterNotes = append(mirBlockEnterNotes, note)
						if len(mirBlockEnterNotes) > 64 {
							mirBlockEnterNotes = mirBlockEnterNotes[len(mirBlockEnterNotes)-64:]
						}
					}
				}
			}
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
	if baseGTEndTop != "" || mirGTA != "" {
		sb.WriteString(fmt.Sprintf("GT@3598 stack: BASE(endTop=%s endBelow=%s | st[0]=%s st[1]=%s) | MIR(a=%s b=%s) %s %s\n", baseGTEndTop, baseGTEndBelow, baseGT0, baseGT1, mirGTA, mirGTB, mirGTASrc, mirGTBSrc))
	}
	if baseADD3595Top != "" || mirADD3595A != "" {
		sb.WriteString(fmt.Sprintf("ADD@3595 stack: BASE(top=%s below=%s) | MIR(a=%s b=%s) %s %s\n", baseADD3595Top, baseADD3595Below, mirADD3595A, mirADD3595B, mirADD3595ASrc, mirADD3595BSrc))
	}
	if baseADD3533Top != "" || mirADD3533A != "" {
		sb.WriteString(fmt.Sprintf("ADD@3533 stack: BASE(top=%s below=%s) | MIR(a=%s b=%s) %s %s\n", baseADD3533Top, baseADD3533Below, mirADD3533A, mirADD3533B, mirADD3533ASrc, mirADD3533BSrc))
	}
	if baseADD3591Top != "" || mirADD3591A != "" {
		sb.WriteString(fmt.Sprintf("ADD@3591 stack: BASE(top=%s below=%s) | MIR(a=%s b=%s) %s %s\n", baseADD3591Top, baseADD3591Below, mirADD3591A, mirADD3591B, mirADD3591ASrc, mirADD3591BSrc))
	}
	if baseKeccak3581Off != "" || mirKeccak3581 != "" {
		sb.WriteString(fmt.Sprintf("KECCAK@3581: BASE(off=%s sz=%s data(64)=%s hash=%s) | MIR(%s hash=%s)\n", baseKeccak3581Off, baseKeccak3581Sz, baseKeccak3581Data, baseKeccak3581Hash, mirKeccak3581, mirKeccak3581Hash))
	}
	if len(baseJump6048Tail) > 0 || len(mirJump6048Tail) > 0 {
		sb.WriteString(fmt.Sprintf("JUMP@6048: BASE(count=%d tail=%v) | MIR(count=%d tail=%v)\n", baseJump6048Count, baseJump6048Tail, mirJump6048Count, mirJump6048Tail))
	}
	if len(baseJUMPIWindowCounts) > 0 || len(mirJUMPIWindowCounts) > 0 {
		sb.WriteString("JUMPI loop-window summary (pc: baseCount/baseLastCond | mirCount/mirLastCond):\n")
		for pc := uint64(5900); pc <= 6200; pc++ {
			bc := baseJUMPIWindowCounts[pc]
			mc := mirJUMPIWindowCounts[pc]
			if bc == 0 && mc == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("  pc=%d: base=%d/%s | mir=%d/%s\n", pc, bc, baseJUMPIWindowLast[pc], mc, mirJUMPIWindowLast[pc]))
		}
	}
	if baseJUMPI13015Dest != "" || mirJUMPI13015Dest != "" {
		sb.WriteString(fmt.Sprintf("JUMPI@13015 last: BASE(count=%d dest=%s cond=%s) | MIR(count=%d dest=%s cond=%s)\n",
			baseJUMPI13015Count, baseJUMPI13015Dest, baseJUMPI13015Cond,
			mirJUMPI13015Count, mirJUMPI13015Dest, mirJUMPI13015Cond))
	}
	if baseLT13010Top != "" || mirLT13010A != "" {
		sb.WriteString(fmt.Sprintf("LT@13010 last: BASE(count=%d top=%s below=%s) | MIR(count=%d a=%s b=%s)\n",
			baseLT13010Count, baseLT13010Top, baseLT13010Below,
			mirLT13010Count, mirLT13010A, mirLT13010B))
	}
	if baseSSTORE9282Key != "" || mirSSTORE9282Key != "" {
		sb.WriteString(fmt.Sprintf("SSTORE@9282: BASE(key=%s val=%s) | MIR(key=%s val=%s)\n",
			baseSSTORE9282Key, baseSSTORE9282Val, mirSSTORE9282Key, mirSSTORE9282Val))
	}
	if baseKECCAK9308 != "" || mirKECCAK9308 != "" {
		sb.WriteString(fmt.Sprintf("KECCAK@9308: BASE(%s) | MIR(%s)\n", baseKECCAK9308, mirKECCAK9308))
	}
	if baseSLOAD9309Key != "" || mirSLOAD9309Key != "" {
		sb.WriteString(fmt.Sprintf("SLOAD@9309 key: BASE(%s) | MIR(%s)\n", baseSLOAD9309Key, mirSLOAD9309Key))
	}
	if tx.To() != nil && baseSLOAD9309Key != "" {
		slot := common.HexToHash(baseSLOAD9309Key)
		preV := preState.GetState(*tx.To(), slot)
		sb.WriteString(fmt.Sprintf("PRESTATE SLOAD@9309 value: 0x%x\n", preV[:]))
	}
	if mirSLOAD9309Val != "" {
		sb.WriteString(fmt.Sprintf("MIR SLOAD@9309 loaded value: %s\n", mirSLOAD9309Val))
	}
	if tx.To() != nil && baseSLOAD9162Key != "" {
		slot := common.HexToHash(baseSLOAD9162Key)
		preV := preState.GetState(*tx.To(), slot)
		sb.WriteString(fmt.Sprintf("PRESTATE SLOAD@9162 key=%s value=0x%x\n", baseSLOAD9162Key, preV[:]))
	}
	if mirSLOAD9162Val != "" {
		sb.WriteString(fmt.Sprintf("MIR SLOAD@9162 key=%s value=%s\n", mirSLOAD9162Key, mirSLOAD9162Val))
	}
	if tx.To() != nil && baseSLOAD9263Key != "" {
		slot := common.HexToHash(baseSLOAD9263Key)
		preV := preState.GetState(*tx.To(), slot)
		sb.WriteString(fmt.Sprintf("PRESTATE SLOAD@9263 key=%s value=0x%x\n", baseSLOAD9263Key, preV[:]))
	}
	if mirSLOAD9263Val != "" {
		sb.WriteString(fmt.Sprintf("MIR SLOAD@9263 key=%s value=%s\n", mirSLOAD9263Key, mirSLOAD9263Val))
	}
	// SLOAD@9285 happens after SSTORE@9282; expected to reflect the stored value if keys match.
	if baseSLOAD9285Key != "" {
		sb.WriteString(fmt.Sprintf("BASE SLOAD@9285 key=%s\n", baseSLOAD9285Key))
	}
	if mirSLOAD9285Val != "" {
		sb.WriteString(fmt.Sprintf("MIR SLOAD@9285 key=%s value=%s\n", mirSLOAD9285Key, mirSLOAD9285Val))
	}
	if baseJUMP9324Dest != "" || mirJUMP9324Dest != "" {
		sb.WriteString(fmt.Sprintf("JUMP@9324: BASE(first=%s count=%d last=%s) | MIR(first=%s count=%d last=%s)\n",
			baseJUMP9324Dest, baseJUMP9324Count, baseJUMP9324Last,
			mirJUMP9324Dest, mirJUMP9324Count, mirJUMP9324Last))
	}
	if baseJUMP9278Dest != "" || mirJUMP9278Dest != "" {
		sb.WriteString(fmt.Sprintf("JUMP@9278 dest: BASE(%s) | MIR(%s)\n", baseJUMP9278Dest, mirJUMP9278Dest))
	}
	if baseJUMP13026Dest != "" || mirJUMP13026Dest != "" {
		sb.WriteString(fmt.Sprintf("JUMP@13026 dest: BASE(%s) | MIR(%s)\n", baseJUMP13026Dest, mirJUMP13026Dest))
	}
	for _, pc := range []uint64{13002, 13020} {
		if n := baseJumpdestCounts[pc]; n > 0 {
			sb.WriteString(fmt.Sprintf("BASE JUMPDEST visits pc=%d count=%d\n", pc, n))
		}
	}
	if len(baseJumpdestSeq) > 0 {
		sb.WriteString(fmt.Sprintf("BASE JUMPDEST tail: %v\n", baseJumpdestSeq))
	}
	for _, pc := range []uint{13002, 13020} {
		if n := mirBlockEnterCounts[pc]; n > 0 {
			sb.WriteString(fmt.Sprintf("MIR block enters pc=%d count=%d\n", pc, n))
		}
	}
	if len(mirBlockSeq) > 0 {
		sb.WriteString(fmt.Sprintf("MIR block entry tail: %v\n", mirBlockSeq))
	}
	if len(mirBlockEnterNotes) > 0 {
		sb.WriteString("MIR block entry notes (tail):\n")
		for _, n := range mirBlockEnterNotes {
			sb.WriteString("  " + n + "\n")
		}
	}
	if len(mirResolveTail) > 0 {
		sb.WriteString("MIR resolveBB tail:\n")
		for _, n := range mirResolveTail {
			sb.WriteString("  " + n + "\n")
		}
	}
	if baseJUMPIEndTop != "" || mirJUMPIDest2 != "" {
		sb.WriteString(fmt.Sprintf("JUMPI@3602 stack: BASE(endTop=%s endBelow=%s | st[0]=%s st[1]=%s) | MIR(dest=%s cond=%s)\n", baseJUMPIEndTop, baseJUMPIEndBelow, baseJUMPI0, baseJUMPI1, mirJUMPIDest2, mirJUMPICond2))
	}

	// Best-effort: find first divergence in (pc,op) stream. Note MIR stream is sourced from MIR step hook
	// and may omit optimized-away opcodes.
	if len(baseOps) > 0 && len(mirOps) > 0 {
		// Two-pointer alignment: advance base over ignorable ops (PUSH/DUP/SWAP/JUMPDEST) until it matches MIR.
		i, j := 0, 0
		for i < len(baseOps) && j < len(mirOps) {
			if baseOps[i].pc == mirOps[j].pc && baseOps[i].op == mirOps[j].op {
				i++
				j++
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
	}

	sb.WriteString("\n--- BASE last opcodes (tail) ---\n")
	for _, s := range baseTrace {
		sb.WriteString(fmt.Sprintf("pc=%d op=0x%02x gas=%d cost=%d depth=%d err=%v\n", s.pc, s.op, s.gas, s.cost, s.depth, s.err))
	}
	sb.WriteString("\n--- BASE call frames (tail) ---\n")
	for _, c := range baseCalls {
		sb.WriteString(c + "\n")
	}
	sb.WriteString("\n--- MIR last steps (tail) ---\n")
	for _, s := range mirTrace {
		sb.WriteString(fmt.Sprintf("evmPC=%d evmOp=0x%02x mirOp=%s gasLeft=%d\n", s.evmPC, s.evmOp, s.op.String(), s.gasLeft))
	}
	sb.WriteString("\n--- MIR call frames (tail) ---\n")
	for _, c := range mirCalls {
		sb.WriteString(c + "\n")
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

	baseState := env.statedb.Copy()
	mirState := env.statedb.Copy()

	baseRun, err := processCommonTxsOnly(env.chain, cfg, baseState, blk, false)
	if err != nil {
		return fmt.Errorf("base common-tx run failed: %w", err)
	}
	mirRun, err := processCommonTxsOnly(env.chain, cfg, mirState, blk, true)
	if err != nil {
		return fmt.Errorf("mir common-tx run failed: %w", err)
	}

	signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
	for i, tx := range blk.Transactions() {
		if isBSCSystemTx(tx) {
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
			fmt.Print(debugOneTx(env.chain, cfg, env.statedb, blk, i))
			return fmt.Errorf("tx receipt mismatch idx=%d hash=%s from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s\n  base: %s root=%s cumGas=%d\n  mir : %s root=%s cumGas=%d",
				i, tx.Hash(), from, to, tx.Nonce(), tx.Gas(), tx.GasPrice(), tx.Value(),
				fmtReceipt(br), baseRun.rootByIndex[i], baseRun.cumGasByIndex[i],
				fmtReceipt(mr), mirRun.rootByIndex[i], mirRun.cumGasByIndex[i],
			)
		}
		if baseRun.rootByIndex[i] != mirRun.rootByIndex[i] {
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
		baseState2 := env.statedb.Copy()
		mirState2 := env.statedb.Copy()
		baseRes, baseErr := env.processor.Process(blk, baseState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: false})
		mirRes, mirErr := env.processor.Process(blk, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
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
				if i < len(blk.Transactions()) && isBSCSystemTx(blk.Transactions()[i]) {
					kind = "system"
				}
				return fmt.Errorf("full block receipt mismatch txIdx=%d kind=%s\n  base: %s root=%s\n  mir : %s root=%s",
					i, kind, fmtReceipt(br), baseState2.IntermediateRoot(cfg.IsEIP158(blk.Number())), fmtReceipt(mr), mirState2.IntermediateRoot(cfg.IsEIP158(blk.Number())))
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
func scanRange(db ethdb.Database, cfg *params.ChainConfig, genesisHash common.Hash, from, to uint64, doFullBlock bool) error {
	if from == 0 {
		// Block 0 is genesis and contains no transactions to compare.
		from = 1
	}
	if to < from {
		return fmt.Errorf("bad range: to (%d) < from (%d)", to, from)
	}
	env, err := newReplayEnv(db, cfg, genesisHash)
	if err != nil {
		return err
	}
	// Advance state once to the pre-state of `from`.
	if from > 1 {
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
		baseRun, err := processCommonTxsOnly(env.chain, cfg, baseState, blk, false)
		if err != nil {
			return fmt.Errorf("block %d base common-tx run failed: %w", n, err)
		}
		mirRun, err := processCommonTxsOnly(env.chain, cfg, mirState, blk, true)
		if err != nil {
			return fmt.Errorf("block %d mir common-tx run failed: %w", n, err)
		}

		signer := types.MakeSigner(cfg, blk.Number(), blk.Time())
		for i, tx := range blk.Transactions() {
			if isBSCSystemTx(tx) {
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
				fmt.Print(debugOneTx(env.chain, cfg, env.statedb, blk, i))
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
			baseRes, baseErr := env.processor.Process(blk, baseState2, baseVmCfg)
			mirRes, mirErr := env.processor.Process(blk, mirState2, vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true})
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
					if i < len(blk.Transactions()) && isBSCSystemTx(blk.Transactions()[i]) {
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
		if err := scanRange(db, cfg, genesisHash, start, end, *full); err != nil {
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
