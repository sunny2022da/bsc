package MIR

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ExecResult is the outcome of executing MIR.
type ExecResult struct {
	HaltOp     MirOperation
	ReturnData []byte
	Err        error
	GasUsed    uint64
	GasLeft    uint64
	RefundUsed uint64 // refund applied at tx end (capped), if gasLimit != 0
	LastEVMPC  uint   // best-effort: last executed EVM pc (for debugging)
	// Debug-only: RETURN/REVERT operands observed at halt (best-effort).
	ReturnOffset uint64
	ReturnSize   uint64
}

// Shared immutable zero value to avoid allocations in hot paths.
var u256Zero = new(uint256.Int)

// ErrMIRInternal marks errors that originate from MIR's incomplete static analysis
// (unresolved Unknown values, missing PHI results, exhausted resolution paths)
// rather than legitimate EVM execution errors. The runner uses this to decide
// whether to fall back to the stock EVM interpreter for the current frame.
var ErrMIRInternal = errors.New("MIR internal failure")

// blockHistoryMax caps the block history ring buffer. Deep enough to find
// live-in defs across typical internal-function call chains, bounded to
// keep memory usage predictable.
const blockHistoryMax = 256

// Common small constants (immutable). These are safe to share because MIRInterpreter never mutates
// the operand values passed into gas/memory helpers.
var (
	u256One = uint256.NewInt(1)
	u256U32 = uint256.NewInt(32)
)

// entryStack mismatch counters: helpful signal for invalid bytecode or CFG/snapshot bugs.
// Throttled to avoid log spam during fullnode sync.
var (
	mirEntryStackMismatchCount atomic.Uint64
	mirEntryStackMismatchTick  atomic.Uint64
)

func maybeLogEntryStackMismatch(it *MIRInterpreter, cur, prev *MIRBasicBlock, entryLen, incomingLen int) {
	// Throttle: log at most once per 1024 mismatches globally.
	const every = uint64(1024)
	n := mirEntryStackMismatchCount.Add(1)
	if (n % every) != 1 {
		return
	}
	// Ensure only one goroutine logs per tick.
	if !mirEntryStackMismatchTick.CompareAndSwap(n-every, n) && n != 1 {
		return
	}
	codeHash := common.Hash{}
	if it != nil && it.cfg != nil {
		codeHash = it.cfg.codeAddr
	}
	curPC, prevPC := uint(0), uint(0)
	curUnr, prevUnr := false, false
	if cur != nil {
		curPC = cur.firstPC
		curUnr = cur.unresolvedJump
	}
	if prev != nil {
		prevPC = prev.firstPC
		prevUnr = prev.unresolvedJump
	}
	log.Warn("MIR entryStack length mismatch (potential CFG/snapshot bug or invalid bytecode)",
		"count", n,
		"codeHash", codeHash.Hex(),
		"cur", fmt.Sprintf("0x%x", curPC),
		"prev", fmt.Sprintf("0x%x", prevPC),
		"entryLen", entryLen,
		"incomingLen", incomingLen,
		"curUnresolvedJump", curUnr,
		"prevUnresolvedJump", prevUnr,
	)
}

// MIRInterpreter executes MIRBasicBlocks produced by CFG.Parse().
// This is a "minimal" interpreter: enough to validate CFG/PHI/control-flow and core arithmetic.
type MIRInterpreter struct {
	cfg *CFG

	// Dense results table keyed by MIR.resIdx (global per-CFG slot index).
	// resultsGen marks which generation a slot belongs to; this avoids per-run clearing.
	results    []uint256.Int
	resultsGen []uint32
	gen        uint32
	nextResIdx int

	// Cached constant gas schedule for the currently active chain rules.
	constGasRules params.Rules
	constGasInit  bool
	constGas      [256]uint64
	constGasKnown [256]bool

	// simple linear memory model
	mem []byte

	validJumpDests map[uint]bool

	// gas metering
	chainRules    params.Rules
	gasLimit      uint64 // 0 means "unlimited" (no OOG)
	gasUsed       uint64
	memLastGasFee uint64 // mirrors vm.Memory.lastGasCost for expansion accounting

	// minimal state for SLOAD/SSTORE gas + semantics
	contractAddr common.Address
	callerAddr   common.Address
	originAddr   common.Address
	callValue    *uint256.Int
	txGasPrice   *big.Int // effective gas price for the current tx (GASPRICE opcode)
	state        StateBackend
	// vmStateDB is a fast-path handle for fullnode execution (when StateBackend is *StateDBBackend).
	// This avoids an extra interface dispatch layer in hot access-list/state paths.
	vmStateDB vm.StateDB

	// readOnly is true when MIR is executing inside a STATICCALL frame.
	// State-modifying opcodes (SSTORE, LOG, CREATE, SELFDESTRUCT, etc.) must
	// return ErrWriteProtection when this is set, matching stock EVM behaviour.
	readOnly bool

	// CALL-like context (needed for CALLDATACOPY/RETURNDATACOPY)
	callData   []byte
	returnData []byte

	callCreate CallCreateBackend

	// tx-level refund application guard
	refundApplied bool
	// applyRefundCapInFinish controls whether MIRInterpreter applies the tx-level
	// refund cap internally on STOP/RETURN/REVERT/SELFDESTRUCT.
	//
	// IMPORTANT: When MIR is used as a vm runner inside geth, the transaction-level
	// refund cap is applied by state_transition, not the interpreter. In that mode,
	// this must be disabled, otherwise MIR will "refund" against the post-intrinsic
	// call gas only (causing gasUsed mismatches).
	applyRefundCapInFinish bool

	// Context for LOGs
	blockNumber uint64
	// Block context for block environment opcodes (NUMBER/TIMESTAMP/COINBASE/etc).
	blockTime        uint64
	blockCoinbase    common.Address
	blockGasLimit    uint64
	blockDifficulty  *big.Int
	blockRandom      *common.Hash
	blockBaseFee     *big.Int
	blockBlobBaseFee *big.Int
	blockGetHash     vm.GetHashFunc

	// Tx context (for Cancun BLOBHASH)
	txBlobHashes []common.Hash

	// Debug: last executed EVM pc (best-effort)
	lastEvmPC uint

	// Optional debug hook (used by tests/tools): called for each executed MIR instruction.
	stepHook func(evmPC uint, evmOp byte, op MirOperation)
	// Optional debug hook for JUMPI condition values. Called for each JUMPI with the evaluated
	// destination, condition, and whether the branch was taken. Used by traceCallTreeBothModes in
	// blockchain.go to compare MIR vs base-EVM JUMPI decisions when a receipt mismatch is detected.
	// The cfg parameter is a live reference to the executing CFG so callers can dump it before
	// runtime eviction (runtimeBecameDynamic) removes it from the global cache.
	jumpiHook func(pc uint, dest uint, cond *uint256.Int, taken bool, cfg *CFG)

	// tracePhi: when true, evalPhi logs every resolution with the chosen path id,
	// cur/prev block PCs, phi stack index, and resolved value. Used to locate the
	// first PHI whose output diverges between MIR and base EVM.
	tracePhi bool

	// Optional debug hook (used by tools): called when resolving a JUMP/JUMPI target PC to a basic block.
	// existed indicates whether the CFG already had a block entry for targetPC.
	resolveHook func(fromFirstPC uint, fromEvmPC uint, targetPC uint, resolvedFirstPC uint, existed bool)

	// Optional debug hook to inspect operands at runtime (used by tools/tests).
	// Values are passed by value to avoid accidental mutation by the caller.
	debugOperandHook func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int)
	// Extended operand hook including operand source (def op/pc if the operand is a Variable).
	debugOperandHookEx func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp MirOperation, bDefOp MirOperation)
	// Debug hook for KECCAK256 input bytes (truncated) to diagnose memory divergence.
	debugKeccakHook func(evmPC uint, off uint64, sz uint64, data []byte)
	// Optional debug hook for PHI resolution. Intended for tools diagnosing control-flow/CFG issues.
	// Receives basic info about the predecessor edge and the resolved value.
	debugPhiHook func(curFirstPC uint, prevFirstPC uint, phiPC uint, phiStackIndex int, incomingLen int, incomingIdx int, val uint256.Int)

	// Optional debug hook for call-like argument inspection (CALL/DELEGATECALL/STATICCALL/CALLCODE).
	// Intended for tools diagnosing memory overflow / bad stack value propagation.
	debugCallArgsHook func(evmPC uint, evmOp byte, op MirOperation, gasReq uint256.Int, to common.Address,
		inOff uint256.Int, inOffDefPC uint, inOffDefOp MirOperation,
		inSz uint256.Int, inSzDefPC uint, inSzDefOp MirOperation,
		outOff uint256.Int, outOffDefPC uint, outOffDefOp MirOperation,
		outSz uint256.Int, outSzDefPC uint, outSzDefOp MirOperation,
		inOffOv bool, inSzOv bool, outOffOv bool, outSzOv bool)

	// NOTE: Do not add "duplicate log" guards here. Emitting identical logs multiple times
	// is perfectly legal EVM behavior (e.g. loops), and strict MIR must preserve it.

	// Execution cursor (for GAS/call-gas semantics when constant gas is precharged at block entry).
	curBlock *MIRBasicBlock
	curEvmPC uint
	curEvmOp byte

	// blockHistory tracks the sequence of basic blocks executed in this frame.
	// Used by evalPhi's Unknown-resolution fallback: when a PHI operand traces
	// to a live-in that MIR couldn't resolve at Parse time, walk back through
	// the history to find the actual runtime value in an earlier block's
	// result table. Ring buffer capped at blockHistoryMax to bound memory.
	blockHistory    []*MIRBasicBlock
	blockHistoryPos int // next write index (ring buffer)

	// Cached per-block prefix sums of constant gas for original EVM opcode stream.
	// Indexed by basic block number; each entry is len(block.evmOps)+1 where prefix[i] is sum of 0..i-1.
	//
	// This enables O(1) constant-gas charging per executed MIR op (including optimized-away PUSH/DUP/SWAP),
	// without the incorrect semantics of "charge the whole block upfront" (which breaks CALL gas forwarding).
	blockConstPrefix [][]uint64
	// Cached prefix table for the currently executing block (avoid per-op lookups).
	curBlockConstPrefix []uint64
	// Cached per-block constant deltas for the currently executing block.
	curBlockConstDelta []uint64
	curBlockConstTail  uint64

	// Cached per-block constant gas deltas per MIR instruction for the current ruleset.
	// delta[i] is the constant gas to charge when executing MIR instruction with idx=i.
	// This removes most work from the hot chargeConstGasForMIR path.
	blockConstDelta [][]uint64
	// Cached per-block "tail" constant gas to charge at block end (for blocks that fall through without a terminator MIR).
	blockConstTail []uint64

	// Per-block execution cursor into evmOps for constant-gas charging.
	curEvmOpIndex int

	// manageStateSnapshots controls whether MIRInterpreter snapshots/reverts state internally.
	// When MIR runs as a vm runner inside geth, the outer EVM already snapshots/reverts around
	// contract execution, so doing it again here is redundant and expensive.
	manageStateSnapshots bool
}

// ContractAddress returns the current contract address being executed by this interpreter.
// This is intended for diagnostics/tools.
func (it *MIRInterpreter) ContractAddress() common.Address {
	if it == nil {
		return common.Address{}
	}
	return it.contractAddr
}

// DebugDumpEvmPCRange returns a MIR dump for the interpreter's current CFG for [start,end].
// Intended for debugging/tools only.
func (it *MIRInterpreter) DebugDumpEvmPCRange(start, end uint) string {
	if it == nil {
		return "<nil interpreter>\n"
	}
	return DebugDumpMIRForEvmPCRange(it.cfg, start, end)
}

// DebugDumpCodeHexRange dumps raw EVM bytecode bytes for [start,end] (inclusive start, exclusive end).
// Intended for debugging/tools only.
func (it *MIRInterpreter) DebugDumpCodeHexRange(start, end uint) string {
	if it == nil || it.cfg == nil {
		return "<nil interpreter/cfg>\n"
	}
	code := it.cfg.rawCode
	if code == nil {
		return "<nil code>\n"
	}
	if start > uint(len(code)) {
		start = uint(len(code))
	}
	if end > uint(len(code)) {
		end = uint(len(code))
	}
	if end < start {
		end = start
	}
	if start == end {
		return fmt.Sprintf("code[%d:%d]=<empty>\n", start, end)
	}
	// Print a compact single-line dump to keep replay output manageable.
	return fmt.Sprintf("code[%d:%d]=%x\n", start, end, code[start:end])
}

// DebugDumpIncomingStacksForPC dumps the recorded incoming stack snapshots for the basic block at `pc`.
// This is intended for debugging tools only.
func (it *MIRInterpreter) DebugDumpIncomingStacksForPC(pc uint, topK int) string {
	if it == nil || it.cfg == nil {
		return "<nil interpreter/cfg>\n"
	}
	b := it.cfg.pcToBlock[pc]
	if b == nil {
		return fmt.Sprintf("no block at pc=%d\n", pc)
	}
	if topK <= 0 {
		topK = 8
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Incoming stacks for block pc=0x%x parents=%d unresolvedJump=%v entryGen=%d\n",
		b.firstPC, len(b.parents), b.unresolvedJump, b.EntryStackGen()))
	if es := b.EntryStack(); es != nil {
		sb.WriteString(fmt.Sprintf("  entryStackLen=%d\n", len(es)))
	} else {
		sb.WriteString("  entryStackLen=<nil>\n")
	}
	if xs := b.ExitStack(); xs != nil {
		sb.WriteString(fmt.Sprintf("  exitStackLen=%d\n", len(xs)))
	} else {
		sb.WriteString("  exitStackLen=<nil>\n")
	}
	if b.incomingStacks == nil || len(b.incomingStacks) == 0 {
		sb.WriteString("  <no incomingStacks>\n")
		return sb.String()
	}
	for _, p := range b.parents {
		if p == nil {
			continue
		}
		s := b.incomingStacks[p]
		g := uint64(0)
		if b.incomingStacksGen != nil {
			g = b.incomingStacksGen[p]
		}
		sb.WriteString(fmt.Sprintf("  from=0x%x gen=%d len=%d | top%d: ", p.firstPC, g, len(s), topK))
		if len(s) == 0 {
			sb.WriteString("<empty>\n")
			continue
		}
		start := len(s) - topK
		if start < 0 {
			start = 0
		}
		for i := len(s) - 1; i >= start; i-- {
			v := s[i]
			u, err := it.evalValue(&v)
			if err == nil && u != nil {
				sb.WriteString("0x")
				sb.WriteString(u.Hex())
			} else {
				switch v.kind {
				case Konst:
					if v.u != nil {
						sb.WriteString("K(" + v.u.Hex() + ")")
					} else {
						sb.WriteString("K(?)")
					}
				case Variable:
					if v.def != nil {
						sb.WriteString(fmt.Sprintf("V(defPC=%d defOp=%s)", v.def.evmPC, v.def.op.String()))
					} else {
						sb.WriteString("V(<nil def>)")
					}
				default:
					sb.WriteString(fmt.Sprintf("kind=%d", int(v.kind)))
				}
			}
			if i != start {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// DebugDumpEntryExitStacksForPC dumps the cached entry/exit stacks (static shape) for the block at `pc`.
// This is intended for debugging tools only.
func (it *MIRInterpreter) DebugDumpEntryExitStacksForPC(pc uint, topK int) string {
	if it == nil || it.cfg == nil {
		return "<nil interpreter/cfg>\n"
	}
	b := it.cfg.pcToBlock[pc]
	if b == nil {
		return fmt.Sprintf("no block at pc=%d\n", pc)
	}
	if topK <= 0 {
		topK = 8
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Entry/Exit stacks for block pc=0x%x unresolvedJump=%v entryGen=%d\n", b.firstPC, b.unresolvedJump, b.EntryStackGen()))
	dump := func(name string, s []Value) {
		if s == nil {
			sb.WriteString(fmt.Sprintf("  %s: <nil>\n", name))
			return
		}
		sb.WriteString(fmt.Sprintf("  %s len=%d top%d: ", name, len(s), topK))
		start := len(s) - topK
		if start < 0 {
			start = 0
		}
		for i := len(s) - 1; i >= start; i-- {
			v := s[i]
			if v.kind == Konst && v.u != nil {
				sb.WriteString("0x" + v.u.Hex())
			} else if v.kind == Konst {
				u := uint256.NewInt(0).SetBytes(v.payload)
				sb.WriteString("0x" + u.Hex())
			} else if v.kind == Variable && v.def != nil {
				sb.WriteString(fmt.Sprintf("V(defPC=%d defOp=%s)", v.def.evmPC, v.def.op.String()))
			} else {
				sb.WriteString(fmt.Sprintf("kind=%d", int(v.kind)))
			}
			if i != start {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("\n")
	}
	dump("entryStack", b.EntryStack())
	dump("exitStack", b.ExitStack())
	return sb.String()
}

func snapshotHasDefsFromBlock(snap []Value, blockNum uint) bool {
	for i := range snap {
		v := &snap[i]
		if v == nil || v.kind != Variable || v.def == nil {
			continue
		}
		if v.def.defBlockNum == blockNum {
			return true
		}
	}
	return false
}

func NewMIRInterpreter(cfg *CFG) *MIRInterpreter {
	it := &MIRInterpreter{
		cfg:            cfg,
		results:        make([]uint256.Int, 0, 4096),
		resultsGen:     make([]uint32, 0, 4096),
		gen:            1,
		nextResIdx:     1,
		mem:            nil,
		validJumpDests: nil,
		// Default to "Frontier-like" rules (all false). A real fullnode MUST set rules
		// per block using SetChainRules or SetChainConfig before execution to get gas parity.
		chainRules:    params.Rules{},
		constGasRules: params.Rules{},
		constGasInit:  false,
		gasLimit:      0,
		gasUsed:       0,
		memLastGasFee: 0,
		contractAddr:  common.Address{},
		callerAddr:    common.Address{},
		originAddr:    common.Address{},
		callValue:     u256Zero,
		state:         NewInMemoryState(),
		callData:      nil,
		returnData:    nil,
		callCreate:    NoopCallCreateBackend{},
		refundApplied: false,
		// Default to true for standalone/tests. Fullnode runner disables this.
		applyRefundCapInFinish: true,
		// Default to true for standalone/tests. Fullnode runner disables this because
		// EVM.Call/Create already snapshot/revert around execution.
		manageStateSnapshots: true,
		lastEvmPC:            0,
		stepHook:             nil,
		blockNumber:          0,
		blockTime:            0,
		blockCoinbase:        common.Address{},
		blockGasLimit:        0,
		blockDifficulty:      nil,
		blockRandom:          nil,
		blockBaseFee:         nil,
		blockBlobBaseFee:     nil,
		blockGetHash:         nil,
		txBlobHashes:         nil,
	}
	if cfg != nil {
		it.validJumpDests = cfg.JumpDests()
		if cfg.nextResIdx > it.nextResIdx {
			it.nextResIdx = cfg.nextResIdx
		}
		it.ensureResultsCapacity(it.nextResIdx)
	}
	it.rebuildConstGasTable()
	return it
}

// SetManageStateSnapshots controls whether MIRInterpreter performs StateBackend Snapshot/Revert internally.
// For geth integration (EVMRunner), set this to false because EVM.Call/Create already wraps execution
// in a StateDB snapshot.
func (it *MIRInterpreter) SetManageStateSnapshots(enabled bool) {
	if it == nil {
		return
	}
	it.manageStateSnapshots = enabled
}

// SetApplyRefundCapInFinish controls whether MIRInterpreter applies the tx-level refund cap
// internally at halt. Fullnode mode should set this to false.
func (it *MIRInterpreter) SetApplyRefundCapInFinish(enabled bool) {
	if it == nil {
		return
	}
	it.applyRefundCapInFinish = enabled
}

func (it *MIRInterpreter) rebuildConstGasTable() {
	if it == nil {
		return
	}
	for i := 0; i < 256; i++ {
		c, ok := vm.ConstantGasForOp(it.chainRules, vm.OpCode(byte(i)))
		it.constGasKnown[i] = ok
		it.constGas[i] = c
	}
	it.constGasRules = it.chainRules
	it.constGasInit = true
}

func (it *MIRInterpreter) ensureResultsCapacity(n int) {
	// We want to index directly by resIdx; keep len >= n+1 so slot n is valid.
	if it == nil || n <= 0 {
		return
	}
	want := n + 1
	if len(it.results) < want {
		old := len(it.results)
		it.results = append(it.results, make([]uint256.Int, want-old)...)
	}
	if len(it.resultsGen) < want {
		old := len(it.resultsGen)
		it.resultsGen = append(it.resultsGen, make([]uint32, want-old)...)
	}
}

// ResetForRun clears per-execution state while keeping long-lived allocations (maps/slices)
// so the interpreter can be safely reused (e.g. via sync.Pool) for performance.
func (it *MIRInterpreter) ResetForRun(cfg *CFG) {
	if it == nil {
		return
	}
	// Advance generation to invalidate previous results without clearing maps/slices.
	it.gen++
	if it.gen == 0 {
		// Extremely rare wrap-around: clear generation table.
		for i := range it.resultsGen {
			it.resultsGen[i] = 0
		}
		it.gen = 1
	}

	prevCfg := it.cfg
	it.cfg = cfg
	if cfg != nil {
		it.validJumpDests = cfg.JumpDests()
		if cfg.nextResIdx > it.nextResIdx {
			it.nextResIdx = cfg.nextResIdx
		}
		it.ensureResultsCapacity(it.nextResIdx)
	} else {
		it.validJumpDests = nil
	}
	// If CFG changes (different contract), cached per-block gas tables are invalid.
	if prevCfg != cfg {
		it.blockConstPrefix = nil
		it.blockConstDelta = nil
		it.blockConstTail = nil
	}
	// Reset memory but keep capacity
	if it.mem != nil {
		it.mem = it.mem[:0]
	}
	it.gasUsed = 0
	it.memLastGasFee = 0
	it.returnData = nil
	it.callData = nil
	it.readOnly = false
	it.refundApplied = false
	it.lastEvmPC = 0
	it.curBlock = nil
	it.curEvmPC = 0
	it.curEvmOp = 0
	it.curBlockConstPrefix = nil
	it.curBlockConstDelta = nil
	it.curBlockConstTail = 0
	// Reset block history ring buffer (keep capacity).
	if it.blockHistory != nil {
		it.blockHistory = it.blockHistory[:0]
	}
	it.blockHistoryPos = 0
	it.jumpiHook = nil
	it.debugOperandHook = nil
	it.debugOperandHookEx = nil
	it.debugKeccakHook = nil
	it.debugPhiHook = nil
	// (no log de-dup guards)
}

func (it *MIRInterpreter) SetStepHook(h func(evmPC uint, evmOp byte, op MirOperation)) {
	it.stepHook = h
}

// recordBlockEntry pushes a block into the history ring buffer. Used by
// evalPhi's Unknown-resolution fallback to walk back through the execution
// chain and find the actual runtime value for a live-in that MIR's static
// analysis couldn't trace at Parse time.
func (it *MIRInterpreter) recordBlockEntry(b *MIRBasicBlock) {
	if b == nil {
		return
	}
	if len(it.blockHistory) < blockHistoryMax {
		it.blockHistory = append(it.blockHistory, b)
		return
	}
	// Ring buffer full: overwrite oldest.
	it.blockHistory[it.blockHistoryPos] = b
	it.blockHistoryPos++
	if it.blockHistoryPos >= blockHistoryMax {
		it.blockHistoryPos = 0
	}
}

// SetResolveHook installs an optional hook invoked during JUMP/JUMPI resolution.
func (it *MIRInterpreter) SetResolveHook(h func(fromFirstPC uint, fromEvmPC uint, targetPC uint, resolvedFirstPC uint, existed bool)) {
	it.resolveHook = h
}

// SetJumpiHook sets a hook called for each JUMPI execution with (pc, dest, cond, taken, cfg).
// Used by traceCallTreeBothModes to compare MIR vs base-EVM JUMPI decisions and to dump the
// live CFG (which may later be evicted via runtimeBecameDynamic).
func (it *MIRInterpreter) SetJumpiHook(h func(pc uint, dest uint, cond *uint256.Int, taken bool, cfg *CFG)) {
	it.jumpiHook = h
}

// SetTracePhi enables or disables PHI resolution tracing. When enabled, evalPhi
// logs every resolution with the chosen path id. Used for diagnostic replays only.
func (it *MIRInterpreter) SetTracePhi(on bool) {
	it.tracePhi = on
}

// SetDebugOperandHook registers a hook that receives selected opcode operands during execution.
// Intended for diagnostics only.
func (it *MIRInterpreter) SetDebugOperandHook(h func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int)) {
	it.debugOperandHook = h
}

func (it *MIRInterpreter) SetDebugOperandHookEx(h func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp MirOperation, bDefOp MirOperation)) {
	it.debugOperandHookEx = h
}

func (it *MIRInterpreter) SetDebugKeccakHook(h func(evmPC uint, off uint64, sz uint64, data []byte)) {
	it.debugKeccakHook = h
}

func (it *MIRInterpreter) SetDebugPhiHook(h func(curFirstPC uint, prevFirstPC uint, phiPC uint, phiStackIndex int, incomingLen int, incomingIdx int, val uint256.Int)) {
	it.debugPhiHook = h
}

func (it *MIRInterpreter) SetDebugCallArgsHook(h func(evmPC uint, evmOp byte, op MirOperation, gasReq uint256.Int, to common.Address,
	inOff uint256.Int, inOffDefPC uint, inOffDefOp MirOperation,
	inSz uint256.Int, inSzDefPC uint, inSzDefOp MirOperation,
	outOff uint256.Int, outOffDefPC uint, outOffDefOp MirOperation,
	outSz uint256.Int, outSzDefPC uint, outSzDefOp MirOperation,
	inOffOv bool, inSzOv bool, outOffOv bool, outSzOv bool)) {
	it.debugCallArgsHook = h
}

// CurrentBlockFirstPC returns the current basic block start pc (best-effort; 0 if unknown).
// This is intended for debugging/tracing tools.
func (it *MIRInterpreter) CurrentBlockFirstPC() uint {
	if it == nil || it.curBlock == nil {
		return 0
	}
	return it.curBlock.FirstPC()
}

// CurrentBlock returns the currently executing basic block (best-effort; nil if unknown).
// Intended for debugging/tracing tools.
func (it *MIRInterpreter) CurrentBlock() *MIRBasicBlock {
	if it == nil {
		return nil
	}
	return it.curBlock
}

func (it *MIRInterpreter) setResult(def *MIR, v *uint256.Int) {
	if it == nil || def == nil {
		return
	}
	dst := it.resultSlot(def)
	if v == nil {
		dst.Clear()
		return
	}
	dst.Set(v)
}

func (it *MIRInterpreter) getResult(def *MIR) (*uint256.Int, bool) {
	if it == nil || def == nil {
		return nil, false
	}
	idx := def.resIdx
	if idx <= 0 {
		idx = it.ensureResIdx(def)
	}
	if idx <= 0 || idx >= len(it.resultsGen) {
		return nil, false
	}
	if it.resultsGen[idx] != it.gen {
		return nil, false
	}
	return &it.results[idx], true
}

func (it *MIRInterpreter) invalidateBlockResults(b *MIRBasicBlock) {
	if it == nil || b == nil {
		return
	}
	if mirDebugBlock != 0 && it.blockNumber == mirDebugBlock {
		log.Warn("MIR invalidateBlockResults called",
			"block", it.blockNumber,
			"firstPC", b.FirstPC(),
			"numInstr", len(b.instructions),
		)
	}
	for _, m := range b.instructions {
		if m == nil {
			continue
		}
		// Do not invalidate PHI results: they can be legally used as loop-carried live-ins across
		// rebuilds, and clearing them can produce spurious "missing result for def MirPHI" in
		// dynamic CFG regions where blocks are invalidated/rebuilt between iterations.
		if m.op == MirPHI {
			continue
		}
		if m.resIdx > 0 && m.resIdx < len(it.resultsGen) {
			it.resultsGen[m.resIdx] = 0
		}
	}
}

func (it *MIRInterpreter) ensureResIdx(def *MIR) int {
	if it == nil || def == nil {
		return 0
	}
	if def.resIdx > 0 {
		return def.resIdx
	}
	// Support tests that construct MIR manually (without CFG appendMIR allocating resIdx).
	def.resIdx = it.nextResIdx
	it.nextResIdx++
	it.ensureResultsCapacity(it.nextResIdx)
	return def.resIdx
}

func (it *MIRInterpreter) resultSlot(def *MIR) *uint256.Int {
	if it == nil || def == nil {
		return u256Zero
	}
	// Hot path: CFG-built MIR always has a valid resIdx and ResetForRun pre-sized results tables.
	if idx := def.resIdx; idx > 0 && idx < len(it.resultsGen) {
		it.resultsGen[idx] = it.gen
		return &it.results[idx]
	}
	// Slow path: tests or defensive growth.
	idx := it.ensureResIdx(def)
	if idx <= 0 {
		return u256Zero
	}
	it.ensureResultsCapacity(idx)
	it.resultsGen[idx] = it.gen
	return &it.results[idx]
}

// tagIncomingEpoch marks (from -> to) as observed in the current runtimeEpoch.
// This is crucial for cached CFG execution: entry-stack rebuild logic prefers current-epoch
// incoming stacks, and some contracts legitimately have different stack heights per predecessor.
// Without this tagging on *static* edges, the epoch filter can drop the actually-taken edge and
// the block can rebuild using the wrong predecessor's stack height/values (leading to
// "missing result for def" and control-flow divergence).
func (it *MIRInterpreter) tagIncomingEpoch(from, to *MIRBasicBlock) {
	if it == nil || it.cfg == nil || it.cfg.runtimeEpoch == 0 || from == nil || to == nil {
		return
	}
	if to.incomingStacks == nil {
		return
	}
	s, ok := to.incomingStacks[from]
	if !ok {
		return
	}
	if to.incomingStacksGen == nil {
		to.incomingStacksGen = make(map[*MIRBasicBlock]uint64, 8)
	}
	to.incomingStacksGen[from] = it.cfg.runtimeEpoch
	to.preferredEntryHeight = len(s)
}

// refreshEdgeIfNeeded refreshes the incoming stack snapshot for the from→to edge when the
// snapshot is stale or missing, so that PHI resolution has a concrete predecessor shape.
// It must be called with from being the currently executing block.
//
// This is the extracted common logic shared by MirJUMP and MirJUMPI fast paths.  The
// slow path (resolveBB) calls connectEdge directly, which also updates jumpTable.
func (it *MIRInterpreter) refreshEdgeIfNeeded(prev, from, to *MIRBasicBlock) {
	if it.cfg == nil {
		return
	}
	// Genuine loop back-edges: materialize the predecessor's exit stack into concrete
	// constants (using the current-iteration result cache) and update the loop header's
	// incoming snapshot. This is critical for "shift register" style loops where MIR's
	// static PHI operands reference outer-block PHIs with iteration-invariant values;
	// without refresh, evalPhi returns the same value every iteration. Materialization
	// captures the actual body-computed values at the moment the back-edge is traversed.
	//
	// connectEdge has an existing guard (see opcodeParser.go) that skips the usual
	// entry-stack invalidation for existing back-edges, so this refresh is safe:
	// it updates incomingStacks without triggering rebuild / invalidateBlockResults.
	it.cfg.EnsureLoopInfo()
	if to.IsLoopHeader && to.IsBackEdgeFrom(from) && to.entryStack != nil && to.built {
		snap := it.computeExitSnapshotForEdge(prev, from)
		if snap != nil {
			snap = it.materializeSnapshot(snap)
			it.cfg.connectEdge(from, to, snap)
		}
		return
	}
	isBackEdge := to.IsLoopHeader && to.IsBackEdgeFrom(from)
	if !(it.cfg.runtimeBecameDynamic || from.unresolvedJump || to.unresolvedJump ||
		isBackEdge || to.entryStack == nil) {
		return
	}
	need := true
	var oldSnap []Value
	hadOld := false
	if to.incomingStacks != nil {
		if s, ok := to.incomingStacks[from]; ok {
			oldSnap, hadOld = s, true
			if to.entryStack != nil {
				need = false
			}
		}
	}
	// In runtime-discovered dynamic CFGs the same edge can be traversed with different
	// calldata-dependent values.  Keep (a small top-K) incoming snapshot fresh so
	// stack-sensitive control-flow (jump tables) is compiled correctly.
	var snap []Value
	if it.cfg.runtimeEpoch != 0 && it.cfg.runtimeBecameDynamic {
		snap = it.computeExitSnapshotForEdgeTo(prev, from, to)
		// Back-edges and loop-exit edges must NOT be materialized:
		// - Back-edges: values change every iteration (stale PHI operands on re-entry)
		// - Loop-exit edges: values are iteration-dependent (e.g. SLOAD results);
		//   materializing them poisons the cached CFG for future calls with different state.
		if !from.IsInLoop && !isBackEdge {
			snap = it.materializeSnapshotTopK(snap, 16)
		}
		if hadOld && stacksEqual(oldSnap, snap) {
			need = false
		} else {
			need = true
		}
	}
	if !need && it.cfg.runtimeEpoch != 0 {
		// Keep incomingStacksGen aligned with the current epoch even when the snapshot
		// itself hasn't changed; entry-stack rebuild logic uses this to prefer current
		// run inputs and avoid stack-height underflows for SWAP/DUP-heavy blocks.
		if to.incomingStacksGen == nil {
			to.incomingStacksGen = make(map[*MIRBasicBlock]uint64, 8)
		}
		to.incomingStacksGen[from] = it.cfg.runtimeEpoch
		return
	}
	if need {
		if snap == nil {
			snap = it.computeExitSnapshotForEdgeTo(prev, from, to)
		}
		// connectEdge also updates from.jumpTable[to.firstPC], keeping the table in sync.
		it.cfg.connectEdge(from, to, snap)
	}
}

// SetGasLimit enables out-of-gas checking. If limit==0, gas is tracked but never errors.
func (it *MIRInterpreter) SetGasLimit(limit uint64) {
	it.gasLimit = limit
}

// GasLimit returns the current gas limit for this execution frame (0 means "unlimited").
func (it *MIRInterpreter) GasLimit() uint64 {
	if it == nil {
		return 0
	}
	return it.gasLimit
}

// GasUsed returns the amount of gas consumed so far in the current frame.
func (it *MIRInterpreter) GasUsed() uint64 {
	if it == nil {
		return 0
	}
	return it.gasUsed
}

// SetChainRules controls fork-dependent constant gas schedule. Defaults to Cancun.
func (it *MIRInterpreter) SetChainRules(r params.Rules) {
	if it.chainRules == r {
		return
	}
	it.chainRules = r
	it.rebuildConstGasTable()
}

// SetChainConfig derives and sets fork rules for a specific block context.
// Fullnode integration should call this per block (rules are fork-dependent).
func (it *MIRInterpreter) SetChainConfig(cfg *params.ChainConfig, blockNumber uint64, isMerge bool, timestamp uint64) {
	it.blockNumber = blockNumber
	if cfg == nil {
		it.SetChainRules(params.Rules{})
		return
	}
	it.SetChainRules(cfg.Rules(new(big.Int).SetUint64(blockNumber), isMerge, timestamp))
}

func (it *MIRInterpreter) SetContractAddress(addr common.Address) {
	it.contractAddr = addr
}

func (it *MIRInterpreter) SetCallerAddress(addr common.Address) {
	it.callerAddr = addr
}

func (it *MIRInterpreter) SetOriginAddress(addr common.Address) {
	it.originAddr = addr
}

func (it *MIRInterpreter) SetCallValue(v *uint256.Int) {
	if v == nil {
		it.callValue = u256Zero
		return
	}
	// Treat as immutable for the duration of the call.
	it.callValue = v
}

func (it *MIRInterpreter) SetTxGasPrice(p *big.Int) {
	it.txGasPrice = p
}

func (it *MIRInterpreter) SetStateBackend(s StateBackend) {
	it.state = s
	// Fast-path: if we are backed by a geth StateDB adapter, keep the underlying vm.StateDB.
	if sb, ok := s.(*StateDBBackend); ok && sb != nil {
		it.vmStateDB = sb.db
	} else {
		it.vmStateDB = nil
	}
}

func (it *MIRInterpreter) SetCallCreateBackend(b CallCreateBackend) {
	if b == nil {
		it.callCreate = NoopCallCreateBackend{}
		return
	}
	it.callCreate = b
}

func (it *MIRInterpreter) SetCallData(data []byte) {
	if data == nil {
		it.callData = nil
		return
	}
	// NOTE: this is treated as read-only. Avoid copying for performance.
	it.callData = data
}

// Run executes from the standard EVM entrypoint PC=0.
func (it *MIRInterpreter) Run() ExecResult {
	return it.RunFrom(0)
}

// RunFrom executes starting at an explicit PC. Useful for debugging/resume.
func (it *MIRInterpreter) RunFrom(entryPC uint) ExecResult {
	if it.cfg == nil {
		return ExecResult{Err: errors.New("nil CFG")}
	}
	// Snapshot state so we can revert on REVERT or any fatal error, matching geth semantics.
	// NOTE: This snapshot includes refund counter/access list/logs via StateDB journaling.
	snap := -1
	if it.manageStateSnapshots && it.state != nil {
		snap = it.state.Snapshot()
	}
	cur := it.cfg.pcToBlock[entryPC]
	if cur == nil {
		return ExecResult{Err: fmt.Errorf("no block at pc %d", entryPC)}
	}

	var prev *MIRBasicBlock
	for {
		// Record this block in the execution history for Unknown-resolution fallback.
		it.recordBlockEntry(cur)
		// Ensure loop analysis is current before any IsLoopHeader/IsInLoop checks.
		// Runtime edge additions (connectEdge) invalidate loopInfoValid; without this
		// call, stale IsLoopHeader=false can cause loop headers to be incorrectly
		// invalidated, destroying loop-carried PHI results.
		if it.cfg != nil {
			it.cfg.EnsureLoopInfo()
		}
		// Cached-CFG correctness: if runtime has recorded any current-epoch incoming snapshots for
		// this block, do not keep using a parse-time (gen=0) entry stack. Parse-time entry stacks
		// can be over-specialized (or built from a different predecessor-height heuristic) and may
		// embed def references that are not valid on the actually-taken edge, leading to
		// "missing result for def" later.
		if it.cfg != nil && it.cfg.runtimeEpoch != 0 && cur != nil && cur.EntryStackGen() == 0 && cur.incomingStacksGen != nil && cur.EntryStack() != nil && !cur.IsLoopHeader {
			// Skip loop headers entirely: their parse-time entry stack already has
			// forced PHIs for all stack positions (commit 7dff24e50). Rebuilding would
			// create new MIR instructions with new resIdx values, but the back-edge PHI
			// operands still point to old defs → "missing result" on loop iterations.
			for _, p := range cur.parents {
				if p == nil || cur.IsBackEdgeFrom(p) {
					continue
				}
				if g, ok := cur.incomingStacksGen[p]; ok && g == it.cfg.runtimeEpoch {
					// Force rebuild from current-epoch incomings.
					cur.SetEntryStack(nil)
					if len(cur.instructions) > 0 {
						it.invalidateBlockResults(cur)
						cur.ResetForRebuild(false)
					}
					cur.built = false
					break
				}
			}
		}
		// Reset the per-interpreter block instruction cursor.
		// NOTE: we use a local variable (blockPos) instead of the block's shared `pos` field
		// to avoid re-entrant corruption: when contract A (MIR) calls contract A again (MIR),
		// the inner execution walks the same basic block and advances the shared `pos` field,
		// causing the outer execution to skip remaining instructions.
		blockPos := 0
		// Dynamic repair / runtime snapshot seeding.
		// Needed not only for unresolved-jump CFGs, but also for CFGs that have merge points
		// with differing incoming stack heights (requires runtime-epoch tagging).
		if it.cfg != nil && it.cfg.needsRuntimeEpoch() {
			// Skip runtime snapshot refresh for back-edges and loop headers.
			// Loop headers have forced parse-time PHIs that are correct; any rebuild
			// via connectEdge creates new MIR objects with new resIdx, breaking
			// back-edge PHI operands that still reference old defs.
			isBackEdgeEntry := prev != nil && cur != nil && cur.IsLoopHeader && cur.IsBackEdgeFrom(prev)
			// Also skip blocks pending rebuild from parse-time (built=false).
			// These blocks have symbolic parse-time incomingStacks that correctly
			// differentiate multiple paths. Refreshing here materializes runtime
			// values into constants, which can make different symbolic paths look
			// identical → no PHIs created → stale def references leak through.
			isPendingRebuild := cur != nil && !cur.built
			if prev != nil && cur != nil && cur.incomingStacks != nil && !isBackEdgeEntry && !cur.IsLoopHeader && !isPendingRebuild {
				if in, ok := cur.incomingStacks[prev]; ok && in != nil {
					// Dynamic CFG correctness: even if stack *heights* match, stack *values* feeding into
					// dispatcher blocks (SWAP/POP-heavy jump tables) can be calldata-/path-dependent.
					//
					// MIR does not execute EVM stack ops at runtime; it relies on the CFG builder's entry
					// stack snapshot. If we reuse a stale incoming snapshot from an earlier execution,
					// the builder can bake in wrong constants (e.g. wrong JUMP destination) and diverge.
					//
					// To prevent this, refresh the (prev->cur) incoming snapshot from the predecessor's
					// *runtime* values when this CFG requires runtime-epoch tagging.
					//
					// IMPORTANT: this is needed even for CFGs without unresolved jumps. Some contracts have
					// valid control flow that can reach the same JUMPDEST with different stack heights;
					// in those cases, relying on parse-time snapshots can bake in stale/path-dependent
					// constants and flip branch conditions.
					// Only do the expensive runtime snapshot refresh when we have evidence that
					// parse-time snapshots/entry stacks might be stale for this edge.
					//
					// This keeps hot-path perf for common/static contracts while still repairing
					// tricky merge/loop cases (e.g. entryStack invalidation / preferredEntryHeight).
					if it.cfg != nil && it.cfg.runtimeEpoch != 0 &&
						(it.cfg.runtimeBecameDynamic || prev.unresolvedJump || cur.unresolvedJump || cur.preferredEntryHeight != 0 || cur.EntryStack() == nil) {
						// Refresh using the per-edge exit snapshot (not prev.ExitStack), otherwise we can
						// materialize the wrong permutation/values when duplicate constants or PHIs exist.
						ex := it.computeExitSnapshotForEdgeTo(nil, prev, cur)
						if ex != nil {
							var fresh []Value
							// Back-edges (loop jumps where the target block appears earlier in the
							// bytecode than the source) must NOT be materialized: their values change
							// every iteration, so baking the current iteration's value as a Konst would
							// produce stale constants when the outer loop re-enters the same block.
							// Note: resolveBB already guards against this via its own firstPC check;
							// this guard covers the block-entry refresh path which had no such check.
							isBackEdge := cur.IsLoopHeader && cur.IsBackEdgeFrom(prev)
							if isBackEdge || prev.IsInLoop {
								// Back-edges and loop-exit edges must stay symbolic:
								// materializing iteration-dependent values (SLOAD etc.)
								// poisons the cached CFG for future calls.
								fresh = ex
							} else {
								k := 64
								if len(ex) < k {
									k = len(ex)
								}
								fresh = it.materializeSnapshotTopK(ex, k)
							}
							// Avoid unnecessary edge updates: only connect if the snapshot is stale for this epoch
							// or the values differ.
							staleEpoch := false
							if cur.incomingStacksGen != nil {
								if g, okg := cur.incomingStacksGen[prev]; !okg || g != it.cfg.runtimeEpoch {
									staleEpoch = true
								}
							}
							if staleEpoch || !stacksEqual(in, fresh) {
								it.cfg.connectEdge(prev, cur, fresh)
								if in2, ok2 := cur.incomingStacks[prev]; ok2 && in2 != nil {
									in = in2
								}
							}
						}
						// If this is a dynamic/unresolved block and the cached entry stack no longer matches
						// the concrete incoming snapshot (even at the same height), rebuild the block so we
						// don't bake stale/path-dependent constants into downstream stack-op-heavy regions.
						if cur != nil && cur.unresolvedJump {
							es2 := cur.EntryStack()
							if es2 != nil && len(es2) == len(in) && !stacksEqual(es2, in) {
								cur.preferredEntryHeight = len(in)
								cur.SetEntryStack(nil)
								if len(cur.instructions) > 0 {
									it.invalidateBlockResults(cur)
									cur.ResetForRebuild(false)
								}
								cur.built = false
							}
						}
					}
					// Ignore stale runtime snapshots from previous executions when CFG is cached.
					if it.cfg != nil && it.cfg.runtimeEpoch != 0 && cur.incomingStacksGen != nil {
						if g, okg := cur.incomingStacksGen[prev]; okg && g != 0 && g != it.cfg.runtimeEpoch {
							in = nil
						}
					}
					if in == nil {
						goto skipSeed
					}
					es := cur.EntryStack()
					// Discard runtime-specialized entry stacks from previous executions.
					// They can leak path-dependent shape/value assumptions across different calldata
					// and cause consensus divergence.
					if es != nil && it.cfg != nil {
						if g := cur.EntryStackGen(); g != 0 && g != it.cfg.runtimeEpoch {
							cur.SetEntryStack(nil)
							es = nil
						}
					}
					// If the block's entry stack height differs from the concrete incoming snapshot height
					// for this predecessor edge, we must rebuild with the correct shape.
					//
					// IMPORTANT:
					// - entryStack==nil is often used as an invalidation marker when CFG edges/snapshots change.
					//   In that common case, if all incoming stacks have the same height, we want
					//   buildBasicBlock -> getEntryStackForBlock to recompute from *all* incomings and
					//   (re)introduce PHIs as needed (instead of specializing to a single predecessor).
					// - however, when incoming stack *heights vary* (dynamic CFG backfill / invalid bytecode),
					//   we must specialize the entry stack to this predecessor edge, otherwise the mode-height
					//   filter may discard the current edge and we won't rebuild to the needed shape.
					needSeed := false
					if es != nil {
						// If the CFG became dynamic at runtime (new blocks discovered / jump-table backfill),
						// a parse-time (gen=0) entry stack can be overly specialized (baked constants) and cause
						// wrong control flow even when stack heights match. In that case, force a rebuild seeded
						// from the concrete incoming snapshot for this edge.
						if it.cfg != nil && it.cfg.runtimeEpoch != 0 && it.cfg.runtimeBecameDynamic && cur.EntryStackGen() == 0 {
							needSeed = true
						}
						// NOTE: height mismatch (len(es) != len(in)) alone does NOT trigger rebuild.
						// The PHI was built for the mode height; edges with different heights are handled
						// by evalPhi's snapshot fallback, which returns zero for out-of-range depths.
						// Rebuilding on every height-mismatched edge causes thrashing: each rebuild
						// invalidates downstream operand references and produces "missing result for def".
					} else {
						// entryStack is nil.
						//
						// Only seed if incoming stack heights vary and this edge's height
						// is not the mode height.
						modeLen := -1
						modeCnt := -1
						counts := make(map[int]int, 4)
						for _, s := range cur.incomingStacks {
							counts[len(s)]++
						}
						for l, c := range counts {
							if c > modeCnt || (c == modeCnt && (modeLen < 0 || l < modeLen)) {
								modeLen, modeCnt = l, c
							}
						}
						// In dynamic-jump regions, DO NOT unconditionally specialize to a single predecessor
						// when heights are consistent. Doing so can bake path-dependent constants into the
						// entry stack and remove required PHIs, which can flip branch conditions and diverge.
						// NOTE: height mismatch (len(in) != modeLen) does NOT trigger rebuild.
						// Same rationale as the es!=nil path above: PHIs built at mode height
						// handle shorter edges via evalPhi's snapshot fallback returning zero.
						_ = modeLen
					}
					if needSeed {
						// This should be rare for valid bytecode: feasible paths reaching the same JUMPDEST
						// should have the same stack height. When it happens, it often indicates either:
						// - incomplete/unstable dynamic CFG discovery (transient), or
						// - a CFG/snapshot bookkeeping bug.
						//
						// Log (throttled) so we can notice it during long sync runs.
						maybeLogEntryStackMismatch(it, cur, prev, func() int {
							if es == nil {
								return -1
							}
							return len(es)
						}(), len(in))
						// If we have a CFG and a predecessor, refresh this edge snapshot using the
						// concrete runtime exit stack of the predecessor. This repairs cases where
						// build-time snapshots (or stale cached ones) have the wrong height/values.
						if it.cfg != nil && prev != nil && cur != nil {
							// IMPORTANT: use computeExitSnapshotForEdgeTo so loop/backedge hardening runs.
							// In particular, this avoids storing "future defs" (values defined in `cur`) as
							// symbolic live-ins, which would cause getEntryStackForBlock to drop the backedge
							// snapshot entirely and can freeze loop-carried values (e.g. loop index).
							snap := it.computeExitSnapshotForEdgeTo(nil, prev, cur)
							it.cfg.connectEdge(prev, cur, snap)
							if in2, ok2 := cur.incomingStacks[prev]; ok2 && in2 != nil {
								in = in2
							}
						}
						// IMPORTANT: do NOT seed the entry stack values from a single predecessor edge.
						// That can bake per-path constants (e.g. return addresses, dispatcher indices) into
						// the block and eliminate required PHIs, which is a common cause of divergent loops
						// and invalid jumpdest 0x0.
						//
						// Instead, force a rebuild using *all* incoming stacks of this edge's height and let
						// getEntryStackForBlock generate PHIs to reconcile differing values.
						// When incoming stack heights vary, we must rebuild to the *current edge's* height.
						// Otherwise (e.g. picking the mode/max height), we can drop the current edge's return
						// address / deep operands and bake the wrong control-flow (common in internal-call
						// trampolines).
						cur.preferredEntryHeight = len(in)
						cur.SetEntryStack(nil)
						if len(cur.instructions) > 0 {
							it.invalidateBlockResults(cur)
							cur.ResetForRebuild(false)
						}
						cur.built = false
					}
				}
			}
		}
	skipSeed:
		// Ensure the current block is built before executing it. This is critical for correctness
		// when new incoming edges are discovered at runtime (dynamic jumps): we must never rebuild
		// a block while it is actively executing, because that can invalidate PHI/results mid-run.
		if cur != nil && !cur.built {
			// Try PHI-only rebuild first: this preserves non-PHI instructions and
			// their resIdx, avoiding the need to save/restore loop-carried results
			// and the cascade of invalidated operand references.
			phiOnly := false
			if len(cur.instructions) > 0 {
				phiOnly = cur.RebuildPhiOnly(it.cfg)
			}
			if !phiOnly {
				// PHI-only rebuild not possible (height changed or no existing instructions).
				// Fall back to full rebuild with loop-carried result preservation.
				var savedResults map[mirDefKey]uint256.Int
				if cur.IsLoopHeader || cur.IsInLoop {
					savedResults = make(map[mirDefKey]uint256.Int, len(cur.instructions))
					for _, m := range cur.instructions {
						if m == nil || m.op == MirPHI {
							continue
						}
						if m.resIdx > 0 && m.resIdx < len(it.resultsGen) && it.resultsGen[m.resIdx] == it.gen {
							savedResults[keyForDef(m)] = it.results[m.resIdx]
						}
					}
				}
				if len(cur.instructions) > 0 {
					it.invalidateBlockResults(cur)
					cur.ResetForRebuild(false)
				}
				if err := it.cfg.buildBasicBlock(cur, it.validJumpDests); err != nil {
					return it.finishResult(ExecResult{Err: fmt.Errorf("%w: runtime rebuild failed: %v", ErrMIRInternal, err)})
				}
				if savedResults != nil {
					for _, m := range cur.instructions {
						if m == nil || m.op == MirPHI {
							continue
						}
						if v, ok := savedResults[keyForDef(m)]; ok {
							if m.resIdx > 0 && m.resIdx < len(it.results) {
								it.results[m.resIdx] = v
								it.resultsGen[m.resIdx] = it.gen
							}
						}
					}
				}
			}
		}

		// Reset the local instruction cursor for this block execution.
		blockPos = 0
		it.curEvmOpIndex = -1
		it.curBlockConstPrefix = it.ensureBlockConstPrefix(cur)
		it.curBlockConstDelta, it.curBlockConstTail = it.ensureBlockConstDelta(cur)

		// NOTE: EVM can reach the same JUMPDEST with different stack heights via dynamic jumps.
		// MIR must tolerate this at runtime. PHI evaluation uses per-edge incoming snapshots,
		// and out-of-range stack slots resolve to 0 (defensive semantics).

	execBlock:
		for {
			// Inline MIRBasicBlock.GetNextOp() using local blockPos to avoid re-entrant corruption.
			var m *MIR
			if blockPos >= len(cur.instructions) {
				m = nil
			} else {
				m = cur.instructions[blockPos]
				blockPos++
			}
			if m == nil {
				// Charge any trailing constant gas in this block not yet accounted for.
				if it.curBlockConstTail != 0 {
					if err := it.chargeGas(it.curBlockConstTail); err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
				}
				// No explicit terminator MIR in this block: fallthrough if any child exists.
				children := cur.Children()
				if len(children) == 0 {
					return it.finishResult(ExecResult{HaltOp: MirSTOP})
				}
				// Deterministic: fallthrough to the first child (for non-terminator blocks).
				// Performance: computing edge snapshots is allocation-heavy. Only refresh snapshots when
				// needed for dynamic CFG regions (unresolved jumps). For static CFG edges (including loops),
				// rely on build-time snapshots unless we detect a mismatch and explicitly repair it.
				if it.cfg != nil && cur != nil && children[0] != nil {
					to := children[0]
					if cur.unresolvedJump || to.unresolvedJump || (to.IsLoopHeader && to.IsBackEdgeFrom(cur)) {
						// Avoid allocation-heavy snapshot computation on stable edges:
						// only refresh if this edge hasn't been recorded yet or the target entry stack
						// is currently invalidated (nil) and may need PHI rebuild.
						need := true
						if to.incomingStacks != nil {
							if _, ok := to.incomingStacks[cur]; ok && to.entryStack != nil {
								need = false
							}
						}
						if need {
							it.cfg.connectEdge(cur, to, it.computeExitSnapshotForEdgeTo(prev, cur, to))
						}
					}
				}
				prev, cur = cur, children[0]
				break execBlock
			}
			// Charge constant gas up to and including the originating EVM opcode for this MIR op.
			// This accounts for optimized-away stack ops (PUSH/DUP/SWAP) by charging them in the delta
			// between consecutive emitted MIR ops.
			if it.curBlockConstDelta != nil && m.idx >= 0 && m.idx < len(it.curBlockConstDelta) {
				if d := it.curBlockConstDelta[m.idx]; d != 0 {
					if err := it.chargeGas(d); err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
				}
			} else {
				if err := it.chargeConstGasForMIR(cur, m); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
			}
			it.lastEvmPC = m.evmPC
			it.curBlock = cur
			it.curEvmPC = m.evmPC
			it.curEvmOp = m.evmOp
			if it.stepHook != nil {
				it.stepHook(m.evmPC, m.evmOp, m.op)
			}

			// Optional debug hooks
			if it.debugOperandHook != nil {
				// Targeted operand capture for diagnosing control-flow divergence.
				switch m.op {
				case MirADD:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *a, *b)
					}
				case MirAND:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *a, *b)
					}
				case MirCALLDATACOPY, MirRETURNDATACOPY:
					// For copy ops capture: a=dest, b=size.
					dest, err1 := it.evalOperand(m, 0)
					sz, err2 := it.evalOperand(m, 2)
					if err1 == nil && err2 == nil && dest != nil && sz != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *dest, *sz)
					}
				case MirSLOAD:
					k, err := it.evalOperand(m, 0)
					if err == nil && k != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *k, uint256.Int{})
					}
				case MirSSTORE:
					k, err1 := it.evalOperand(m, 0)
					v, err2 := it.evalOperand(m, 1)
					if err1 == nil && err2 == nil && k != nil && v != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *k, *v)
					}
				case MirJUMP:
					d, err := it.evalOperand(m, 0)
					if err == nil && d != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *d, uint256.Int{})
					}
				case MirGT:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *a, *b)
					}
				case MirLT:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *a, *b)
					}
				case MirJUMPI:
					d, err1 := it.evalOperand(m, 0)
					c, err2 := it.evalOperand(m, 1)
					if err1 == nil && err2 == nil && d != nil && c != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *d, *c)
					}
				}
			}
			if it.debugOperandHookEx != nil {
				switch m.op {
				case MirADD:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirLT:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirSLOAD:
					k, err := it.evalOperand(m, 0)
					if err == nil && k != nil {
						var kDefPC uint
						var kDefOp MirOperation
						if len(m.operands) >= 1 {
							if v := m.operands[0]; v != nil && v.def != nil {
								kDefPC, kDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *k, uint256.Int{}, kDefPC, 0, kDefOp, 0)
					}
				case MirMLOAD:
					off, err := it.evalOperand(m, 0)
					if err == nil && off != nil {
						var offDefPC uint
						var offDefOp MirOperation
						if len(m.operands) >= 1 {
							if v := m.operands[0]; v != nil && v.def != nil {
								offDefPC, offDefOp = v.def.evmPC, v.def.op
							}
						}
						// Best-effort: compute the word that MLOAD will read from memory.
						//
						// IMPORTANT: This must be side-effect free (no gas charging / no memory expansion),
						// otherwise enabling debug hooks changes execution semantics.
						var loaded uint256.Int
						loaded.Clear()
						o64, ov := off.Uint64WithOverflow()
						if !ov {
							o := int(o64)
							if o >= 0 && o+32 <= len(it.mem) {
								loaded.SetBytes(it.mem[o : o+32])
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *off, loaded, offDefPC, 0, offDefOp, 0)
					}
				case MirMSTORE:
					off, err1 := it.evalOperand(m, 0)
					val, err2 := it.evalOperand(m, 1)
					if err1 == nil && err2 == nil && off != nil && val != nil {
						var offDefPC, valDefPC uint
						var offDefOp, valDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								offDefPC, offDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								valDefPC, valDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *off, *val, offDefPC, valDefPC, offDefOp, valDefOp)
					}
				case MirSTATICCALL:
					// STATICCALL operands are important for memory overflow debugging.
					// We expose (gas, addr) as (a,b) here; detailed offsets/sizes are better captured
					// at the call-execution layer, but this is still useful to link provenance.
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirOR:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirSUB:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirCALLDATACOPY, MirRETURNDATACOPY:
					// For copy ops capture: a=dest, b=size.
					dest, err1 := it.evalOperand(m, 0)
					sz, err2 := it.evalOperand(m, 2)
					if err1 == nil && err2 == nil && dest != nil && sz != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 3 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[2]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *dest, *sz, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirSSTORE:
					k, err1 := it.evalOperand(m, 0)
					v, err2 := it.evalOperand(m, 1)
					if err1 == nil && err2 == nil && k != nil && v != nil {
						var kDefPC, vDefPC uint
						var kDefOp, vDefOp MirOperation
						if len(m.operands) >= 2 {
							if vv := m.operands[0]; vv != nil && vv.def != nil {
								kDefPC, kDefOp = vv.def.evmPC, vv.def.op
							}
							if vv := m.operands[1]; vv != nil && vv.def != nil {
								vDefPC, vDefOp = vv.def.evmPC, vv.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *k, *v, kDefPC, vDefPC, kDefOp, vDefOp)
					}
				case MirAND:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirJUMP:
					d, err := it.evalOperand(m, 0)
					if err == nil && d != nil {
						var dDefPC uint
						var dDefOp MirOperation
						if len(m.operands) >= 1 {
							if v := m.operands[0]; v != nil && v.def != nil {
								dDefPC, dDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *d, uint256.Int{}, dDefPC, 0, dDefOp, 0)
					}
				case MirGT:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						var aDefPC, bDefPC uint
						var aDefOp, bDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								aDefPC, aDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								bDefPC, bDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *a, *b, aDefPC, bDefPC, aDefOp, bDefOp)
					}
				case MirJUMPI:
					d, err1 := it.evalOperand(m, 0)
					c, err2 := it.evalOperand(m, 1)
					if err1 == nil && err2 == nil && d != nil && c != nil {
						var dDefPC, cDefPC uint
						var dDefOp, cDefOp MirOperation
						if len(m.operands) >= 2 {
							if v := m.operands[0]; v != nil && v.def != nil {
								dDefPC, dDefOp = v.def.evmPC, v.def.op
							}
							if v := m.operands[1]; v != nil && v.def != nil {
								cDefPC, cDefOp = v.def.evmPC, v.def.op
							}
						}
						it.debugOperandHookEx(m.evmPC, m.evmOp, m.op, *d, *c, dDefPC, cDefPC, dDefOp, cDefOp)
					}
				}
			}

			// executes the MIR operation
			switch m.op {
			case MirPHI:
				v, err := it.evalPhi(cur, prev, m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.setResult(m, v)

			case MirPOP:
				// effect already modeled by IR; no runtime action needed here

			case MirNOP:
				// No-op instruction used for bookkeeping (e.g. constant-folded EVM op alignment/gas).
				// Constant gas for its originating EVM opcode is still charged via the const-delta path.

			case MirADD, MirMUL, MirSUB, MirDIV, MirSDIV, MirMOD, MirSMOD, MirEXP, MirSIGNEXT,
				MirAND, MirOR, MirXOR, MirBYTE, MirSHL, MirSHR, MirSAR,
				MirLT, MirGT, MirSLT, MirSGT, MirEQ:
				// Dynamic gas: EXP charges per-byte of exponent (on top of constant gas).
				if m.op == MirEXP {
					if err := it.chargeExpDynamicGas(m); err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
				}
				a, b, err := it.evalBinary(m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				switch m.op {
				case MirADD:
					out.Add(a, b)
				case MirMUL:
					out.Mul(a, b)
				case MirSUB:
					out.Sub(a, b)
				case MirDIV:
					out.Div(a, b)
				case MirSDIV:
					out.SDiv(a, b)
				case MirMOD:
					out.Mod(a, b)
				case MirSMOD:
					out.SMod(a, b)
				case MirEXP:
					out.Exp(a, b)
				case MirSIGNEXT:
					// EVM SIGNEXTEND: stack is [byteIndex(top)=a, value=b]; ExtendSign(value, byteIndex).
					out.ExtendSign(b, a)
				case MirAND:
					out.And(a, b)
				case MirOR:
					out.Or(a, b)
				case MirXOR:
					out.Xor(a, b)
				case MirBYTE:
					// EVM: BYTE(n, x) => nth byte of x (0=most significant), or 0 if n>=32.
					n := a.Uint64()
					if n >= 32 {
						out.Clear()
					} else {
						b32 := b.Bytes32()
						out.SetUint64(uint64(b32[n]))
					}
				case MirSHL:
					shift, ov := a.Uint64WithOverflow()
					if ov || shift >= 256 {
						out.Clear()
					} else {
						out.Lsh(b, uint(shift))
					}
				case MirSHR:
					shift, ov := a.Uint64WithOverflow()
					if ov || shift >= 256 {
						out.Clear()
					} else {
						out.Rsh(b, uint(shift))
					}
				case MirSAR:
					shift, ov := a.Uint64WithOverflow()
					if ov || shift >= 256 {
						out.SRsh(b, 255)
					} else {
						out.SRsh(b, uint(shift))
					}
				case MirLT:
					if a.Lt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirGT:
					// EVM semantics: GT compares x > y where x is stack top and y is next item.
					if a.Gt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirSLT:
					if a.Slt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirSGT:
					if a.Sgt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirEQ:
					if a.Eq(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				}

			case MirADDMOD, MirMULMOD:
				// Ternary ops: operands are [a(top), b, c(modulus)].
				a, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				b, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				c, err := it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				switch m.op {
				case MirADDMOD:
					out.AddMod(a, b, c)
				case MirMULMOD:
					out.MulMod(a, b, c)
				}

			case MirNOT, MirISZERO:
				a, err := it.evalUnary(m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				switch m.op {
				case MirNOT:
					out.Not(a)
				case MirISZERO:
					if a.IsZero() {
						out.SetOne()
					} else {
						out.Clear()
					}
				}

			case MirMLOAD:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, u256U32); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				word := it.mem[o : o+32]
				it.resultSlot(m).SetBytes(word)

			case MirMSTORE:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, u256U32); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				w := val.Bytes32()
				copy(it.mem[o:o+32], w[:])

			case MirMSTORE8:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, u256One); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 1)
				it.mem[o] = byte(val.Uint64() & 0xff)

			case MirMSIZE:
				it.resultSlot(m).SetUint64(uint64(len(it.mem)))

			case MirKECCAK256:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeKeccakDynamicGas(off, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				if n < 0 {
					n = 0
				}
				it.ensureMem(o + n)
				if it.debugKeccakHook != nil {
					off64, _ := off.Uint64WithOverflow()
					sz64, _ := sz.Uint64WithOverflow()
					snip := n
					if snip > 64 {
						snip = 64
					}
					buf := make([]byte, snip)
					if snip > 0 {
						copy(buf, it.mem[o:o+snip])
					}
					it.debugKeccakHook(m.evmPC, off64, sz64, buf)
				}
				h := crypto.Keccak256Hash(it.mem[o : o+n])
				it.resultSlot(m).SetBytes(h[:])

			case MirADDRESS:
				it.resultSlot(m).SetBytes(it.contractAddr.Bytes())

			case MirORIGIN:
				it.resultSlot(m).SetBytes(it.originAddr.Bytes())

			case MirCALLER:
				it.resultSlot(m).SetBytes(it.callerAddr.Bytes())

			case MirGASPRICE:
				out := it.resultSlot(m)
				if it.txGasPrice == nil {
					out.Clear()
				} else {
					out.SetFromBig(it.txGasPrice)
				}

			case MirPC:
				it.resultSlot(m).SetUint64(uint64(m.evmPC))

			case MirCOINBASE:
				it.resultSlot(m).SetBytes(it.blockCoinbase.Bytes())

			case MirTIMESTAMP:
				it.resultSlot(m).SetUint64(it.blockTime)

			case MirNUMBER:
				it.resultSlot(m).SetUint64(it.blockNumber)

			case MirGASLIMIT:
				it.resultSlot(m).SetUint64(it.blockGasLimit)

			case MirCHAINID:
				out := it.resultSlot(m)
				if it.chainRules.ChainID == nil {
					out.Clear()
				} else {
					out.SetFromBig(it.chainRules.ChainID)
				}

			case MirBASEFEE:
				out := it.resultSlot(m)
				if !it.chainRules.IsLondon || it.blockBaseFee == nil {
					out.Clear()
				} else {
					out.SetFromBig(it.blockBaseFee)
				}

			case MirDIFFICULTY:
				// Pre-merge: DIFFICULTY returns block difficulty.
				// Post-merge: DIFFICULTY is repurposed as PREVRANDAO (random).
				out := it.resultSlot(m)
				if it.chainRules.IsMerge {
					if it.blockRandom == nil {
						out.Clear()
					} else {
						out.SetBytes(it.blockRandom.Bytes())
					}
				} else {
					if it.blockDifficulty == nil {
						out.Clear()
					} else {
						out.SetFromBig(it.blockDifficulty)
					}
				}

			case MirBLOCKHASH:
				blkN, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				// If no GetHash hook is provided, behave as if unknown (0).
				if it.blockGetHash == nil || blkN == nil {
					out.Clear()
					break
				}
				n64, ov := blkN.Uint64WithOverflow()
				if ov {
					out.Clear()
					break
				}
				// EVM semantics: only hashes for the previous 256 blocks are available.
				if n64 >= it.blockNumber || it.blockNumber-n64 > 256 {
					out.Clear()
					break
				}
				h := it.blockGetHash(n64)
				out.SetBytes(h[:])

			case MirBLOBHASH:
				idxU, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				if !it.chainRules.IsCancun || idxU == nil {
					out.Clear()
					break
				}
				i64, ov := idxU.Uint64WithOverflow()
				if ov || int(i64) >= len(it.txBlobHashes) {
					out.Clear()
					break
				}
				h := it.txBlobHashes[int(i64)]
				out.SetBytes(h[:])

			case MirBLOBBASEFEE:
				out := it.resultSlot(m)
				if !it.chainRules.IsCancun || it.blockBlobBaseFee == nil {
					out.Clear()
				} else {
					out.SetFromBig(it.blockBlobBaseFee)
				}

			case MirSELFBALANCE:
				out := it.resultSlot(m)
				if it.state == nil {
					out.Clear()
				} else {
					out.Set(it.state.GetBalanceU256(it.contractAddr))
				}

			case MirCALLVALUE:
				out := it.resultSlot(m)
				if it.callValue == nil {
					out.Clear()
				} else {
					out.Set(it.callValue)
				}

			case MirGAS:
				// With incremental constant-gas charging, GAS observes the current gas remaining.
				it.resultSlot(m).SetUint64(it.gasLeft())

			case MirCALLDATALOAD:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				var word [32]byte
				if o < 0 {
					o = 0
				}
				if it.callData != nil && o < len(it.callData) {
					end := o + 32
					if end > len(it.callData) {
						end = len(it.callData)
					}
					copy(word[:], it.callData[o:end])
				}
				it.resultSlot(m).SetBytes(word[:])

			case MirCALLDATASIZE:
				it.resultSlot(m).SetUint64(uint64(len(it.callData)))

			case MirCODESIZE:
				// EVM CODESIZE returns the size of the current executing code.
				// In MIR, cfg.rawCode is the contract bytecode this interpreter instance was built for.
				if it.cfg == nil {
					it.resultSlot(m).Clear()
				} else {
					it.resultSlot(m).SetUint64(uint64(len(it.cfg.rawCode)))
				}

			case MirSLOAD:
				keyU, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				slot := common.Hash(keyU.Bytes32())
				if err := it.chargeSLoadGas(slot); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				var hv common.Hash
				if it.state != nil {
					hv = it.state.GetState(it.contractAddr, slot)
				}
				it.resultSlot(m).SetBytes(hv[:])
				if mirDebugBlock != 0 && it.blockNumber == mirDebugBlock {
					log.Warn("MIR SLOAD", "addr", it.contractAddr, "pc", m.evmPC, "slot", slot, "value", hv)
				}
				// Optional targeted debug: expose the loaded value (post-read).
				if it.debugOperandHook != nil && keyU != nil {
					var vv uint256.Int
					vv.SetBytes(hv[:])
					it.debugOperandHook(m.evmPC, m.evmOp, m.op, *keyU, vv)
				}

			case MirSSTORE:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				keyU, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				valU, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				slot := common.Hash(keyU.Bytes32())
				val := common.Hash(valU.Bytes32())
				if err := it.chargeSStoreGas(slot, val); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if it.state != nil {
					it.state.SetState(it.contractAddr, slot, val)
				}

			case MirTLOAD:
				keyU, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				slot := common.Hash(keyU.Bytes32())
				var hv common.Hash
				if it.state != nil {
					hv = it.state.GetTransientState(it.contractAddr, slot)
				}
				it.resultSlot(m).SetBytes(hv[:])

			case MirTSTORE:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				keyU, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				valU, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if it.state != nil {
					it.state.SetTransientState(it.contractAddr, common.Hash(keyU.Bytes32()), common.Hash(valU.Bytes32()))
				}

			case MirMCOPY:
				// Operands: dst, src, size
				dst, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				src, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMcopyDynamicGas(dst, src, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				d := int(dst.Uint64())
				s := int(src.Uint64())
				n := int(sz.Uint64())
				if n < 0 {
					n = 0
				}
				need := maxInt(d+n, s+n)
				it.ensureMem(need)
				// Go's copy is memmove-safe for overlapping slices.
				copy(it.mem[d:d+n], it.mem[s:s+n])

			case MirLOG0, MirLOG1, MirLOG2, MirLOG3, MirLOG4:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				if err := it.chargeLogDynamicGas(m); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				// Semantics (recording logs)
				// 1. Get offset and size
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}

				// 2. Read data from memory
				o := int(off.Uint64())
				n := int(sz.Uint64())
				if n < 0 {
					n = 0
				}
				it.ensureMem(o + n)
				data := make([]byte, n)
				copy(data, it.mem[o:o+n])

				// 3. Read topics from stack
				numTopics := int(m.op - MirLOG0)
				topics := make([]common.Hash, numTopics)
				for i := 0; i < numTopics; i++ {
					// Topics start at operand index 2
					val, err := it.evalOperand(m, 2+i)
					if err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
					topics[i] = common.Hash(val.Bytes32())
				}

				// 4. Record log via backend
				if it.state != nil {
					it.state.AddLog(it.contractAddr, topics, data, it.blockNumber)
				}
				if mirRunnerDebugLog {
					topicStrs := make([]string, len(topics))
					for ti, t := range topics {
						topicStrs[ti] = t.Hex()
					}
					log.Debug("MIR LOG emitted",
						"addr", it.contractAddr,
						"pc", m.evmPC,
						"numTopics", len(topics),
						"topics", topicStrs,
						"dataLen", len(data),
					)
				}
				if mirDebugBlock != 0 && it.blockNumber == mirDebugBlock {
					topicStrs := make([]string, len(topics))
					for ti, t := range topics {
						topicStrs[ti] = t.Hex()
					}
					log.Warn("MIR LOG debug",
						"block", it.blockNumber,
						"addr", it.contractAddr,
						"pc", m.evmPC,
						"numTopics", len(topics),
						"topics", topicStrs,
						"dataLen", len(data),
					)
				}

			case MirBALANCE:
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				if it.state == nil {
					out.Clear()
					break
				}
				bal := it.state.GetBalance(addr)
				out.SetBytes(bal[:])

			case MirEXTCODESIZE:
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				if it.state == nil {
					out.Clear()
					break
				}
				out.SetUint64(uint64(it.state.GetCodeSize(addr)))

			case MirEXTCODEHASH:
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := it.resultSlot(m)
				if it.state == nil {
					out.Clear()
					break
				}
				h := it.state.GetCodeHash(addr)
				out.SetBytes(h[:])

			case MirEXTCODECOPY:
				// Operands: address, destOffset, codeOffset, size
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				dest, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				// codeOffset (ignored for now)
				_, err = it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 3)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(dest, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeCopyGas(sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				// Semantics: copy external account code into memory (out-of-range reads => zero padding)
				d := int(dest.Uint64())
				n := int(sz.Uint64())
				if n < 0 {
					n = 0
				}
				it.ensureMem(d + n)
				var code []byte
				if it.state != nil {
					code = it.state.GetCode(addr)
				}
				// codeOffset is operand 2
				co, _ := it.evalOperand(m, 2)
				codeOff := int(co.Uint64())
				for i := 0; i < n; i++ {
					srcIdx := codeOff + i
					if srcIdx >= 0 && srcIdx < len(code) {
						it.mem[d+i] = code[srcIdx]
					} else {
						it.mem[d+i] = 0
					}
				}

			case MirCALLDATACOPY:
				// operands: dest, offset, size
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				off, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(dest, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeCopyGas(sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.memCopyFromBytes(dest, off, sz, it.callData)

			case MirCODECOPY:
				// operands: dest, offset, size
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				off, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(dest, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeCopyGas(sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				var code []byte
				if it.cfg != nil {
					code = it.cfg.rawCode
				}
				it.memCopyFromBytes(dest, off, sz, code)

			case MirRETURNDATASIZE:
				it.resultSlot(m).SetUint64(uint64(len(it.returnData)))

			case MirRETURNDATACOPY:
				// operands: dest, offset, size
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				off, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 2)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				// Bounds check (matches geth opReturnDataCopy):
				// if offset+size > len(returnData) => ErrReturnDataOutOfBounds (fatal)
				off64, offOv := off.Uint64WithOverflow()
				sz64, szOv := sz.Uint64WithOverflow()
				if offOv || szOv {
					return it.finishResult(ExecResult{Err: vm.ErrReturnDataOutOfBounds})
				}
				end := off64 + sz64
				if end < off64 || uint64(len(it.returnData)) < end {
					return it.finishResult(ExecResult{Err: vm.ErrReturnDataOutOfBounds})
				}
				if err := it.chargeMemoryExpansion(dest, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeCopyGas(sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.memCopyFromBytes(dest, off, sz, it.returnData)

			case MirCALL, MirCALLCODE, MirDELEGATECALL, MirSTATICCALL:
				ok, err := it.execCallLike(m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.resultSlot(m).SetUint64(ok)

			case MirCREATE:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				addr, err := it.execCreateLike(m, false)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.resultSlot(m).SetBytes(addr.Bytes())

			case MirCREATE2:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				addr, err := it.execCreateLike(m, true)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.resultSlot(m).SetBytes(addr.Bytes())

			case MirJUMP:
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				target := uint(dest.Uint64())
				// Fast path: O(1) jump table lookup.
				// Static targets are pre-populated by connectEdge during Parse().
				// Dynamic targets are cached here after the first resolveBB call.
				if cur != nil {
					if ch, ok := cur.jumpTable[target]; ok && ch != nil {
						it.refreshEdgeIfNeeded(prev, cur, ch)
						it.tagIncomingEpoch(cur, ch)
						prev, cur = cur, ch
						break execBlock
					}
				}
				// Slow path: runtime analysis — validate target PC, build block if new,
				// connect the edge (which also populates jumpTable for future fast-path hits).
				nb, err := it.resolveBB(prev, cur, target)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				prev, cur = cur, nb
				break execBlock

			case MirJUMPI:
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				cond, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				target := uint(dest.Uint64())
				if it.jumpiHook != nil {
					it.jumpiHook(m.evmPC, target, cond, !cond.IsZero(), it.cfg)
				}
				if mirDebugBlock != 0 && it.blockNumber == mirDebugBlock {
					log.Warn("MIR JUMPI", "addr", it.contractAddr, "pc", m.evmPC, "target", target, "cond", cond.Uint64(), "taken", !cond.IsZero())
				}
				if !cond.IsZero() {
					// Fast path: O(1) jump table lookup.
					// Static targets are pre-populated by connectEdge during Parse().
					// Dynamic targets are cached here after the first resolveBB call.
					if cur != nil {
						if ch, ok := cur.jumpTable[target]; ok && ch != nil {
							it.refreshEdgeIfNeeded(prev, cur, ch)
							it.tagIncomingEpoch(cur, ch)
							prev, cur = cur, ch
							break execBlock
						}
					}
					// Slow path: runtime analysis — validate target PC, build block if new,
					// connect the edge (which also populates jumpTable for future fast-path hits).
					nb, err := it.resolveBB(prev, cur, target)
					if err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
					prev, cur = cur, nb
					break execBlock
				}
				// fallthrough: cond == 0, so we take the non-jump successor (evmPC+1).
				ftPC := m.evmPC + 1
				var ft *MIRBasicBlock
				// Fast path: O(1) jumpTable lookup.
				// The fallthrough block is connected first in buildBasicBlock (connectEdge before
				// the taken-branch edge), so it is always present in jumpTable[ftPC].
				// This correctly handles N>1 taken-branch targets (traceJumpDestCandidates), where
				// cur has more than 2 children (fallthrough + N targets) and the old len==2 fast
				// path was silently skipped, leaving only the O(N) scan.
				if cur != nil {
					if ch, ok := cur.jumpTable[ftPC]; ok && ch != nil {
						ft = ch
					}
				}
				if ft == nil {
					// Fallback: linear scan for transient states where jumpTable may be incomplete
					// (e.g. before the first Parse() pass for this block has finished).
					for _, ch := range cur.Children() {
						if ch != nil && ch.firstPC == ftPC {
							ft = ch
							break
						}
					}
					if ft == nil {
						if len(cur.Children()) == 0 {
							return it.finishResult(ExecResult{HaltOp: MirSTOP})
						}
						ft = cur.Children()[0]
					}
				}
				// Performance: avoid snapshotting fallthrough edges unless we are in an unresolved
				// jump region. Static CFG fallthrough edges already have build-time snapshots.
				// However, if the fallthrough target entry stack is invalidated, refresh this edge snapshot
				// even for forward static edges.
				if cur != nil && ft != nil && it.cfg != nil && (cur.unresolvedJump || ft.unresolvedJump || (ft.IsLoopHeader && ft.IsBackEdgeFrom(cur)) || ft.entryStack == nil) {
					need := true
					if ft.incomingStacks != nil {
						if _, ok := ft.incomingStacks[cur]; ok && ft.entryStack != nil {
							need = false
						}
					}
					if !need && it.cfg != nil && it.cfg.runtimeEpoch != 0 {
						if ft.incomingStacksGen == nil {
							ft.incomingStacksGen = make(map[*MIRBasicBlock]uint64, 8)
						}
						ft.incomingStacksGen[cur] = it.cfg.runtimeEpoch
					}
					if need {
						it.cfg.connectEdge(cur, ft, it.computeExitSnapshotForEdgeTo(prev, cur, ft))
					}
				}
				it.tagIncomingEpoch(cur, ft)
				prev, cur = cur, ft
				break execBlock

			case MirSTOP:
				return it.finishResult(ExecResult{HaltOp: MirSTOP})
			case MirRETURN:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				it.ensureMem(o + n)
				out := make([]byte, n)
				copy(out, it.mem[o:o+n])
				return it.finishResult(ExecResult{HaltOp: MirRETURN, ReturnData: out, ReturnOffset: off.Uint64(), ReturnSize: sz.Uint64()})
			case MirREVERT:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, sz); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				it.ensureMem(o + n)
				out := make([]byte, n)
				copy(out, it.mem[o:o+n])
				// Revert state changes and keep leftover gas.
				if it.manageStateSnapshots && it.state != nil && snap >= 0 {
					it.state.RevertToSnapshot(snap)
				}
				return it.finishResult(ExecResult{HaltOp: MirREVERT, ReturnData: out, Err: vm.ErrExecutionReverted, ReturnOffset: off.Uint64(), ReturnSize: sz.Uint64()})

			case MirSELFDESTRUCT:
				if it.readOnly {
					return it.finishResult(ExecResult{Err: vm.ErrWriteProtection})
				}
				beneficiary, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeSelfdestructDynamicGas(beneficiary); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.execSelfdestruct(beneficiary)
				return it.finishResult(ExecResult{HaltOp: MirSELFDESTRUCT})

			default:
				// Fatal error: revert and consume all gas.
				if it.manageStateSnapshots && it.state != nil && snap >= 0 {
					it.state.RevertToSnapshot(snap)
				}
				return it.finishResult(ExecResult{Err: fmt.Errorf("unimplemented MIR op: %s", m.op.String())})
			}
		}
	}
}

// resolveBB is the runtime backfill hook for dynamic jumps.
// It validates jumpdest, creates/builds the target block if missing, and records a CFG edge
// (including incoming stack snapshot) to enable PHI correctness.
// computeExitSnapshotForEdge computes a best-effort exit stack snapshot for the concrete
// executed edge (prev -> from), to be stored as the incoming snapshot for the dynamic
// jump target during runtime backfill.
//
// Why this exists:
//   - CFG build-time `from.ExitStack()` is computed from a single assumed entry stack for `from`.
//   - For some real-world bytecode (jump-table dispatchers, meta-programmed flows), the same basic
//     block can be reached with different stack heights across iterations (e.g. self-loop patterns).
//   - Using the build-time `ExitStack()` for dynamic backfill can therefore record an incorrect
//     incoming snapshot for the target block, which then causes PHIs to resolve to 0 and
//     manifests as `invalid jumpdest 0x0` on otherwise-valid native executions.
//
// This routine uses the *runtime* entry snapshot (`from.incomingStacks[prev]`) and the
// build-time stack delta for `from` to compute a consistent exit snapshot for this edge.
func (it *MIRInterpreter) computeExitSnapshotForEdge(prev, from *MIRBasicBlock) []Value {
	if from == nil {
		return nil
	}
	// Runtime entry snapshot for this edge, if available.
	var entry []Value
	if prev != nil {
		entry = from.incomingStacks[prev]
		// Ignore stale runtime snapshots from previous executions when CFG is cached.
		if entry != nil && it.cfg != nil && it.cfg.runtimeEpoch != 0 && from.incomingStacksGen != nil {
			if g, ok := from.incomingStacksGen[prev]; ok && g != 0 && g != it.cfg.runtimeEpoch {
				entry = nil
			}
		}
	}
	if entry == nil {
		// Fall back to the block's cached entry stack (best-effort).
		entry = from.EntryStack()
	}
	exitStatic := from.ExitStack()
	entryStatic := from.EntryStack()
	if exitStatic == nil {
		// If the block doesn't have an exit snapshot (e.g. transiently during rebuild),
		// never record "nil => empty stack" for an edge: that poisons downstream PHIs.
		// Best-effort: use the runtime entry snapshot for this edge.
		if entry != nil {
			out := make([]Value, len(entry))
			copy(out, entry)
			return out
		}
		return nil
	}
	if entryStatic == nil {
		// Can't reason about live-in mapping without a static entry shape; fall back.
		return exitStatic
	}

	// Best-effort, order-preserving reconstruction:
	// Use the static exit stack as the *shape* (including SWAP/DUP-induced permutation),
	// but substitute the live-in values with the ones from the concrete runtime entry
	// snapshot for this edge.
	//
	// This avoids relying on "live-ins are a prefix" (which is false under SWAP), and it
	// prevents incorrect edge snapshots from polluting downstream PHIs (e.g. storing a
	// jump-destination value into storage).
	if entry != nil && len(entry) == len(entryStatic) {
		out := make([]Value, len(exitStatic))
		for i := len(exitStatic) - 1; i >= 0; i-- {
			ev := exitStatic[i]
			if !ev.liveIn {
				// Produced within this block; keep as-is (it refers to MIR defs in this block).
				out[i] = ev
				continue
			}
			// Stable remap by original entry-stack slot position when available.
			// This avoids ambiguity when the same constant appears multiple times.
			if ev.liveInPos >= 0 && ev.liveInPos < len(entry) {
				rv := entry[ev.liveInPos]
				rv.liveIn = true
				rv.liveInPos = ev.liveInPos
				out[i] = rv
				continue
			}
			// No position metadata: fall back to static value.
			out[i] = ev
		}
		return out
	}

	// Fallback: if stack heights differ, we can still preserve net-pop behavior by truncating
	// the runtime entry snapshot. This is conservative and avoids accidental stack growth.
	delta := len(exitStatic) - len(entryStatic) // pushes - pops
	if delta < 0 && entry != nil {
		n := len(entry) + delta
		if n < 0 {
			n = 0
		}
		out := make([]Value, n)
		copy(out, entry[:n])
		return out
	}
	return exitStatic
}

// computeExitSnapshotForEdgeTo is like computeExitSnapshotForEdge, but it can additionally
// apply loop/back-edge hardening. For edges that jump "backwards" in bytecode (to.firstPC <= from.firstPC),
// symbolic SSA-style Values can represent the *current-iteration* defs, which are unsafe to carry
// into the next iteration (they become "future" defs). In these cases we materialize the snapshot
// into constants based on the current runtime values.
func (it *MIRInterpreter) computeExitSnapshotForEdgeTo(prev, from, to *MIRBasicBlock) []Value {
	// Use the runtime entry snapshot (when available) to substitute live-ins into the exit-stack
	// shape. This is required for correctness when the entry stack contains runtime-dependent
	// values (not just constants), even on fully static CFG edges.
	snap := it.computeExitSnapshotForEdge(prev, from)
	if snap == nil || to == nil || from == nil {
		return snap
	}
	// Correctness: on back-edges/self-loops, symbolic Values produced within `from` become
	// "future defs" when carried into the next iteration. Materialize only produced values
	// (non-liveIns) into constants to preserve semantics while keeping cost bounded.
	if it.cfg != nil {
		it.cfg.EnsureLoopInfo()
	}
	if to.IsLoopHeader && to.IsBackEdgeFrom(from) {
		return snap
	}
	// Correctness: loops may cross blocks without the lexical "backedge" appearing on this edge
	// (e.g. body->header via an intermediate dispatcher). If an incoming snapshot for `to` carries
	// a Value defined in `to` itself (and it's not a PHI), that Value is a loop-carried runtime
	// value and must not be represented by a symbolic def pointer here (it would be a future def).
	// Materialize just those self-defined values into constants.
	if to.blockNum != 0 {
		for i := range snap {
			v := snap[i]
			if v.kind == Variable && v.def != nil && v.def.op != MirPHI && v.def.defBlockNum == to.blockNum {
				return it.materializeSnapshotSelfDefsOnly(snap, to.blockNum)
			}
		}
	}
	return snap
}

// materializeSnapshotProducedOnly converts only non-liveIn (produced-in-block) elements of a
// symbolic snapshot into constants. This is enough to prevent "future def" issues on back-edges
// without paying the cost of materializing the entire snapshot.
func (it *MIRInterpreter) materializeSnapshotProducedOnly(in []Value) []Value {
	if it == nil || len(in) == 0 {
		return in
	}
	out := make([]Value, len(in))
	copy(out, in)
	for i := range out {
		v := out[i]
		if v.kind == Konst {
			continue
		}
		// Only materialize values produced within the source block (i.e., not live-ins).
		if v.liveIn {
			continue
		}
		u, err := it.evalValue(&v)
		if err != nil || u == nil {
			// Best-effort: keep symbolic if evaluation fails.
			continue
		}
		cv := newConstValueFromU(u)
		cv.liveIn = true
		cv.liveInPos = -1
		out[i] = *cv
	}
	return out
}

// materializeSnapshotSelfDefsOnly materializes only values whose defining MIR belongs to `toBlockNum`
// (excluding PHIs). These are illegal as symbolic live-ins (they are future defs) and must be carried
// as concrete runtime values instead.
func (it *MIRInterpreter) materializeSnapshotSelfDefsOnly(in []Value, toBlockNum uint) []Value {
	if it == nil || len(in) == 0 {
		return in
	}
	out := make([]Value, len(in))
	copy(out, in)
	for i := range out {
		v := out[i]
		if v.kind == Konst {
			continue
		}
		if v.kind == Variable && v.def != nil && v.def.op != MirPHI && v.def.defBlockNum == toBlockNum {
			u, err := it.evalValue(&v)
			if err != nil || u == nil {
				continue
			}
			cv := newConstValueFromU(u)
			cv.liveIn = true
			cv.liveInPos = -1
			out[i] = *cv
		}
	}
	return out
}

func (it *MIRInterpreter) resolveBB(prev, from *MIRBasicBlock, targetPC uint) (*MIRBasicBlock, error) {
	if it.cfg == nil {
		return nil, errors.New("nil CFG")
	}
	if it.validJumpDests != nil && !it.validJumpDests[targetPC] {
		return nil, fmt.Errorf("invalid jumpdest 0x%x", targetPC)
	}
	existed := false
	nb := it.cfg.pcToBlock[targetPC]
	if nb != nil {
		existed = true
	}
	if nb == nil {
		nb = it.cfg.getOrCreateBlock(targetPC)
	}
	// If we discover a new basic block target at runtime, treat this CFG as dynamic/mutable.
	// This is a correctness signal for caching layers: path-dependent runtime expansion and
	// incoming snapshots must not be shared globally across unrelated executions.
	if it.cfg != nil && (!existed || (from != nil && from.unresolvedJump)) {
		it.cfg.runtimeBecameDynamic = true
	}
	if it.resolveHook != nil {
		fromPC := uint(0)
		if from != nil {
			fromPC = from.FirstPC()
		}
		it.resolveHook(fromPC, it.curEvmPC, targetPC, nb.FirstPC(), existed)
	}
	// Record incoming stack snapshot for PHI evaluation.
	if from != nil {
		// Avoid repeated allocation-heavy snapshotting for already-recorded stable edges.
		need := true
		if existed && nb != nil && nb.incomingStacks != nil {
			if _, ok := nb.incomingStacks[from]; ok && nb.entryStack != nil {
				need = false
			}
		}
		if need {
			snap := it.computeExitSnapshotForEdgeTo(prev, from, nb)
			// For dynamic control-flow edges, prefer a concrete runtime snapshot (materialized) to avoid
			// leaking symbolic/stale defs across rebuilds. Materialize enough of the stack to cover
			// common ABI/dispatcher patterns (often > 16 deep) without always paying full cost.
			if it.cfg != nil && it.cfg.runtimeEpoch != 0 && (from.unresolvedJump || nb.unresolvedJump || it.cfg.runtimeBecameDynamic) && snap != nil {
				// Avoid materializing back-edges, backward jumps into dispatchers, and
				// loop-exit edges. Materialization can freeze iteration-dependent values
				// (SLOAD etc.) into constants and poison the cached CFG.
				if !from.IsInLoop && !(nb.IsLoopHeader && nb.IsBackEdgeFrom(from)) {
					k := 64
					if len(snap) < k {
						k = len(snap)
					}
					snap = it.materializeSnapshotTopK(snap, k)
				}
			}
			it.cfg.connectEdge(from, nb, snap)
		}
	}
	return nb, nil
}

// materializeSnapshotTopK materializes only the top K stack elements (top-of-stack is at the end
// of the slice). This is a correctness/perf compromise for dynamic CFG backfill: it makes control-
// flow sensitive values concrete (jump tables / dispatch) without paying to materialize the entire
// stack snapshot.
func (it *MIRInterpreter) materializeSnapshotTopK(in []Value, k int) []Value {
	if it == nil || len(in) == 0 || k <= 0 {
		return in
	}
	out := make([]Value, len(in))
	copy(out, in)
	start := len(out) - k
	if start < 0 {
		start = 0
	}
	for i := start; i < len(out); i++ {
		v := out[i]
		if v.kind == Konst {
			continue
		}
		// Avoid materializing PHIs into constants: PHI selection is edge-dependent and forcing a
		// concrete value here can bake the wrong path's value into downstream blocks.
		// Keeping the PHI symbolic lets evalOperand fetch the correct runtime result.
		if v.kind == Variable && v.def != nil && v.def.op == MirPHI {
			continue
		}
		u, err := it.evalValue(&v)
		if err != nil || u == nil {
			v.liveIn = true
			out[i] = v
			continue
		}
		cv := newConstValueFromU(u)
		cv.liveIn = true
		cv.liveInPos = -1
		out[i] = *cv
	}
	return out
}

// materializeSnapshot converts a symbolic stack snapshot into a constant snapshot by evaluating
// each element to its current runtime value. This is intended for tricky dynamic CFG cases such
// as self-loops where symbolic defs cannot be safely used as loop-carried values.
func (it *MIRInterpreter) materializeSnapshot(in []Value) []Value {
	if it == nil || len(in) == 0 {
		return in
	}
	out := make([]Value, len(in))
	for i := range in {
		v := in[i]
		// Preserve constants as-is.
		if v.kind == Konst {
			out[i] = v
			continue
		}
		u, err := it.evalValue(&v)
		if err != nil || u == nil {
			// If we can't evaluate (e.g. missing result for a def), preserve the symbolic value
			// instead of forcing it to 0, which can silently corrupt loop-carried semantics.
			v.liveIn = true
			out[i] = v
			continue
		}
		// Store as a constant (big-endian) so evalValue is O(1) next time.
		payload := u.Bytes()
		out[i] = Value{kind: Konst, payload: payload, u: uint256.NewInt(0).SetBytes(payload), liveIn: true}
	}
	return out
}

func (it *MIRInterpreter) ensureMem(n int) {
	if n <= 0 {
		return
	}
	// EVM memory expands in 32-byte words. Keep len(mem) word-aligned so MSIZE matches geth.
	want := ((n + 31) / 32) * 32
	if len(it.mem) >= want {
		return
	}
	// Grow to want, reusing capacity when possible.
	//
	// IMPORTANT: We must zero the newly-exposed bytes. Geth achieves this by appending a
	// freshly zeroed slice. Do the same here; this avoids repeated allocations for small
	// expansions in tight loops and is a major perf win for ABI-return heavy paths.
	if cap(it.mem) >= want {
		extra := want - len(it.mem)
		it.mem = append(it.mem, make([]byte, extra)...)
		return
	}
	// Allocate a fresh buffer sized to want (zeroed), and copy existing content.
	newMem := make([]byte, want)
	copy(newMem, it.mem)
	it.mem = newMem
}

func (it *MIRInterpreter) finishResult(r ExecResult) ExecResult {
	r.LastEVMPC = it.lastEvmPC
	// Apply tx-level refund cap once, on normal halts.
	if it.applyRefundCapInFinish && !it.refundApplied && r.Err == nil {
		switch r.HaltOp {
		case MirSTOP, MirRETURN, MirREVERT, MirSELFDESTRUCT:
			r.RefundUsed = it.applyRefundCap()
			it.refundApplied = true
		}
	}
	// If the error is not a known EVM semantic error and not already tagged as
	// ErrMIRInternal, wrap it so the runner can detect MIR-specific failures
	// and fall back to the stock EVM (instead of consuming all gas silently).
	if r.Err != nil && !isEVMSemanticError(r.Err) && !errors.Is(r.Err, ErrMIRInternal) {
		r.Err = fmt.Errorf("%w: %v", ErrMIRInternal, r.Err)
	}
	// Fatal errors consume all gas, matching geth (except REVERT which keeps gas-left).
	if r.Err != nil && !errors.Is(r.Err, vm.ErrExecutionReverted) && it.gasLimit > 0 {
		it.gasUsed = it.gasLimit
	}
	r.GasUsed = it.gasUsed
	if it.gasLimit > 0 {
		if it.gasUsed >= it.gasLimit {
			r.GasLeft = 0
		} else {
			r.GasLeft = it.gasLimit - it.gasUsed
		}
	}
	return r
}

// isEVMSemanticError returns true if err is a legitimate EVM execution error
// (not an MIR internal failure). These errors should propagate normally and
// not trigger a fallback to the stock EVM interpreter.
func isEVMSemanticError(err error) bool {
	if errors.Is(err, vm.ErrOutOfGas) ||
		errors.Is(err, vm.ErrExecutionReverted) ||
		errors.Is(err, vm.ErrWriteProtection) ||
		errors.Is(err, vm.ErrReturnDataOutOfBounds) ||
		errors.Is(err, vm.ErrGasUintOverflow) ||
		errors.Is(err, vm.ErrInvalidJump) {
		return true
	}
	// ErrStackOverflow/ErrStackUnderflow are struct types, not sentinel values.
	var sof *vm.ErrStackOverflow
	var suf *vm.ErrStackUnderflow
	if errors.As(err, &sof) || errors.As(err, &suf) {
		return true
	}
	return false
}

func (it *MIRInterpreter) applyRefundCap() uint64 {
	if it.gasLimit == 0 || it.state == nil {
		return 0
	}
	refund := it.state.GetRefund()
	if refund == 0 {
		return 0
	}
	quot := params.RefundQuotient
	if it.chainRules.IsLondon {
		quot = params.RefundQuotientEIP3529
	}
	cap := it.gasUsed / quot
	if refund > cap {
		refund = cap
	}
	// Apply by decreasing used gas.
	if refund >= it.gasUsed {
		it.gasUsed = 0
		return refund
	}
	it.gasUsed -= refund
	return refund
}

func (it *MIRInterpreter) chargeSelfdestructDynamicGas(beneficiary common.Address) error {
	if it.state == nil {
		return nil
	}
	var gas uint64
	// Base cost introduced by EIP-150 (5000 gas, params.SelfdestructGasEIP150).
	//
	// Geth charges this differently across forks:
	//   Pre-EIP2929:  constantGas = 0; gasSelfdestruct() charges 5000 as its first item.
	//   Post-EIP2929: enable2929 sets constantGas = 5000; gasSelfdestructEIP2929 no longer
	//                 includes the 5000 (only the EIP-2929 cold-access delta).
	//
	// MIR charges constantGas via blockConstDelta (using ConstantGasForOp, which reads the
	// same jump table), so:
	//   Pre-EIP2929:  constantGas = 0 → we must add 5000 here.
	//   Post-EIP2929: constantGas = 5000 already charged → adding it here would double-count.
	if it.chainRules.IsEIP150 && !it.chainRules.IsEIP2929 {
		gas += params.SelfdestructGasEIP150
	}
	// EIP-2929: cold account access cost if beneficiary not warm.
	if it.chainRules.IsEIP2929 && !it.state.AddressInAccessList(beneficiary) {
		it.state.AddAddressToAccessList(beneficiary)
		gas += params.ColdAccountAccessCostEIP2929
	}
	// EIP150+ create-by-selfdestruct cost if beneficiary empty and we transfer value.
	if it.chainRules.IsEIP150 {
		bal := it.state.GetBalanceU256(it.contractAddr)
		transfers := bal != nil && !bal.IsZero()
		if transfers {
			if it.chainRules.IsEIP158 {
				if it.state.Empty(beneficiary) {
					gas += params.CreateBySelfdestructGas
				}
			} else if !it.state.Exists(beneficiary) {
				gas += params.CreateBySelfdestructGas
			}
		}
	}
	// Refunds: removed by EIP-3529 (London+)
	if !it.chainRules.IsLondon && !it.state.HasSelfDestructed(it.contractAddr) {
		it.state.AddRefund(params.SelfdestructRefundGas)
	}
	return it.chargeGas(gas)
}

func (it *MIRInterpreter) execSelfdestruct(beneficiary common.Address) {
	if it.state == nil {
		return
	}
	bal := it.state.GetBalanceU256(it.contractAddr)
	if it.chainRules.IsCancun {
		// EIP-6780: SELFDESTRUCT only actually destructs if the contract was created in the
		// current transaction. In all cases the balance is transferred to the beneficiary.
		// Use SubBalance + AddBalance to match stock EVM (opSelfdestruct6780) balance tracing.
		if bal != nil && !bal.IsZero() {
			it.state.SubBalanceU256(it.contractAddr, bal)
			it.state.AddBalanceU256(beneficiary, bal)
		}
		it.state.SelfDestruct6780(it.contractAddr)
	} else {
		// Pre-Cancun: always destruct and transfer balance.
		if bal != nil && !bal.IsZero() {
			it.state.AddBalanceU256(beneficiary, bal)
			it.state.SetBalanceU256(it.contractAddr, u256Zero)
		}
		it.state.SelfDestruct(it.contractAddr)
	}
}

func (it *MIRInterpreter) chargeGas(amount uint64) error {
	if amount == 0 {
		return nil
	}
	// overflow safe add
	if it.gasUsed > ^uint64(0)-amount {
		return vm.ErrGasUintOverflow
	}
	it.gasUsed += amount
	if it.gasLimit > 0 && it.gasUsed > it.gasLimit {
		return vm.ErrOutOfGas
	}
	return nil
}

func (it *MIRInterpreter) refundGas(amount uint64) {
	if amount == 0 {
		return
	}
	// Only meaningful when gasLimit is set. If unset, we treat gas as "infinite"
	// and keep GasUsed as a monotonic counter.
	if it.gasLimit == 0 {
		return
	}
	if amount >= it.gasUsed {
		it.gasUsed = 0
		return
	}
	it.gasUsed -= amount
}

func (it *MIRInterpreter) chargeBlockConstantGas(b *MIRBasicBlock) error {
	if b == nil {
		return nil
	}
	// Deprecated: block-entry constant gas precharge breaks CALL gas forwarding semantics.
	// Constant gas is now charged incrementally per MIR op via chargeConstGasForMIR.
	return nil
}

// toWordSize matches geth's toWordSize: ceil(size/32).
func toWordSize(size uint64) uint64 {
	if size > 0 {
		return (size + 31) / 32
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// chargeMemoryExpansion charges the quadratic memory expansion gas for accessing
// memory region [offset, offset+size).
func (it *MIRInterpreter) chargeMemoryExpansion(offset, size *uint256.Int) error {
	if offset == nil || size == nil {
		return nil
	}
	// Match stock EVM (calcMemSize64): check size==0 FIRST, before any offset checks.
	// When size is zero, no memory expansion is needed regardless of offset value.
	// This is critical: stock EVM returns (0, false) for size==0 even if offset overflows uint64.
	if size.IsZero() {
		return nil
	}

	// Fast no-expansion path: if the accessed range is already within current memory size,
	// we can return without any word-size rounding or quadratic fee math.
	memLen := uint64(len(it.mem))
	if memLen != 0 && offset.BitLen() <= 64 && size.BitLen() <= 64 {
		off := offset.Uint64()
		sz := size.Uint64()
		end := off + sz
		if end < off {
			// Overflow in fast path: stock EVM → ErrGasUintOverflow → OOG.
			it.gasUsed = it.gasLimit
			return nil
		}
		if end <= memLen {
			return nil
		}
	}

	// Slow path: convert to uint64, checking for overflow.
	var off, sz uint64
	if offset.BitLen() <= 64 {
		off = offset.Uint64()
	} else {
		var offOverflow bool
		off, offOverflow = offset.Uint64WithOverflow()
		if offOverflow {
			// Stock EVM: offset overflow → ErrGasUintOverflow → OOG. Consume all gas.
			it.gasUsed = it.gasLimit
			return nil
		}
	}
	if size.BitLen() <= 64 {
		sz = size.Uint64()
	} else {
		var szOverflow bool
		sz, szOverflow = size.Uint64WithOverflow()
		if szOverflow {
			// Stock EVM: size overflow → ErrGasUintOverflow → OOG. Consume all gas.
			it.gasUsed = it.gasLimit
			return nil
		}
	}
	newSize := off + sz
	// Mirror vm.memoryGasCost logic, but with our own last-fee tracking.
	if newSize == 0 {
		return nil
	}
	if newSize > 0x1FFFFFFFE0 {
		it.gasUsed = it.gasLimit
		return nil
	}
	newWords := toWordSize(newSize)
	newSizeRounded := newWords * 32
	if newSizeRounded > uint64(len(it.mem)) {
		square := newWords * newWords
		lin := newWords * params.MemoryGas
		quad := square / params.QuadCoeffDiv
		newTotalFee := lin + quad
		fee := newTotalFee - it.memLastGasFee
		it.memLastGasFee = newTotalFee
		return it.chargeGas(fee)
	}
	return nil
}

func (it *MIRInterpreter) chargeKeccakDynamicGas(offset, size *uint256.Int) error {
	// Memory expansion part
	if err := it.chargeMemoryExpansion(offset, size); err != nil {
		return err
	}
	if size == nil {
		return nil
	}
	var sz uint64
	if size.BitLen() <= 64 {
		sz = size.Uint64()
	} else {
		var overflow bool
		sz, overflow = size.Uint64WithOverflow()
		if overflow {
			return errors.New("keccak size overflow")
		}
	}
	words := toWordSize(sz)
	wordGas := words * params.Keccak256WordGas
	// overflow check
	if words != 0 && wordGas/words != params.Keccak256WordGas {
		return errors.New("gas uint64 overflow")
	}
	return it.chargeGas(wordGas)
}

func (it *MIRInterpreter) chargeExpDynamicGas(m *MIR) error {
	// EXP dynamic gas depends on exponent byte-size (stack operand 1).
	if m == nil {
		return nil
	}
	exp, err := it.evalOperand(m, 1)
	if err != nil {
		return err
	}
	// bytes = (bitlen+7)/8. uint256.Int has BitLen().
	bits := exp.BitLen()
	var bytes uint64
	if bits > 0 {
		bytes = uint64((bits + 7) / 8)
	}
	// Fork-dependent ExpByte cost (EIP-158 repricing).
	expByteGas := params.ExpByteFrontier
	if it.chainRules.IsEIP158 {
		expByteGas = params.ExpByteEIP158
	}
	dyn := bytes * expByteGas
	if bytes != 0 && dyn/bytes != expByteGas {
		return errors.New("gas uint64 overflow")
	}
	// EXP base cost handling:
	// - Some jump tables encode params.ExpGas in the opcode's constantGas.
	// - Others encode it in the dynamic gas function.
	// MIR charges block-constant gas via ConstantGasForOp, so we add ExpGas here only
	// when the constantGas for EXP is 0 for the active ruleset.
	base := uint64(0)
	if c, ok := vm.ConstantGasForOp(it.chainRules, vm.EXP); ok && c == 0 {
		base = params.ExpGas
	}
	total := base + dyn
	if total < dyn {
		return errors.New("gas uint64 overflow")
	}
	return it.chargeGas(total)
}

func (it *MIRInterpreter) chargeCopyGas(size *uint256.Int) error {
	if size == nil {
		return nil
	}
	var sz uint64
	if size.BitLen() <= 64 {
		sz = size.Uint64()
	} else {
		var overflow bool
		sz, overflow = size.Uint64WithOverflow()
		if overflow {
			return errors.New("copy size overflow")
		}
	}
	words := toWordSize(sz)
	wordGas := words * params.CopyGas
	if words != 0 && wordGas/words != params.CopyGas {
		return errors.New("gas uint64 overflow")
	}
	return it.chargeGas(wordGas)
}

func (it *MIRInterpreter) chargeMemoryExpansionMax(endSize uint64) error {
	// Charge expansion to endSize bytes.
	if endSize == 0 {
		return nil
	}
	if endSize > 0x1FFFFFFFE0 {
		return errors.New("memory expansion overflow")
	}
	newWords := toWordSize(endSize)
	newSizeRounded := newWords * 32
	if newSizeRounded > uint64(len(it.mem)) {
		square := newWords * newWords
		lin := newWords * params.MemoryGas
		quad := square / params.QuadCoeffDiv
		newTotalFee := lin + quad
		fee := newTotalFee - it.memLastGasFee
		it.memLastGasFee = newTotalFee
		return it.chargeGas(fee)
	}
	return nil
}

func (it *MIRInterpreter) chargeMcopyDynamicGas(dst, src, size *uint256.Int) error {
	if dst == nil || src == nil || size == nil {
		return nil
	}
	d, dOv := dst.Uint64WithOverflow()
	s, sOv := src.Uint64WithOverflow()
	n, nOv := size.Uint64WithOverflow()
	if dOv || sOv || nOv {
		return errors.New("mcopy operand overflow")
	}
	// memorySize := max(dst+size, src+size)
	end1 := d + n
	if end1 < d {
		return errors.New("mcopy dst+size overflow")
	}
	end2 := s + n
	if end2 < s {
		return errors.New("mcopy src+size overflow")
	}
	if end2 > end1 {
		end1 = end2
	}
	if err := it.chargeMemoryExpansionMax(end1); err != nil {
		return err
	}
	return it.chargeCopyGas(size)
}

func (it *MIRInterpreter) chargeLogDynamicGas(m *MIR) error {
	if m == nil {
		return nil
	}
	// Operands: dataOffset, dataSize, topic1..topicN (N = LOGx - LOG0)
	if len(m.operands) < 2 {
		return errors.New("bad LOG operands")
	}
	off, err := it.evalOperand(m, 0)
	if err != nil {
		return err
	}
	sz, err := it.evalOperand(m, 1)
	if err != nil {
		return err
	}
	if err := it.chargeMemoryExpansion(off, sz); err != nil {
		return err
	}
	// NOTE: In geth, LOGx charges ALL of the following in the dynamic gas function
	// (see vm.makeGasLog):
	// - params.LogGas (base)
	// - params.LogTopicGas * numTopics
	// - params.LogDataGas * dataSize
	// plus memory expansion.
	// The jump table constant gas for LOGx is 0.

	// + LogGas base
	if err := it.chargeGas(params.LogGas); err != nil {
		return err
	}
	// + topics
	numTopics := uint64(m.op - MirLOG0)
	topicsGas := numTopics * params.LogTopicGas
	if numTopics != 0 && topicsGas/numTopics != params.LogTopicGas {
		return errors.New("gas uint64 overflow")
	}
	if err := it.chargeGas(topicsGas); err != nil {
		return err
	}
	dataSz, overflow := sz.Uint64WithOverflow()
	if overflow {
		return errors.New("log data size overflow")
	}
	dataGas := dataSz * params.LogDataGas
	if dataSz != 0 && dataGas/dataSz != params.LogDataGas {
		return errors.New("gas uint64 overflow")
	}
	return it.chargeGas(dataGas)
}

func (it *MIRInterpreter) memCopyFromBytes(dest, off, size *uint256.Int, src []byte) {
	if dest == nil || off == nil || size == nil {
		return
	}
	d, dOv := dest.Uint64WithOverflow()
	o, oOv := off.Uint64WithOverflow()
	n, nOv := size.Uint64WithOverflow()
	if dOv || oOv || nOv {
		return
	}
	if n == 0 {
		return
	}
	di := int(d)
	oi := int(o)
	ni := int(n)
	it.ensureMem(di + ni)
	if ni <= 0 {
		return
	}
	// Copy src[oi:oi+ni] into mem[di:di+ni], zero-padding if out of bounds.
	if oi < 0 {
		zeroPrefix := -oi
		if zeroPrefix > ni {
			zeroPrefix = ni
		}
		for i := range it.mem[di : di+zeroPrefix] {
			it.mem[di+i] = 0
		}
		di += zeroPrefix
		ni -= zeroPrefix
		oi = 0
		if ni == 0 {
			return
		}
	}
	avail := len(src) - oi
	if avail < 0 {
		avail = 0
	}
	cn := ni
	if cn > avail {
		cn = avail
	}
	if cn > 0 {
		copy(it.mem[di:di+cn], src[oi:oi+cn])
	}
	if cn < ni {
		for i := range it.mem[di+cn : di+ni] {
			it.mem[di+cn+i] = 0
		}
	}
}

func (it *MIRInterpreter) memSetFromBytes(dest, size *uint256.Int, src []byte) {
	if dest == nil || size == nil {
		return
	}
	d, dOv := dest.Uint64WithOverflow()
	n, nOv := size.Uint64WithOverflow()
	if dOv || nOv {
		return
	}
	if n == 0 {
		return
	}
	di := int(d)
	ni := int(n)
	it.ensureMem(di + ni)
	if ni <= 0 {
		return
	}
	// Copy what we have and zero the rest (matches EVM semantics).
	cn := ni
	if cn > len(src) {
		cn = len(src)
	}
	if cn > 0 {
		copy(it.mem[di:di+cn], src[:cn])
	}
	if cn < ni {
		for i := range it.mem[di+cn : di+ni] {
			it.mem[di+cn+i] = 0
		}
	}
}

func (it *MIRInterpreter) execCallLike(m *MIR) (uint64, error) {
	if m == nil {
		return 0, errors.New("nil call mir")
	}
	// MIR operands encoding (from opcodeParser):
	// CALL/CALLCODE: [gas, to, value, inOff, inSize, outOff, outSize]
	// DELEGATECALL/STATICCALL: [gas, to, inOff, inSize, outOff, outSize]
	switch m.op {
	case MirCALL, MirCALLCODE:
		if len(m.operands) != 7 {
			return 0, errors.New("bad CALL operands")
		}
		gReq, err := it.evalOperand(m, 0)
		if err != nil {
			return 0, err
		}
		to, err := it.evalAddressOperand(m, 1)
		if err != nil {
			return 0, err
		}
		val, err := it.evalOperand(m, 2)
		if err != nil {
			return 0, err
		}
		inOff, _ := it.evalOperand(m, 3)
		inSz, _ := it.evalOperand(m, 4)
		outOff, _ := it.evalOperand(m, 5)
		outSz, _ := it.evalOperand(m, 6)
		return it.doCall(m.op, gReq, to, val, inOff, inSz, outOff, outSz)
	case MirDELEGATECALL, MirSTATICCALL:
		if len(m.operands) != 6 {
			return 0, errors.New("bad (DELEGATE|STATIC)CALL operands")
		}
		gReq, err := it.evalOperand(m, 0)
		if err != nil {
			return 0, err
		}
		to, err := it.evalAddressOperand(m, 1)
		if err != nil {
			return 0, err
		}
		inOff, _ := it.evalOperand(m, 2)
		inSz, _ := it.evalOperand(m, 3)
		outOff, _ := it.evalOperand(m, 4)
		outSz, _ := it.evalOperand(m, 5)
		if it.debugCallArgsHook != nil && gReq != nil && inOff != nil && inSz != nil && outOff != nil && outSz != nil {
			_, inOffOv := inOff.Uint64WithOverflow()
			_, inSzOv := inSz.Uint64WithOverflow()
			_, outOffOv := outOff.Uint64WithOverflow()
			_, outSzOv := outSz.Uint64WithOverflow()

			defPC := func(i int) uint {
				if i < 0 || i >= len(m.operands) {
					return 0
				}
				v := m.operands[i]
				if v == nil || v.def == nil {
					return 0
				}
				return v.def.evmPC
			}
			defOp := func(i int) MirOperation {
				if i < 0 || i >= len(m.operands) {
					return 0
				}
				v := m.operands[i]
				if v == nil || v.def == nil {
					return 0
				}
				return v.def.op
			}
			it.debugCallArgsHook(m.evmPC, m.evmOp, m.op, *gReq, to,
				*inOff, defPC(2), defOp(2),
				*inSz, defPC(3), defOp(3),
				*outOff, defPC(4), defOp(4),
				*outSz, defPC(5), defOp(5),
				inOffOv, inSzOv, outOffOv, outSzOv)
		}
		// delegate/static have no value operand on stack; use current callValue for delegate.
		val := u256Zero
		if m.op == MirDELEGATECALL && it.callValue != nil {
			val = it.callValue
		}
		return it.doCall(m.op, gReq, to, val, inOff, inSz, outOff, outSz)
	default:
		return 0, fmt.Errorf("not a call-like op: %s", m.op.String())
	}
}

func (it *MIRInterpreter) doCall(op MirOperation, gasReq *uint256.Int, to common.Address, value, inOff, inSz, outOff, outSz *uint256.Int) (uint64, error) {
	// STATICCALL context: CALL with non-zero value is forbidden (writes state).
	if it.readOnly && value != nil && !value.IsZero() {
		return 0, vm.ErrWriteProtection
	}
	doCallDebug := mirDebugBlock != 0 && it.blockNumber == mirDebugBlock
	gasAtEntry := it.gasUsed
	if doCallDebug {
		log.Warn("MIR doCall entry", "op", op, "to", to, "gasUsed", gasAtEntry, "gasLeft", it.gasLeft())
	}
	// Memory expansion: stock EVM (memory_table.go memoryCall) takes max(inEnd, outEnd).
	// Two sequential chargeMemoryExpansion calls are INCORRECT here: the first call
	// advances memLastGasFee; if the second region is smaller and len(it.mem) has not
	// yet been extended (ensureMem runs later), the second call computes
	// newTotalFee - memLastGasFee where newTotalFee < memLastGasFee → uint64 underflow
	// → chargeGas receives a huge value → spurious "gas uint64 overflow" OOG.
	{
		callEnd := func(off, sz *uint256.Int) (uint64, error) {
			if sz == nil || sz.IsZero() {
				return 0, nil
			}
			var o uint64
			if off != nil {
				var ov bool
				o, ov = off.Uint64WithOverflow()
				if ov {
					// Stock EVM: overflow → ErrGasUintOverflow → OOG.
					it.gasUsed = it.gasLimit
					return 0, nil
				}
			}
			s, ov := sz.Uint64WithOverflow()
			if ov {
				it.gasUsed = it.gasLimit
				return 0, nil
			}
			end := o + s
			if end < o {
				it.gasUsed = it.gasLimit
				return 0, nil
			}
			return end, nil
		}
		inEnd, err := callEnd(inOff, inSz)
		if err != nil {
			return 0, err
		}
		outEnd, err := callEnd(outOff, outSz)
		if err != nil {
			return 0, err
		}
		maxEnd := inEnd
		if outEnd > maxEnd {
			maxEnd = outEnd
		}
		if err := it.chargeMemoryExpansionMax(maxEnd); err != nil {
			return 0, err
		}
	}

	if doCallDebug {
		log.Warn("MIR doCall after memExpansion", "gasUsed", it.gasUsed, "memDelta", it.gasUsed-gasAtEntry)
	}
	gasAfterMem := it.gasUsed

	// EIP-2929 warm/cold account access delta for call target
	if err := it.chargeAccountAccessDelta(to); err != nil {
		return 0, err
	}
	if doCallDebug {
		log.Warn("MIR doCall after accessDelta", "gasUsed", it.gasUsed, "accessDelta", it.gasUsed-gasAfterMem)
	}

	// CALL/CALLCODE: new account + value transfer costs
	transfersValue := value != nil && !value.IsZero()
	if (op == MirCALL || op == MirCALLCODE) && transfersValue && it.state != nil {
		if it.chainRules.IsEIP158 {
			if it.state.Empty(to) {
				if err := it.chargeGas(params.CallNewAccountGas); err != nil {
					return 0, err
				}
			}
		} else if !it.state.Exists(to) {
			if err := it.chargeGas(params.CallNewAccountGas); err != nil {
				return 0, err
			}
		}
	}
	if (op == MirCALL || op == MirCALLCODE) && transfersValue && !it.chainRules.IsEIP4762 {
		if err := it.chargeGas(params.CallValueTransferGas); err != nil {
			return 0, err
		}
	}

	// Determine gas to pass to the callee (EIP-150 63/64 cap).
	//
	// Mirror stock EVM callGas() (core/vm/gas.go): when the requested gas does not fit
	// in uint64, it is trivially larger than the 63/64 cap, so we forward the cap
	// instead of returning an error.  Returning an error here causes the entire call to
	// fail and consume all caller gas, diverging from stock EVM which silently caps.
	avail := it.gasLeft()
	if it.chainRules.IsEIP150 {
		avail = avail - avail/64
	}
	var gasToSend uint64
	if gasReq == nil || !gasReq.IsUint64() || gasReq.Uint64() > avail {
		gasToSend = avail
	} else {
		gasToSend = gasReq.Uint64()
	}

	if doCallDebug {
		log.Warn("MIR doCall gasToSend", "avail", avail, "gasToSend", gasToSend, "gasLeft", it.gasLeft())
	}

	// Charge the transferred gas (caller pays it)
	if err := it.chargeGas(gasToSend); err != nil {
		return 0, err
	}

	// CALL stipend: free to callee, not charged to caller
	gasForCallee := gasToSend
	if (op == MirCALL || op == MirCALLCODE) && transfersValue {
		gasForCallee += params.CallStipend
	}

	// Prepare input args from memory
	io := int(inOff.Uint64())
	ins := int(inSz.Uint64())
	if ins < 0 {
		ins = 0
	}
	it.ensureMem(io + ins)
	args := make([]byte, ins)
	copy(args, it.mem[io:io+ins])

	// Execute via backend
	var (
		ret       []byte
		returnGas uint64
		err       error
	)
	if it.callCreate == nil {
		it.callCreate = NoopCallCreateBackend{}
	}
	switch op {
	case MirCALL:
		ret, returnGas, err = it.callCreate.Call(it.contractAddr, to, args, gasForCallee, value)
	case MirCALLCODE:
		ret, returnGas, err = it.callCreate.CallCode(it.contractAddr, to, args, gasForCallee, value)
	case MirDELEGATECALL:
		ret, returnGas, err = it.callCreate.DelegateCall(it.callerAddr, it.contractAddr, to, args, gasForCallee, it.callValue)
	case MirSTATICCALL:
		ret, returnGas, err = it.callCreate.StaticCall(it.contractAddr, to, args, gasForCallee)
	}

	// Refund unused gas back to caller.
	// Note: geth refunds the leftover gas from the callee call, which includes any
	// CALL stipend that was added to the callee gas.
	if returnGas > gasForCallee {
		returnGas = gasForCallee
	}
	if doCallDebug {
		log.Warn("MIR doCall return", "op", op, "to", to,
			"gasForCallee", gasForCallee, "returnGas", returnGas,
			"gasUsedBeforeRefund", it.gasUsed, "err", err,
			"totalCallCost", it.gasUsed-gasAtEntry)
	}
	it.refundGas(returnGas)

	// returnData is always set
	it.returnData = ret

	// Copy output to memory only on success or revert (matches geth)
	if err == nil || errors.Is(err, vm.ErrExecutionReverted) {
		oo := int(outOff.Uint64())
		outs := int(outSz.Uint64())
		if outs < 0 {
			outs = 0
		}
		it.ensureMem(oo + outs)
		it.memSetFromBytes(outOff, outSz, ret)
	}

	if err != nil {
		return 0, nil
	}
	return 1, nil
}

func (it *MIRInterpreter) execCreateLike(m *MIR, isCreate2 bool) (common.Address, error) {
	if m == nil {
		return common.Address{}, errors.New("nil create mir")
	}
	if !isCreate2 {
		if len(m.operands) != 3 {
			return common.Address{}, errors.New("bad CREATE operands")
		}
	} else {
		if len(m.operands) != 4 {
			return common.Address{}, errors.New("bad CREATE2 operands")
		}
	}
	val, err := it.evalOperand(m, 0)
	if err != nil {
		return common.Address{}, err
	}
	off, err := it.evalOperand(m, 1)
	if err != nil {
		return common.Address{}, err
	}
	sz, err := it.evalOperand(m, 2)
	if err != nil {
		return common.Address{}, err
	}
	// Memory expansion
	if err := it.chargeMemoryExpansion(off, sz); err != nil {
		return common.Address{}, err
	}
	// CREATE2 charges keccak word gas on initcode size
	var salt *uint256.Int
	if isCreate2 {
		s, err := it.evalOperand(m, 3)
		if err != nil {
			return common.Address{}, err
		}
		salt = s
		if err := it.chargeKeccakWordGas(sz); err != nil {
			return common.Address{}, err
		}
	}
	// Gas to send is all remaining (EIP150 cap always applied for CREATE2, conditional for CREATE)
	gasToSend := it.gasLeft()
	if isCreate2 || it.chainRules.IsEIP150 {
		gasToSend -= gasToSend / 64
	}
	if err := it.chargeGas(gasToSend); err != nil {
		return common.Address{}, err
	}
	// initcode bytes from memory
	o := int(off.Uint64())
	n := int(sz.Uint64())
	if n < 0 {
		n = 0
	}
	it.ensureMem(o + n)
	initCode := make([]byte, n)
	copy(initCode, it.mem[o:o+n])

	if it.callCreate == nil {
		it.callCreate = NoopCallCreateBackend{}
	}
	var (
		ret       []byte
		addr      common.Address
		returnGas uint64
		suberr    error
	)
	if !isCreate2 {
		ret, addr, returnGas, suberr = it.callCreate.Create(it.contractAddr, initCode, gasToSend, val)
	} else {
		ret, addr, returnGas, suberr = it.callCreate.Create2(it.contractAddr, initCode, gasToSend, val, salt)
	}
	if returnGas > gasToSend {
		returnGas = gasToSend
	}
	it.refundGas(returnGas)
	if suberr != nil {
		// CREATE pushes 0 on failure
		addr = common.Address{}
	}
	if errors.Is(suberr, vm.ErrExecutionReverted) {
		it.returnData = ret
	} else {
		it.returnData = nil
	}
	return addr, nil
}

func (it *MIRInterpreter) chargeKeccakWordGas(size *uint256.Int) error {
	if size == nil {
		return nil
	}
	sz, overflow := size.Uint64WithOverflow()
	if overflow {
		return errors.New("size overflow")
	}
	words := toWordSize(sz)
	wordGas := words * params.Keccak256WordGas
	if words != 0 && wordGas/words != params.Keccak256WordGas {
		return errors.New("gas uint64 overflow")
	}
	return it.chargeGas(wordGas)
}

func (it *MIRInterpreter) evalAddressOperand(m *MIR, idx int) (common.Address, error) {
	v, err := it.evalOperand(m, idx)
	if err != nil {
		return common.Address{}, err
	}
	return common.Address(v.Bytes20()), nil
}

// chargeAccountAccessDelta charges the EIP-2929 cold/warm delta for account reads.
// Under EIP-2929, the warm cost is already part of constant gas for relevant opcodes,
// so we only add (cold-warm) on first access.
func (it *MIRInterpreter) chargeAccountAccessDelta(addr common.Address) error {
	if !it.chainRules.IsEIP2929 {
		return nil
	}
	// Fast-path: use underlying vm.StateDB if available (saves one interface hop).
	if it.vmStateDB != nil {
		if !it.vmStateDB.AddressInAccessList(addr) {
			it.vmStateDB.AddAddressToAccessList(addr)
			return it.chargeGas(params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929)
		}
		return nil
	}
	if it.state == nil {
		// Pessimistic: charge full cold access (includes warm component),
		// since we can't track "already warm".
		return it.chargeGas(params.ColdAccountAccessCostEIP2929)
	}
	if !it.state.AddressInAccessList(addr) {
		it.state.AddAddressToAccessList(addr)
		return it.chargeGas(params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929)
	}
	return nil
}

func (it *MIRInterpreter) gasLeft() uint64 {
	if it.gasLimit == 0 {
		return ^uint64(0)
	}
	if it.gasUsed >= it.gasLimit {
		return 0
	}
	return it.gasLimit - it.gasUsed
}

func (it *MIRInterpreter) ensureBlockConstPrefix(b *MIRBasicBlock) []uint64 {
	if it == nil || b == nil {
		return nil
	}
	// Ensure const gas table is initialized for current rules. If rules changed, invalidate caches.
	if !it.constGasInit || it.constGasRules != it.chainRules {
		it.rebuildConstGasTable()
		// Cached per-block gas depends on constant schedule; drop and rebuild lazily.
		it.blockConstPrefix = nil
		it.blockConstDelta = nil
		it.blockConstTail = nil
	}
	// Allocate outer table lazily.
	if it.blockConstPrefix == nil {
		// Basic block numbers are dense from 0..basicBlockCount-1.
		n := 0
		if it.cfg != nil {
			n = int(it.cfg.basicBlockCount)
		}
		if n == 0 {
			n = int(b.blockNum) + 1
		}
		it.blockConstPrefix = make([][]uint64, n)
	} else if int(b.blockNum) >= len(it.blockConstPrefix) {
		// Grow defensively (shouldn't happen if cfg.basicBlockCount is set).
		newTab := make([][]uint64, int(b.blockNum)+1)
		copy(newTab, it.blockConstPrefix)
		it.blockConstPrefix = newTab
	}
	if it.blockConstPrefix[b.blockNum] != nil && len(it.blockConstPrefix[b.blockNum]) == len(b.evmOps)+1 {
		return it.blockConstPrefix[b.blockNum]
	}
	pfx := make([]uint64, len(b.evmOps)+1)
	for i := 0; i < len(b.evmOps); i++ { // compute constGas here
		op := b.evmOps[i].op
		pfx[i+1] = pfx[i] + it.constGas[int(op)]
	}
	it.blockConstPrefix[b.blockNum] = pfx
	return pfx
}

func (it *MIRInterpreter) ensureBlockConstDelta(b *MIRBasicBlock) ([]uint64, uint64) {
	if it == nil || b == nil {
		return nil, 0
	}
	// Ensure prefix is built for this block/ruleset.
	pfx := it.curBlockConstPrefix
	if pfx == nil {
		pfx = it.ensureBlockConstPrefix(b)
		it.curBlockConstPrefix = pfx
	}
	if pfx == nil || len(pfx) == 0 {
		return nil, 0
	}
	// Allocate outer tables lazily.
	if it.blockConstDelta == nil || it.blockConstTail == nil {
		n := 0
		if it.cfg != nil {
			n = int(it.cfg.basicBlockCount)
		}
		if n == 0 {
			n = int(b.blockNum) + 1
		}
		it.blockConstDelta = make([][]uint64, n)
		it.blockConstTail = make([]uint64, n)
	} else if int(b.blockNum) >= len(it.blockConstDelta) {
		need := int(b.blockNum) + 1
		newD := make([][]uint64, need)
		copy(newD, it.blockConstDelta)
		it.blockConstDelta = newD
		newT := make([]uint64, need)
		copy(newT, it.blockConstTail)
		it.blockConstTail = newT
	}
	// Recompute if missing or length mismatch (block rebuild can change instruction count).
	if it.blockConstDelta[b.blockNum] == nil || len(it.blockConstDelta[b.blockNum]) != len(b.instructions) {
		d := make([]uint64, len(b.instructions))
		last := -1
		for i, m := range b.instructions {
			if m == nil {
				continue
			}
			idx := m.evmOpIndex
			if idx < 0 {
				// Fallback (should be rare): resolve via map.
				if b.evmPCToOpIndex != nil {
					if v, ok := b.evmPCToOpIndex[m.evmPC]; ok {
						idx = v
					}
				}
			}
			if idx < 0 {
				continue
			}
			if idx+1 >= len(pfx) {
				continue
			}
			// Charge from last+1 .. idx inclusive.
			d[i] = pfx[idx+1] - pfx[last+1]
			last = idx
		}
		// Tail gas (if block ends without explicit terminator MIR).
		tail := uint64(0)
		if last+1 < len(pfx) {
			tail = pfx[len(pfx)-1] - pfx[last+1]
		}
		it.blockConstDelta[b.blockNum] = d
		it.blockConstTail[b.blockNum] = tail
	}
	return it.blockConstDelta[b.blockNum], it.blockConstTail[b.blockNum]
}

// gasLeftEffective returns the gas remaining *as observed by the currently executing EVM opcode*,
// i.e. after paying the current opcode's cost but before paying costs of future opcodes.
// With incremental constant-gas charging, this equals gasLeft().
func (it *MIRInterpreter) gasLeftEffective() uint64 {
	return it.gasLeft()
}

func (it *MIRInterpreter) chargeConstGasForMIR(b *MIRBasicBlock, m *MIR) error {
	if it == nil || b == nil || m == nil {
		return nil
	}
	deltas, _ := it.ensureBlockConstDelta(b)
	if deltas == nil || m.idx < 0 || m.idx >= len(deltas) {
		return nil
	}
	delta := deltas[m.idx]
	if delta == 0 {
		return nil
	}
	return it.chargeGas(delta)
}

func (it *MIRInterpreter) chargeConstGasToEndOfBlock(b *MIRBasicBlock) error {
	if it == nil || b == nil {
		return nil
	}
	_, tail := it.ensureBlockConstDelta(b)
	delta := tail
	if delta == 0 {
		return nil
	}
	return it.chargeGas(delta)
}

func (it *MIRInterpreter) chargeSLoadGas(slot common.Hash) error {
	// Pre-Berlin SLOAD is covered by constant gas schedule.
	if !it.chainRules.IsEIP2929 {
		return nil
	}
	// Fast-path: use underlying vm.StateDB if available (saves one interface hop).
	if it.vmStateDB != nil {
		_, slotPresent := it.vmStateDB.SlotInAccessList(it.contractAddr, slot)
		if !slotPresent {
			it.vmStateDB.AddSlotToAccessList(it.contractAddr, slot)
			return it.chargeGas(params.ColdSloadCostEIP2929)
		}
		return it.chargeGas(params.WarmStorageReadCostEIP2929)
	}
	if it.state == nil {
		// Without access list, pessimistically assume cold.
		return it.chargeGas(params.ColdSloadCostEIP2929)
	}
	_, slotPresent := it.state.SlotInAccessList(it.contractAddr, slot)
	if !slotPresent {
		it.state.AddSlotToAccessList(it.contractAddr, slot)
		return it.chargeGas(params.ColdSloadCostEIP2929)
	}
	return it.chargeGas(params.WarmStorageReadCostEIP2929)
}

func (it *MIRInterpreter) chargeSStoreGas(slot common.Hash, newVal common.Hash) error {
	// Legacy rules apply only before Constantinople (pre EIP-1283/EIP-2200 era).
	// NOTE: Petersburg does NOT imply legacy rules. Post-Istanbul networks use EIP-2200/2929/3529.
	if !it.chainRules.IsConstantinople {
		if it.state == nil {
			// No state: assume worst-case set.
			return it.chargeGas(params.SstoreSetGas)
		}
		current := it.state.GetState(it.contractAddr, slot)
		switch {
		case current == (common.Hash{}) && newVal != (common.Hash{}): // 0 => non 0
			return it.chargeGas(params.SstoreSetGas)
		case current != (common.Hash{}) && newVal == (common.Hash{}): // non 0 => 0
			it.state.AddRefund(params.SstoreRefundGas)
			return it.chargeGas(params.SstoreClearGas)
		default:
			return it.chargeGas(params.SstoreResetGas)
		}
	}
	// EIP-2929/3529 path (Berlin+): use the modified EIP-2200 rules with warm/cold access list.
	if it.chainRules.IsEIP2929 {
		clearingRefund := params.SstoreClearsScheduleRefundEIP2200
		if it.chainRules.IsLondon {
			clearingRefund = params.SstoreClearsScheduleRefundEIP3529
		}
		return it.chargeSStoreEIP2929(slot, newVal, clearingRefund)
	}
	// EIP-2200 (Constantinople, non-Petersburg): net-metered SSTORE.
	return it.chargeSStoreEIP2200(slot, newVal)
}

func (it *MIRInterpreter) chargeSStoreEIP2200(slot common.Hash, newVal common.Hash) error {
	// EIP-2200 rule (0): if gasleft <= 2300, fail the current call.
	if it.gasLimit > 0 && it.gasLeft() <= params.SstoreSentryGasEIP2200 {
		return errors.New("not enough gas for reentrancy sentry")
	}
	if it.state == nil {
		return errors.New("no state backend for SSTORE EIP-2200")
	}
	current := it.state.GetState(it.contractAddr, slot)
	if current == newVal { // noop (1)
		return it.chargeGas(params.SloadGasEIP2200)
	}
	original := it.state.GetCommittedState(it.contractAddr, slot)
	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return it.chargeGas(params.SstoreSetGasEIP2200)
		}
		if newVal == (common.Hash{}) { // delete slot (2.1.2b)
			it.state.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
		return it.chargeGas(params.SstoreResetGasEIP2200) // write existing slot (2.1.2)
	}
	// dirty update (2.2)
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			it.state.SubRefund(params.SstoreClearsScheduleRefundEIP2200)
		} else if newVal == (common.Hash{}) { // delete slot (2.2.1.2)
			it.state.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
	}
	if original == newVal {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			it.state.AddRefund(params.SstoreSetGasEIP2200 - params.SloadGasEIP2200)
		} else { // reset to original existing slot (2.2.2.2)
			it.state.AddRefund(params.SstoreResetGasEIP2200 - params.SloadGasEIP2200)
		}
	}
	return it.chargeGas(params.SloadGasEIP2200)
}

func (it *MIRInterpreter) chargeSStoreEIP2929(slot common.Hash, newVal common.Hash, clearingRefund uint64) error {
	// Mirrors vm.makeGasSStoreFunc + EIP-2929 modifications.
	if it.gasLimit > 0 && it.gasLeft() <= params.SstoreSentryGasEIP2200 {
		return errors.New("not enough gas for reentrancy sentry")
	}
	if it.state == nil {
		return errors.New("no state backend for SSTORE EIP-2929")
	}
	cost := uint64(0)
	_, slotPresent := it.state.SlotInAccessList(it.contractAddr, slot)
	if !slotPresent {
		cost = params.ColdSloadCostEIP2929
		it.state.AddSlotToAccessList(it.contractAddr, slot)
	}
	current := it.state.GetState(it.contractAddr, slot)
	if current == newVal { // noop (1)
		return it.chargeGas(cost + params.WarmStorageReadCostEIP2929)
	}
	original := it.state.GetCommittedState(it.contractAddr, slot)
	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return it.chargeGas(cost + params.SstoreSetGasEIP2200)
		}
		if newVal == (common.Hash{}) { // delete slot (2.1.2b)
			it.state.AddRefund(clearingRefund)
		}
		// write existing slot (2.1.2): SSTORE_RESET_GAS redefined as (5000 - COLD_SLOAD_COST)
		return it.chargeGas(cost + (params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929))
	}
	// dirty update (2.2)
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			it.state.SubRefund(clearingRefund)
		} else if newVal == (common.Hash{}) { // delete slot (2.2.1.2)
			it.state.AddRefund(clearingRefund)
		}
	}
	if original == newVal {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			it.state.AddRefund(params.SstoreSetGasEIP2200 - params.WarmStorageReadCostEIP2929)
		} else { // reset to original existing slot (2.2.2.2)
			it.state.AddRefund((params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929) - params.WarmStorageReadCostEIP2929)
		}
	}
	return it.chargeGas(cost + params.WarmStorageReadCostEIP2929)
}

func (it *MIRInterpreter) evalPhi(cur, prev *MIRBasicBlock, phi *MIR) (result *uint256.Int, retErr error) {
	// phiPath tags which branch of evalPhi produced the result. Logged when it.tracePhi
	// is on so an operator can see exactly which fallback path a divergent PHI took:
	//   1 = step 1 operand-by-predecessor success
	//   2 = step 2 incoming-stack snapshot (direct value)
	//   3 = step 2 loop-carried via getResult
	//   4 = step 2 loop-carried via defKeyToResIdx
	//   5 = step 2 loop-carried returned 0 (no previous iteration)
	//   6 = step 3 computeExitSnapshotForEdge
	//   7 = step 4 resolveViaHistory
	//   0 = error path
	phiPath := 0
	if it != nil && it.tracePhi {
		defer func() {
			valHex := "<nil>"
			if result != nil {
				valHex = result.Hex()
			}
			errStr := "<nil>"
			if retErr != nil {
				errStr = retErr.Error()
			}
			curPC := uint(0)
			prevPC := uint(0)
			if cur != nil {
				curPC = cur.FirstPC()
			}
			if prev != nil {
				prevPC = prev.FirstPC()
			}
			phiPC := uint(0)
			phiIdx := 0
			if phi != nil {
				phiPC = phi.evmPC
				phiIdx = phi.phiStackIndex
			}
			log.Warn("MIR PHI trace",
				"curPC", curPC, "prevPC", prevPC,
				"phiPC", phiPC, "phiIdx", phiIdx,
				"path", phiPath, "val", valHex, "err", errStr)
		}()
	}
	if cur == nil || phi == nil {
		return nil, errors.New("nil phi context")
	}
	if prev == nil {
		// Entry block should not have PHI; treat as zero.
		return u256Zero, nil
	}

	// Prefer selecting the PHI operand corresponding to the actual predecessor edge.
	// For loop back-edges the operand is a RuntimeVal (set during CFG construction)
	// that evalValue resolves by walking the block history and reading the actual
	// previous-iteration body output — so shift-register loops work correctly
	// without needing any static analysis of loop depth or per-iteration snapshots.
	//
	// Rationale: our PHI nodes are created during CFG build by iterating incoming stacks
	// in parent order. In real EVM control-flow, all predecessors reaching a join must
	// have identical stack height, but our CFG can temporarily include infeasible edges
	// (or incomplete snapshots) during dynamic backfill/rebuild. In those cases, indexing
	// into the predecessor stack snapshot by phiStackIndex can go out-of-range and
	// silently produce 0, which is catastrophic for dynamic jumps (invalid jumpdest 0x0).
	//
	// By selecting the operand by predecessor identity (same ordering as build), we keep
	// PHI resolution stable and avoid depending on snapshot length.
	if len(phi.operands) > 0 && len(cur.parents) > 0 {
		foundPrev := false
		for opIdx, p := range cur.parents {
			if p != prev {
				continue
			}
			foundPrev = true
			if opIdx >= 0 && opIdx < len(phi.operands) && phi.operands[opIdx] != nil {
				// Guard: the operand must not be a PHI defined in this same join block.
				// That would be a "future def" at block entry (usually caused by a stale/incorrect
				// incoming snapshot being specialized into the entry stack).
				if ov := phi.operands[opIdx]; ov != nil && ov.kind == Variable && ov.def != nil &&
					ov.def.op == MirPHI && ov.def.defBlockNum == cur.blockNum {
					// fall back to snapshot indexing below
					break
				}
				// Guard 2: Unknown live-in operands are placeholders inserted during PHI build
				// when this parent's incoming snapshot was missing or had the wrong stack height.
				// evalValue silently returns u256Zero for these — correct for a genuine stack
				// underflow but catastrophically wrong when the parent block hadn't been connected
				// via connectEdge yet at build time. Fall through to the runtime snapshot path
				// which records the actual values from the parent's exit stack.
				if ov := phi.operands[opIdx]; ov != nil && ov.kind == Unknown && ov.liveIn {
					if mirRunnerDebugLog {
						log.Warn("MIR PHI: Unknown live-in operand, falling to snapshot",
							"curFirstPC", cur.FirstPC(),
							"prevFirstPC", prev.FirstPC(),
							"phiPC", phi.evmPC,
							"phiIdx", phi.phiStackIndex,
							"opIdx", opIdx,
						)
					}
					break // fall to snapshot indexing below
				}
				val, err := it.evalValue(phi.operands[opIdx])
				if err != nil {
					// Operand-based PHI selection can become temporarily stale across rebuilds when
					// parents/incoming snapshots change shape. If the selected operand refers to a def
					// that wasn't executed on this edge ("missing result for def"), fall back to the
					// runtime incoming snapshot for this predecessor.
					break
				}
				if it.debugPhiHook != nil && val != nil {
					inLen := 0
					inIdx := -1
					if cur != nil && cur.incomingStacks != nil {
						inLen = len(cur.incomingStacks[prev])
					}
					it.debugPhiHook(cur.FirstPC(), prev.FirstPC(), phi.evmPC, phi.phiStackIndex, inLen, inIdx, *val)
				}
				phiPath = 1
				return val, nil
			}
			break
		}
		if !foundPrev {
			return nil, fmt.Errorf("%w: phi eval failed: predecessor not found in parents (curFirstPC=%d prevFirstPC=%d phiPC=%d phiIdx=%d)",
				ErrMIRInternal, cur.FirstPC(), prev.FirstPC(), phi.evmPC, phi.phiStackIndex)
		}
		// Found predecessor but operand was missing/nil: fall back to snapshot indexing below.
	}

	// Fallback: use the runtime-recorded incoming stack snapshot for this predecessor edge.
	// This is mainly needed for dynamic CFG expansion/backfill cases.
	if cur.incomingStacks != nil {
		// Ignore stale runtime snapshots from previous executions when CFG is cached.
		if it.cfg != nil && it.cfg.runtimeEpoch != 0 && cur.incomingStacksGen != nil {
			if g, ok := cur.incomingStacksGen[prev]; ok && g != 0 && g != it.cfg.runtimeEpoch {
				return nil, fmt.Errorf("%w: phi eval failed: stale incoming snapshot (curFirstPC=%d prevFirstPC=%d phiPC=%d phiIdx=%d)",
					ErrMIRInternal, cur.FirstPC(), prev.FirstPC(), phi.evmPC, phi.phiStackIndex)
			}
		}
		// Secondary staleness check using snapshotEpoch: catches stale runtime snapshots even
		// for "simple" CFGs where runtimeEpoch==0 (which bypasses the check above).
		// incomingSnapshotEpoch is only populated for runtime-written snapshots (parseDone=true),
		// so parse-time snapshots (no entry) are not rejected and cause no regression.
		if it.cfg != nil && cur.incomingSnapshotEpoch != nil {
			if ep, ok := cur.incomingSnapshotEpoch[prev]; ok && ep != it.cfg.snapshotEpoch {
				return nil, fmt.Errorf("%w: phi eval failed: stale snapshot epoch (curFirstPC=%d prevFirstPC=%d phiPC=%d phiIdx=%d ep=%d cur=%d)",
					ErrMIRInternal, cur.FirstPC(), prev.FirstPC(), phi.evmPC, phi.phiStackIndex, ep, it.cfg.snapshotEpoch)
			}
		}
		in := cur.incomingStacks[prev]
		if len(in) > 0 {
			idx := (len(in) - 1) - phi.phiStackIndex
			if idx >= 0 && idx < len(in) {
				v := in[idx]
				// If the incoming snapshot has Unknown at this position, try to
				// resolve from the predecessor's actual exit stack (runtime values).
				if v.kind == Unknown && prev.ExitStack() != nil {
					exitSnap := it.computeExitSnapshotForEdge(nil, prev)
					if exitSnap != nil {
						eidx := (len(exitSnap) - 1) - phi.phiStackIndex
						if eidx >= 0 && eidx < len(exitSnap) && exitSnap[eidx].kind != Unknown {
							v = exitSnap[eidx]
						}
					}
				}
				if v.kind != Unknown {
					// If the incoming snapshot points at a def defined in this same block, it's a
					// loop-carried self-reference. This covers both PHI defs and non-PHI defs
					// (e.g. MirADD in a self-looping block where instruction #N references
					// instruction #M > N). If we have already executed this def in a previous
					// loop iteration, use the cached result as the live-in value.
					if v.kind == Variable && v.def != nil && v.def.defBlockNum == cur.blockNum {
						if r, ok := it.getResult(v.def); ok && r != nil {
							phiPath = 3
							return r, nil
						}
						// After a CFG rebuild the snapshot still holds stale *MIR pointers whose
						// resIdx may no longer be current. Try the stable key-based mapping, which
						// always reflects the post-rebuild resIdx for the same logical def.
						// This is the same defKeyToResIdx lookup that evalValue uses for Variable
						// operands and must be applied here for consistency.
						if it.cfg != nil && it.cfg.defKeyToResIdx != nil {
							if ridx, ok2 := it.cfg.defKeyToResIdx[keyForDef(v.def)]; ok2 && ridx > 0 {
								if ridx < len(it.resultsGen) && it.resultsGen[ridx] == it.gen {
									phiPath = 4
									return &it.results[ridx], nil
								}
							}
						}
						// Truly no previous-iteration result: this is the first time we enter this
						// loop-back edge. Return zero only as a last resort (appropriate for
						// loop-carried accumulators whose initial value was 0). Any non-zero initial
						// value should have been captured via the forward-edge PHI operand path above
						// (lines 4033-4068) rather than reaching this snapshot fallback.
						{
							mapped, mappedOk := 0, false
							if it.cfg != nil && it.cfg.defKeyToResIdx != nil {
								mapped, mappedOk = it.cfg.defKeyToResIdx[keyForDef(v.def)]
							}
							genMatch := false
							if v.def.resIdx > 0 && v.def.resIdx < len(it.resultsGen) {
								genMatch = it.resultsGen[v.def.resIdx] == it.gen
							}
							// Find the ACTUAL instruction in cur.instructions with matching evmPC
							actualResIdx := -1
							for _, ins := range cur.instructions {
								if ins != nil && ins.evmPC == v.def.evmPC && ins.op == v.def.op {
									actualResIdx = ins.resIdx
									break
								}
							}
							log.Warn("MIR PHI loop-carried: no previous iteration result, returning 0",
								"block", it.blockNumber,
								"curFirstPC", cur.FirstPC(),
								"prevFirstPC", prev.FirstPC(),
								"phiPC", phi.evmPC,
								"phiIdx", phi.phiStackIndex,
								"defOp", v.def.op.String(),
								"defResIdx", v.def.resIdx,
								"actualResIdx", actualResIdx,
								"mappedResIdx", mapped,
								"mappedOk", mappedOk,
								"genMatch", genMatch,
								"curBuilt", cur.built,
							)
						}
						phiPath = 5
						return u256Zero, nil
					}
					v.liveIn = true
					phiPath = 2
					return it.evalValue(&v)
				}
			}
		}
	}

	// Last resort: all static PHI resolution paths exhausted (operand was Unknown,
	// snapshot was missing or also Unknown). Before giving up, try to materialize
	// the predecessor's exit stack from actual runtime results. The predecessor
	// was just executed, so all its instruction results are in the result table.
	// This avoids a costly fallback to the stock EVM for CFGs where Parse couldn't
	// determine a value statically but runtime execution has all the information.
	if prev.ExitStack() != nil {
		exitSnap := it.computeExitSnapshotForEdge(nil, prev)
		if exitSnap != nil {
			idx := (len(exitSnap) - 1) - phi.phiStackIndex
			if idx >= 0 && idx < len(exitSnap) {
				v := exitSnap[idx]
				if v.kind != Unknown {
					val, err := it.evalValue(&v)
					if err == nil && val != nil {
						phiPath = 6
						return val, nil
					}
				}
			}
		}
	}

	// Deep fallback: walk back through the block execution history to find
	// the actual runtime value for this stack position. Unknown values in
	// the static analysis are live-ins that MIR couldn't trace at Parse
	// time, but the values themselves exist in runtime — they flowed through
	// earlier blocks' exit stacks and are captured in the result table.
	if val, ok := it.resolveViaHistory(prev, phi.phiStackIndex); ok {
		phiPath = 7
		return val, nil
	}

	return nil, fmt.Errorf("%w: phi eval failed: all paths exhausted (curFirstPC=%d prevFirstPC=%d phiPC=%d phiIdx=%d)",
		ErrMIRInternal, cur.FirstPC(), prev.FirstPC(), phi.evmPC, phi.phiStackIndex)
}

// resolveViaHistory walks back through the block execution history to find
// the runtime value at `stackDepthFromTop` of `startBlock`'s exit stack.
//
// Strategy: if startBlock's exit at that position is a live-in (Unknown or
// a Variable whose value wasn't produced in startBlock), the value came
// from startBlock's entry stack. We compute what slot of the predecessor's
// exit stack corresponds to that entry slot (accounting for the block's
// net stack effect), then recurse. We stop when we find a concrete value
// (Konst, or a Variable with an executed def in the result table).
// resolveRuntimeValue tries to resolve a RuntimeVal by computing the source
// block's exit stack from actual runtime results and reading the value at the
// specified depth-from-top. This is O(1) when the source block's exit stack
// snapshot is available (the common case: the source block was just executed).
func (it *MIRInterpreter) resolveRuntimeValue(sourceBlockPC uint, stackDepthFromTop int) (*uint256.Int, bool) {
	if it.cfg == nil {
		return nil, false
	}
	srcBlock := it.cfg.pcToBlock[sourceBlockPC]
	if srcBlock == nil {
		return nil, false
	}
	// Walk the execution history to find srcBlock's most recent execution and
	// resolve its exit-stack value at the requested depth using current runtime
	// results. This returns the actual body-computed value from the previous
	// iteration (for loop back-edges) rather than a static parse-time snapshot.
	return it.resolveViaHistory(srcBlock, stackDepthFromTop)
}

func (it *MIRInterpreter) resolveViaHistory(startBlock *MIRBasicBlock, stackDepthFromTop int) (*uint256.Int, bool) {
	if startBlock == nil || len(it.blockHistory) == 0 {
		return nil, false
	}
	// Find startBlock's position in the history. Search from the newest entry back.
	// (Ring buffer: effective order is positions [pos..end] then [0..pos-1] when full.)
	hist := it.blockHistory
	startIdx := -1
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i] == startBlock {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		return nil, false
	}

	// Walk back: at each step, map the current depth-from-top through the
	// block's exit stack. If the value is live-in, re-map to the entry
	// depth and move to the previous block in history.
	curDepth := stackDepthFromTop
	for i := startIdx; i >= 0; i-- {
		b := hist[i]
		if b == nil {
			return nil, false
		}
		exitStatic := b.ExitStack()
		entryStatic := b.EntryStack()
		if exitStatic == nil {
			// Without a static exit snapshot we can't map positions.
			return nil, false
		}
		exitIdx := (len(exitStatic) - 1) - curDepth
		if exitIdx < 0 || exitIdx >= len(exitStatic) {
			return nil, false
		}
		v := exitStatic[exitIdx]
		// Case 1: live-in — value came from entry stack. Map to entry position
		// and continue to the previous block.
		if v.liveIn {
			if entryStatic == nil {
				return nil, false
			}
			// Map exit-stack liveIn position to entry stack depth-from-top.
			if v.liveInPos < 0 || v.liveInPos >= len(entryStatic) {
				return nil, false
			}
			curDepth = (len(entryStatic) - 1) - v.liveInPos
			continue
		}
		// Case 2: concrete value produced in this block.
		if v.kind == Konst && v.u != nil {
			return v.u, true
		}
		if v.kind == Variable && v.def != nil {
			if r, ok := it.getResult(v.def); ok && r != nil {
				return r, true
			}
			// Try stable key mapping for rebuilt blocks.
			if it.cfg != nil && it.cfg.defKeyToResIdx != nil {
				if ridx, ok2 := it.cfg.defKeyToResIdx[keyForDef(v.def)]; ok2 && ridx > 0 {
					if ridx < len(it.resultsGen) && it.resultsGen[ridx] == it.gen {
						return &it.results[ridx], true
					}
				}
			}
			// Def exists but no result — give up.
			return nil, false
		}
		// Unknown or other kind: give up.
		return nil, false
	}
	return nil, false
}

func (it *MIRInterpreter) evalValue(v *Value) (*uint256.Int, error) {
	if v == nil {
		return u256Zero, nil
	}
	switch v.kind {
	case Konst:
		if v.u != nil {
			return v.u, nil
		}
		// Constants created via newValue(Konst, ...) should always have v.u set.
		// Fall back to a decoding allocation if needed (e.g. for legacy-constructed Values).
		return uint256.NewInt(0).SetBytes(v.payload), nil
	case Variable, Arguments:
		if v.def == nil {
			if mirDebugBlock != 0 && it.blockNumber == mirDebugBlock {
				log.Warn("MIR evalValue: Variable with nil def returns zero",
					"block", it.blockNumber,
					"curEvmPC", it.curEvmPC,
				)
			}
			return u256Zero, nil
		}
		if r, ok := it.getResult(v.def); ok && r != nil {
			return r, nil
		}
		// Rebuild-safe fallback: incoming stack snapshots may retain stale *MIR pointers
		// after block rebuilds during CFG construction. Map stable identity -> latest resIdx.
		if it.cfg != nil && it.cfg.defKeyToResIdx != nil {
			if ridx, ok := it.cfg.defKeyToResIdx[keyForDef(v.def)]; ok && ridx > 0 {
				if ridx < len(it.resultsGen) && it.resultsGen[ridx] == it.gen {
					return &it.results[ridx], nil
				}
			}
		}
		// When the defining instruction's result was never stored (CFG rebuild changed
		// resIdx or the defining block was never executed on this path), return zero
		// for PHI defs. This matches EVM semantics (stack underflow → 0) and prevents
		// fatal errors from temporarily stale operand references after dynamic rebuilds.
		def := v.def
		if def != nil && def.op == MirPHI {
			// PHI def with stale resIdx after rebuild. Scan the actual block
			// instructions for the matching (evmPC, op) to find the current resIdx.
			if defBlock := it.cfg.pcToBlock[uint(def.evmPC)]; defBlock != nil {
				for _, ins := range defBlock.instructions {
					if ins != nil && ins.evmPC == def.evmPC && ins.op == def.op && ins.phiStackIndex == def.phiStackIndex {
						if ins.resIdx > 0 && ins.resIdx < len(it.resultsGen) && it.resultsGen[ins.resIdx] == it.gen {
							return &it.results[ins.resIdx], nil
						}
						break
					}
				}
			}
			// Still no result — CFG is incomplete for this path.
			mapped, mappedOk := 0, false
			if it.cfg != nil && it.cfg.defKeyToResIdx != nil {
				mapped, mappedOk = it.cfg.defKeyToResIdx[keyForDef(def)]
			}
			curFirstPC := uint(0)
			if it.curBlock != nil {
				curFirstPC = it.curBlock.firstPC
			}
			return nil, fmt.Errorf("%w: missing result for PHI def defPC=%d defBlock=%d phiIdx=%d defResIdx=%d mappedResIdx=%d mappedOk=%v (curFirstPC=%d curEvmPC=%d)",
				ErrMIRInternal, def.evmPC, def.defBlockNum, def.phiStackIndex, def.resIdx, mapped, mappedOk, curFirstPC, it.curEvmPC)
		}
		// For non-PHI defs, this is a genuine missing-result bug. Report it.
		mapped, mappedOk := 0, false
		if it.cfg != nil && it.cfg.defKeyToResIdx != nil && def != nil {
			mapped, mappedOk = it.cfg.defKeyToResIdx[keyForDef(def)]
		}
		curFirstPC := uint(0)
		if it.curBlock != nil {
			curFirstPC = it.curBlock.firstPC
		}
		return nil, fmt.Errorf("%w: missing result for def op=%s defPC=%d defBlock=%d phiIdx=%d defResIdx=%d mappedResIdx=%d mappedOk=%v (curFirstPC=%d curEvmPC=%d)",
			ErrMIRInternal, def.op.String(), def.evmPC, def.defBlockNum, def.phiStackIndex, def.resIdx, mapped, mappedOk, curFirstPC, it.curEvmPC)
	case RuntimeVal:
		// Value that MIR couldn't trace statically but exists at runtime.
		// Resolve from the source block's exit stack via execution history.
		if val, ok := it.resolveRuntimeValue(v.rtSourceBlockPC, v.rtStackPos); ok {
			return val, nil
		}
		// If the source block wasn't in our history, try the full history walk.
		if it.cfg != nil {
			if srcBlock := it.cfg.pcToBlock[v.rtSourceBlockPC]; srcBlock != nil {
				if val, ok := it.resolveViaHistory(srcBlock, v.rtStackPos); ok {
					return val, nil
				}
			}
		}
		return nil, fmt.Errorf("%w: unresolved RuntimeVal (sourcePC=%d stackPos=%d) at evmPC=%d",
			ErrMIRInternal, v.rtSourceBlockPC, v.rtStackPos, it.curEvmPC)
	default:
		// Unknown value with liveIn==false: stack underflow (ValueStack.pop on empty stack).
		if !v.liveIn {
			return nil, fmt.Errorf("stack underflow (0 <=> 1)")
		}
		// Unknown with liveIn==true: legacy placeholder — return error to trigger fallback.
		return nil, fmt.Errorf("%w: unresolved Unknown live-in at evmPC=%d", ErrMIRInternal, it.curEvmPC)
	}
}

func (it *MIRInterpreter) evalOperand(m *MIR, idx int) (*uint256.Int, error) {
	if m == nil || idx < 0 || idx >= len(m.operands) {
		return nil, errors.New("bad operand index")
	}
	// Fast-path: use pre-encoded operand info emitted by MIRBasicBlock.appendMIR.
	if m.opKinds != nil && idx < len(m.opKinds) {
		switch m.opKinds[idx] {
		case 0: // const
			if idx < len(m.opConst) && m.opConst[idx] != nil {
				return m.opConst[idx], nil
			}
			return u256Zero, nil
		case 1: // def
			if idx < len(m.opDefIdx) {
				defIdx := m.opDefIdx[idx]
				if defIdx > 0 && defIdx < len(it.resultsGen) && it.resultsGen[defIdx] == it.gen {
					return &it.results[defIdx], nil
				}
			}
			// fall through to slow path (e.g. cross-BB value without resIdx, legacy Values)
		}
	}
	return it.evalValue(m.operands[idx])
}

func (it *MIRInterpreter) evalUnary(m *MIR) (*uint256.Int, error) {
	return it.evalOperand(m, 0)
}

func (it *MIRInterpreter) evalBinary(m *MIR) (*uint256.Int, *uint256.Int, error) {
	a, err := it.evalOperand(m, 0)
	if err != nil {
		return nil, nil, err
	}
	b, err := it.evalOperand(m, 1)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}
