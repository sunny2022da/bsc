package MIR

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
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
	state        StateBackend

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

	// Debug: last executed EVM pc (best-effort)
	lastEvmPC uint

	// Optional debug hook (used by tests/tools): called for each executed MIR instruction.
	stepHook func(evmPC uint, evmOp byte, op MirOperation)

	// Optional debug hook to inspect operands at runtime (used by tools/tests).
	// Values are passed by value to avoid accidental mutation by the caller.
	debugOperandHook func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int)
	// Extended operand hook including operand source (def op/pc if the operand is a Variable).
	debugOperandHookEx func(evmPC uint, evmOp byte, op MirOperation, a uint256.Int, b uint256.Int, aDefPC uint, bDefPC uint, aDefOp MirOperation, bDefOp MirOperation)
	// Debug hook for KECCAK256 input bytes (truncated) to diagnose memory divergence.
	debugKeccakHook func(evmPC uint, off uint64, sz uint64, data []byte)

	// Execution cursor (for GAS/call-gas semantics when constant gas is precharged at block entry).
	curBlock *MIRBasicBlock
	curEvmPC uint

	// Cached per-block suffix sums of constant gas for original EVM opcode stream.
	// Indexed by basic block number; each entry is len(block.evmOps)+1 where suffix[i] is sum from i..end.
	blockConstSuffix [][]uint64
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
		lastEvmPC:              0,
		stepHook:               nil,
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
	// Reset memory but keep capacity
	if it.mem != nil {
		it.mem = it.mem[:0]
	}
	it.gasUsed = 0
	it.memLastGasFee = 0
	it.returnData = nil
	it.callData = nil
	it.refundApplied = false
	it.lastEvmPC = 0
	it.curBlock = nil
	it.curEvmPC = 0
	it.debugOperandHook = nil
	it.debugOperandHookEx = nil
	it.debugKeccakHook = nil
	// Reset per-run cached suffix tables (cheap; slices will be reused across blocks within this run).
	it.blockConstSuffix = nil
}

func (it *MIRInterpreter) SetStepHook(h func(evmPC uint, evmOp byte, op MirOperation)) {
	it.stepHook = h
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
	for _, m := range b.instructions {
		if m == nil {
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
	idx := it.ensureResIdx(def)
	if idx <= 0 {
		return u256Zero
	}
	it.ensureResultsCapacity(idx)
	it.resultsGen[idx] = it.gen
	return &it.results[idx]
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

func (it *MIRInterpreter) SetStateBackend(s StateBackend) {
	it.state = s
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
	if it.state != nil {
		snap = it.state.Snapshot()
	}
	cur := it.cfg.pcToBlock[entryPC]
	if cur == nil {
		return ExecResult{Err: fmt.Errorf("no block at pc %d", entryPC)}
	}

	var prev *MIRBasicBlock
	for {
		// Ensure the current block is built before executing it. This is critical for correctness
		// when new incoming edges are discovered at runtime (dynamic jumps): we must never rebuild
		// a block while it is actively executing, because that can invalidate PHI/results mid-run.
		if cur != nil && !cur.built {
			if len(cur.instructions) > 0 {
				it.invalidateBlockResults(cur)
				cur.ResetForRebuild(true)
			}
			if err := it.cfg.buildBasicBlock(cur, it.validJumpDests); err != nil {
				return it.finishResult(ExecResult{Err: err})
			}
		}

		// Reset instruction cursor for this block execution
		cur.pos = 0

		// Charge constant gas for all EVM opcodes in this block (including those optimized away in MIR).
		if err := it.chargeBlockConstantGas(cur); err != nil {
			return it.finishResult(ExecResult{Err: err})
		}

		for {
			m := cur.GetNextOp()
			if m == nil {
				// No explicit terminator MIR in this block: fallthrough if any child exists.
				children := cur.Children()
				if len(children) == 0 {
					return it.finishResult(ExecResult{HaltOp: MirSTOP})
				}
				// Deterministic: fallthrough to the first child (for non-terminator blocks).
				prev, cur = cur, children[0]
				break
			}
			it.lastEvmPC = m.evmPC
			it.curBlock = cur
			it.curEvmPC = m.evmPC
			if it.stepHook != nil {
				it.stepHook(m.evmPC, m.evmOp, m.op)
			}
			if it.debugOperandHook != nil {
				// Targeted operand capture for diagnosing control-flow divergence.
				switch m.op {
				case MirADD:
					a, b, err := it.evalBinary(m)
					if err == nil && a != nil && b != nil {
						it.debugOperandHook(m.evmPC, m.evmOp, m.op, *a, *b)
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

			switch m.op {
			case MirPHI:
				v, err := it.evalPhi(cur, prev, m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.setResult(m, v)

			case MirPOP:
				// effect already modeled by IR; no runtime action needed here

			case MirADD, MirMUL, MirSUB, MirDIV, MirSDIV, MirMOD, MirSMOD, MirEXP,
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
					out.Lsh(b, uint(a.Uint64()))
				case MirSHR:
					out.Rsh(b, uint(a.Uint64()))
				case MirSAR:
					out.SRsh(b, uint(a.Uint64()))
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
				var u32 uint256.Int
				u32.SetUint64(32)
				if err := it.chargeMemoryExpansion(off, &u32); err != nil {
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
				var u32 uint256.Int
				u32.SetUint64(32)
				if err := it.chargeMemoryExpansion(off, &u32); err != nil {
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
				var u1 uint256.Int
				u1.SetUint64(1)
				if err := it.chargeMemoryExpansion(off, &u1); err != nil {
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

			case MirCALLVALUE:
				out := it.resultSlot(m)
				if it.callValue == nil {
					out.Clear()
				} else {
					out.Set(it.callValue)
				}

			case MirGAS:
				it.resultSlot(m).SetUint64(it.gasLeftEffective())

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

			case MirSSTORE:
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
				addr, err := it.execCreateLike(m, false)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.resultSlot(m).SetBytes(addr.Bytes())

			case MirCREATE2:
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
				nb, err := it.resolveBB(cur, target)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				prev, cur = cur, nb
				break

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
				if !cond.IsZero() {
					nb, err := it.resolveBB(cur, target)
					if err != nil {
						return it.finishResult(ExecResult{Err: err})
					}
					prev, cur = cur, nb
					break
				}
				// fallthrough: prefer the non-target child when we have a 2-way branch.
				ftPC := m.evmPC + 1
				var ft *MIRBasicBlock
				children := cur.Children()
				if len(children) == 2 {
					// Prefer the successor that is not the jump target.
					if children[0] != nil && children[0].firstPC != target {
						ft = children[0]
					} else if children[1] != nil && children[1].firstPC != target {
						ft = children[1]
					}
				}
				if ft == nil {
					// Fallback: choose the child whose firstPC == evmPC+1, else first child.
					for _, ch := range children {
						if ch != nil && ch.firstPC == ftPC {
							ft = ch
							break
						}
					}
				}
				if ft == nil {
					if len(children) == 0 {
						return it.finishResult(ExecResult{HaltOp: MirSTOP})
					}
					ft = children[0]
				}
				// Ensure we record incoming stack for correct PHI evaluation on fallthrough.
				if cur != nil && ft != nil && it.cfg != nil {
					it.cfg.connectEdge(cur, ft, cur.ExitStack())
					if !ft.built && len(ft.instructions) > 0 {
						it.invalidateBlockResults(ft)
						ft.ResetForRebuild(true)
					}
					if !ft.built {
						_ = it.cfg.buildBasicBlock(ft, it.validJumpDests)
					}
				}
				prev, cur = cur, ft
				break

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
				if it.state != nil && snap >= 0 {
					it.state.RevertToSnapshot(snap)
				}
				return it.finishResult(ExecResult{HaltOp: MirREVERT, ReturnData: out, Err: vm.ErrExecutionReverted, ReturnOffset: off.Uint64(), ReturnSize: sz.Uint64()})

			case MirSELFDESTRUCT:
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
				if it.state != nil && snap >= 0 {
					it.state.RevertToSnapshot(snap)
				}
				return it.finishResult(ExecResult{Err: fmt.Errorf("unimplemented MIR op: %s", m.op.String())})
			}

			// If we performed a control transfer (JUMP/JUMPI), restart loop with new block.
			if cur != nil && cur.pos == 0 && prev != nil && prev != cur {
				// We jumped and reset cur.pos above at top of outer loop.
				break
			}
		}
	}
}

// resolveBB is the runtime backfill hook for dynamic jumps.
// It validates jumpdest, creates/builds the target block if missing, and records a CFG edge
// (including incoming stack snapshot) to enable PHI correctness.
func (it *MIRInterpreter) resolveBB(from *MIRBasicBlock, targetPC uint) (*MIRBasicBlock, error) {
	if it.cfg == nil {
		return nil, errors.New("nil CFG")
	}
	if it.validJumpDests != nil && !it.validJumpDests[targetPC] {
		return nil, fmt.Errorf("invalid jumpdest 0x%x", targetPC)
	}
	nb := it.cfg.pcToBlock[targetPC]
	if nb == nil {
		nb = it.cfg.getOrCreateBlock(targetPC)
	}
	// Record incoming stack snapshot for PHI evaluation.
	if from != nil {
		it.cfg.connectEdge(from, nb, from.ExitStack())
	}
	return nb, nil
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
	// grow to want
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
	// Transfer balance to beneficiary, then mark selfdestruct.
	bal := it.state.GetBalanceU256(it.contractAddr)
	if bal != nil && !bal.IsZero() {
		it.state.AddBalanceU256(beneficiary, bal)
		it.state.SetBalanceU256(it.contractAddr, u256Zero)
	}
	it.state.SelfDestruct(it.contractAddr)
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
	if !it.constGasInit || it.constGasRules != it.chainRules {
		it.rebuildConstGasTable()
	}
	// Charge constant gas for the *original EVM opcode stream* in this basic block.
	// This includes opcodes optimized away in MIR (e.g. PUSH/DUP/SWAP/NOP), and preserves
	// exact ordering information via (pc,op) for GAS/call-gas semantics.
	for _, e := range b.evmOps {
		op := e.op
		if !it.constGasKnown[int(op)] {
			return fmt.Errorf("missing constant gas for evm opcode 0x%x", op)
		}
		if cost := it.constGas[int(op)]; cost != 0 {
			if err := it.chargeGas(cost); err != nil {
				return err
			}
		}
	}
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
	off, offOverflow := offset.Uint64WithOverflow()
	sz, szOverflow := size.Uint64WithOverflow()
	if offOverflow || szOverflow {
		return errors.New("memory offset/size overflow")
	}
	// Zero-size access does not expand memory.
	if sz == 0 {
		return nil
	}
	newSize := off + sz
	// Mirror vm.memoryGasCost logic, but with our own last-fee tracking.
	if newSize == 0 {
		return nil
	}
	if newSize > 0x1FFFFFFFE0 {
		return errors.New("memory expansion overflow")
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
	sz, overflow := size.Uint64WithOverflow()
	if overflow {
		return errors.New("keccak size overflow")
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
	sz, overflow := size.Uint64WithOverflow()
	if overflow {
		return errors.New("copy size overflow")
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
	for i := 0; i < ni; i++ {
		si := oi + i
		if si >= 0 && si < len(src) {
			it.mem[di+i] = src[si]
		} else {
			it.mem[di+i] = 0
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
	for i := 0; i < ni; i++ {
		if i < len(src) {
			it.mem[di+i] = src[i]
		} else {
			it.mem[di+i] = 0
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
	// Memory expansion for in/out regions
	if err := it.chargeMemoryExpansion(inOff, inSz); err != nil {
		return 0, err
	}
	if err := it.chargeMemoryExpansion(outOff, outSz); err != nil {
		return 0, err
	}

	// EIP-2929 warm/cold account access delta for call target
	if err := it.chargeAccountAccessDelta(to); err != nil {
		return 0, err
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

	// Determine gas to pass (EIP-150 63/64 cap)
	var req uint64
	if gasReq == nil || !gasReq.IsUint64() {
		return 0, errors.New("call gas overflow")
	}
	req = gasReq.Uint64()
	avail := it.gasLeftEffective()
	if it.chainRules.IsEIP150 {
		avail = avail - avail/64
	}
	gasToSend := req
	if gasToSend > avail {
		gasToSend = avail
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

func (it *MIRInterpreter) ensureBlockConstSuffix(b *MIRBasicBlock) []uint64 {
	if it == nil || b == nil {
		return nil
	}
	// Ensure const gas table is initialized for current rules.
	if !it.constGasInit || it.constGasRules != it.chainRules {
		it.rebuildConstGasTable()
	}
	// Allocate outer table lazily.
	if it.blockConstSuffix == nil {
		// Basic block numbers are dense from 0..basicBlockCount-1.
		n := 0
		if it.cfg != nil {
			n = int(it.cfg.basicBlockCount)
		}
		if n == 0 {
			n = int(b.blockNum) + 1
		}
		it.blockConstSuffix = make([][]uint64, n)
	} else if int(b.blockNum) >= len(it.blockConstSuffix) {
		// Grow defensively (shouldn't happen if cfg.basicBlockCount is set).
		newTab := make([][]uint64, int(b.blockNum)+1)
		copy(newTab, it.blockConstSuffix)
		it.blockConstSuffix = newTab
	}
	if it.blockConstSuffix[b.blockNum] != nil && len(it.blockConstSuffix[b.blockNum]) == len(b.evmOps)+1 {
		return it.blockConstSuffix[b.blockNum]
	}
	suf := make([]uint64, len(b.evmOps)+1)
	for i := len(b.evmOps) - 1; i >= 0; i-- {
		op := b.evmOps[i].op
		suf[i] = suf[i+1] + it.constGas[int(op)]
	}
	it.blockConstSuffix[b.blockNum] = suf
	return suf
}

// gasLeftEffective returns the gas remaining *as observed by the currently executing EVM opcode*,
// i.e. after paying the current opcode's cost but before paying costs of future opcodes.
// This compensates for MIR's block-entry constant gas precharge.
func (it *MIRInterpreter) gasLeftEffective() uint64 {
	g := it.gasLeft()
	if it == nil || it.curBlock == nil || it.gasLimit == 0 {
		return g
	}
	idx, ok := it.curBlock.evmPCToOpIndex[it.curEvmPC]
	if !ok {
		return g
	}
	suf := it.ensureBlockConstSuffix(it.curBlock)
	if suf == nil {
		return g
	}
	// Add back constant gas for future opcodes in this block.
	rebate := uint64(0)
	if idx+1 < len(suf) {
		rebate = suf[idx+1]
	}
	if g > ^uint64(0)-rebate {
		return ^uint64(0)
	}
	return g + rebate
}

func (it *MIRInterpreter) chargeSLoadGas(slot common.Hash) error {
	// Pre-Berlin SLOAD is covered by constant gas schedule.
	if !it.chainRules.IsEIP2929 {
		return nil
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

func (it *MIRInterpreter) evalPhi(cur, prev *MIRBasicBlock, phi *MIR) (*uint256.Int, error) {
	if cur == nil || phi == nil {
		return nil, errors.New("nil phi context")
	}
	if prev == nil {
		// Entry block should not have PHI; treat as zero.
		return u256Zero, nil
	}
	in := cur.incomingStacks[prev]
	if in == nil {
		// Unknown predecessor: fallback to first operand
		if len(phi.operands) == 0 {
			return u256Zero, nil
		}
		return it.evalValue(phi.operands[0])
	}
	if len(in) == 0 {
		return u256Zero, nil
	}
	// Map stack slot index from top to slice index (bottom->top)
	idx := (len(in) - 1) - phi.phiStackIndex
	if idx < 0 || idx >= len(in) {
		return u256Zero, nil
	}
	v := in[idx]
	v.liveIn = true
	return it.evalValue(&v)
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
		// Provide rich context; this typically indicates a CFG/PHI rebuild or dominance issue.
		def := v.def
		mapped, mappedOk := 0, false
		if it.cfg != nil && it.cfg.defKeyToResIdx != nil && def != nil {
			mapped, mappedOk = it.cfg.defKeyToResIdx[keyForDef(def)]
		}
		curFirstPC := uint(0)
		if it.curBlock != nil {
			curFirstPC = it.curBlock.firstPC
		}
		return nil, fmt.Errorf("missing result for def op=%s defPC=%d defBlock=%d phiIdx=%d defResIdx=%d mappedResIdx=%d mappedOk=%v (curFirstPC=%d curEvmPC=%d)",
			def.op.String(), def.evmPC, def.defBlockNum, def.phiStackIndex, def.resIdx, mapped, mappedOk, curFirstPC, it.curEvmPC)
	default:
		return u256Zero, nil
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
