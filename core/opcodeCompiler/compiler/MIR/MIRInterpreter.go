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

type mirDefKey struct {
	defBlockNum   uint
	evmPC         uint
	op            MirOperation
	phiStackIndex int
}

// Shared immutable zero value to avoid allocations in hot paths.
var u256Zero = new(uint256.Int)

func keyForDef(def *MIR) mirDefKey {
	if def == nil {
		return mirDefKey{}
	}
	return mirDefKey{
		defBlockNum:   def.defBlockNum,
		evmPC:         def.evmPC,
		op:            def.op,
		phiStackIndex: def.phiStackIndex,
	}
}

// MIRInterpreter executes MIRBasicBlocks produced by CFG.Parse().
// This is a "minimal" interpreter: enough to validate CFG/PHI/control-flow and core arithmetic.
type MIRInterpreter struct {
	cfg *CFG

	// results stores computed values for MIR definitions.
	results map[mirDefKey]*uint256.Int

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

	// Context for LOGs
	blockNumber uint64

	// Debug: last executed EVM pc (best-effort)
	lastEvmPC uint

	// Optional debug hook (used by tests/tools): called for each executed MIR instruction.
	stepHook func(evmPC uint, evmOp byte, op MirOperation)
}

func NewMIRInterpreter(cfg *CFG) *MIRInterpreter {
	it := &MIRInterpreter{
		cfg:            cfg,
		results:        make(map[mirDefKey]*uint256.Int, 4096),
		mem:            nil,
		validJumpDests: nil,
		// Default to "Frontier-like" rules (all false). A real fullnode MUST set rules
		// per block using SetChainRules or SetChainConfig before execution to get gas parity.
		chainRules:    params.Rules{},
		gasLimit:      0,
		gasUsed:       0,
		memLastGasFee: 0,
		contractAddr:  common.Address{},
		callerAddr:    common.Address{},
		originAddr:    common.Address{},
		callValue:     uint256.NewInt(0),
		state:         NewInMemoryState(),
		callData:      nil,
		returnData:    nil,
		callCreate:    NoopCallCreateBackend{},
		refundApplied: false,
		lastEvmPC:     0,
		stepHook:      nil,
	}
	if cfg != nil {
		it.validJumpDests = cfg.JumpDests()
	}
	return it
}

// ResetForRun clears per-execution state while keeping long-lived allocations (maps/slices)
// so the interpreter can be safely reused (e.g. via sync.Pool) for performance.
func (it *MIRInterpreter) ResetForRun(cfg *CFG) {
	if it == nil {
		return
	}
	it.cfg = cfg
	if cfg != nil {
		it.validJumpDests = cfg.JumpDests()
	} else {
		it.validJumpDests = nil
	}
	// Clear computed SSA results
	if it.results != nil {
		for k := range it.results {
			delete(it.results, k)
		}
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
}

func (it *MIRInterpreter) SetStepHook(h func(evmPC uint, evmOp byte, op MirOperation)) {
	it.stepHook = h
}

func (it *MIRInterpreter) setResult(def *MIR, v *uint256.Int) {
	if it == nil {
		return
	}
	it.results[keyForDef(def)] = v
}

func (it *MIRInterpreter) getResult(def *MIR) (*uint256.Int, bool) {
	if it == nil {
		return nil, false
	}
	r, ok := it.results[keyForDef(def)]
	return r, ok
}

func (it *MIRInterpreter) invalidateBlockResults(b *MIRBasicBlock) {
	if it == nil || b == nil {
		return
	}
	for _, m := range b.instructions {
		if m == nil {
			continue
		}
		delete(it.results, keyForDef(m))
	}
}

// SetGasLimit enables out-of-gas checking. If limit==0, gas is tracked but never errors.
func (it *MIRInterpreter) SetGasLimit(limit uint64) {
	it.gasLimit = limit
}

// SetChainRules controls fork-dependent constant gas schedule. Defaults to Cancun.
func (it *MIRInterpreter) SetChainRules(r params.Rules) {
	it.chainRules = r
}

// SetChainConfig derives and sets fork rules for a specific block context.
// Fullnode integration should call this per block (rules are fork-dependent).
func (it *MIRInterpreter) SetChainConfig(cfg *params.ChainConfig, blockNumber uint64, isMerge bool, timestamp uint64) {
	it.blockNumber = blockNumber
	if cfg == nil {
		it.chainRules = params.Rules{}
		return
	}
	it.chainRules = cfg.Rules(new(big.Int).SetUint64(blockNumber), isMerge, timestamp)
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
			if it.stepHook != nil {
				it.stepHook(m.evmPC, m.evmOp, m.op)
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
				out := uint256.NewInt(0)
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
					// EVM: BYTE(n, x) => nth byte of x (0=most significant)
					out = b.Byte(a)
				case MirSHL:
					out = b.Lsh(b, uint(a.Uint64()))
				case MirSHR:
					out = b.Rsh(b, uint(a.Uint64()))
				case MirSAR:
					out = b.SRsh(b, uint(a.Uint64()))
				case MirLT:
					if a.Lt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirGT:
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
				it.setResult(m, out)

			case MirNOT, MirISZERO:
				a, err := it.evalUnary(m)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				out := uint256.NewInt(0)
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
				it.setResult(m, out)

			case MirMLOAD:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, uint256.NewInt(0).SetUint64(32)); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				word := it.mem[o : o+32]
				it.setResult(m, uint256.NewInt(0).SetBytes(word))

			case MirMSTORE:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, uint256.NewInt(0).SetUint64(32)); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				b := make([]byte, 32)
				vb := val.Bytes()
				copy(b[32-len(vb):], vb)
				copy(it.mem[o:o+32], b)

			case MirMSTORE8:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeMemoryExpansion(off, uint256.NewInt(0).SetUint64(1)); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				o := int(off.Uint64())
				it.ensureMem(o + 1)
				it.mem[o] = byte(val.Uint64() & 0xff)

			case MirMSIZE:
				it.setResult(m, uint256.NewInt(0).SetUint64(uint64(len(it.mem))))

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
				h := crypto.Keccak256(it.mem[o : o+n])
				it.setResult(m, uint256.NewInt(0).SetBytes(h))

			case MirADDRESS:
				it.setResult(m, uint256.NewInt(0).SetBytes(it.contractAddr.Bytes()))

			case MirORIGIN:
				it.setResult(m, uint256.NewInt(0).SetBytes(it.originAddr.Bytes()))

			case MirCALLER:
				it.setResult(m, uint256.NewInt(0).SetBytes(it.callerAddr.Bytes()))

			case MirCALLVALUE:
				if it.callValue == nil {
					it.setResult(m, uint256.NewInt(0))
				} else {
					it.setResult(m, uint256.NewInt(0).Set(it.callValue))
				}

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
				it.setResult(m, uint256.NewInt(0).SetBytes(word[:]))

			case MirCALLDATASIZE:
				it.setResult(m, uint256.NewInt(0).SetUint64(uint64(len(it.callData))))

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
				it.setResult(m, uint256.NewInt(0).SetBytes(hv[:]))

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
				if it.state == nil {
					it.setResult(m, uint256.NewInt(0))
					break
				}
				bal := it.state.GetBalance(addr)
				it.setResult(m, uint256.NewInt(0).SetBytes(bal[:]))

			case MirEXTCODESIZE:
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if it.state == nil {
					it.setResult(m, uint256.NewInt(0))
					break
				}
				it.setResult(m, uint256.NewInt(0).SetUint64(uint64(it.state.GetCodeSize(addr))))

			case MirEXTCODEHASH:
				addr, err := it.evalAddressOperand(m, 0)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if err := it.chargeAccountAccessDelta(addr); err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				if it.state == nil {
					it.setResult(m, uint256.NewInt(0))
					break
				}
				h := it.state.GetCodeHash(addr)
				it.setResult(m, uint256.NewInt(0).SetBytes(h[:]))

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
				it.setResult(m, uint256.NewInt(0).SetUint64(ok))

			case MirCREATE:
				addr, err := it.execCreateLike(m, false)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.setResult(m, uint256.NewInt(0).SetBytes(addr.Bytes()))

			case MirCREATE2:
				addr, err := it.execCreateLike(m, true)
				if err != nil {
					return it.finishResult(ExecResult{Err: err})
				}
				it.setResult(m, uint256.NewInt(0).SetBytes(addr.Bytes()))

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
	// Ensure block is (re)built if it was invalidated by new incoming stacks.
	for i := 0; i < 8 && !nb.built; i++ {
		if len(nb.instructions) > 0 {
			it.invalidateBlockResults(nb)
			nb.ResetForRebuild(true)
		}
		if err := it.cfg.buildBasicBlock(nb, it.validJumpDests); err != nil {
			return nil, err
		}
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
	if !it.refundApplied && r.Err == nil {
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
		it.state.SetBalanceU256(it.contractAddr, uint256.NewInt(0))
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
	opCounts := b.EVMOpCounts()
	for op, cnt := range opCounts {
		cost, ok := vm.ConstantGasForOp(it.chainRules, vm.OpCode(op))
		if !ok {
			// Be strict: missing gas schedule mapping is a parity bug.
			return fmt.Errorf("missing constant gas for evm opcode 0x%x", op)
		}
		if cnt == 0 || cost == 0 {
			continue
		}
		// safe multiply/add in uint64 domain
		total := cost * uint64(cnt)
		// multiplication overflow check
		if uint64(cnt) != 0 && total/uint64(cnt) != cost {
			return errors.New("gas uint64 overflow")
		}
		if err := it.chargeGas(total); err != nil {
			return err
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
		val := uint256.NewInt(0)
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
	avail := it.gasLeft()
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
		return nil, fmt.Errorf("missing result for def op=%s pc=%d", v.def.op.String(), v.def.evmPC)
	default:
		return u256Zero, nil
	}
}

func (it *MIRInterpreter) evalOperand(m *MIR, idx int) (*uint256.Int, error) {
	if m == nil || idx < 0 || idx >= len(m.operands) {
		return nil, errors.New("bad operand index")
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
