package MIR

import (
	"github.com/holiman/uint256"
)

// mirDefKey is a stable identity for MIR definitions across block rebuilds.
// It is used to map values captured in incoming stack snapshots (which may retain
// stale *MIR pointers) back to the latest MIR resIdx for the same logical def.
type mirDefKey struct {
	defBlockNum   uint
	evmPC         uint
	op            MirOperation
	phiStackIndex int
}

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

// MIR is register based intermediate representation
type MIR struct {
	op       MirOperation
	operands []*Value
	meta     []byte
	pc       *uint // Program counter of the original instruction (optional)
	idx      int   // Index within its basic block, set by appendMIR
	// resIdx is a global, per-CFG result slot index assigned during CFG build.
	// It enables fast operand evaluation and dense result storage at runtime.
	// 0 means "unassigned" (e.g. tests constructing MIR manually).
	resIdx int
	// Stable identity for fixpoint comparisons across rebuilds.
	defBlockNum uint
	// EVM mapping metadata (set during CFG build)
	evmPC uint // byte offset of the originating EVM opcode
	evmOp byte // originating EVM opcode byte value
	// evmOpIndex is the index into the containing basic block's recorded EVM opcode stream (b.evmOps).
	// Set during CFG build to avoid runtime map lookups when charging constant gas incrementally.
	evmOpIndex int
	// Optional auxiliary MIR attached for diagnostics (e.g., original EVM op at invalid jump target)
	aux *MIR
	// For PHI nodes only: the stack slot index this PHI represents (0 = top of stack)
	phiStackIndex int
	// Pre-encoded operand info to avoid runtime eval
	opKinds       []byte         // 0=const,1=def,2=fallback
	opConst       []*uint256.Int // if const
	opDefIdx      []int          // if def (index into results slice)
	genStackDepth int            // stack depth at generation time (for debugging/dumps)
}

// Op returns the MIR operation opcode for this instruction.
func (m *MIR) Op() MirOperation {
	if m == nil {
		return MirINVALID
	}
	return m.op
}

// EvmPC returns the originating EVM program counter (byte offset) for this MIR instruction.
func (m *MIR) EvmPC() uint {
	if m == nil {
		return 0
	}
	return m.evmPC
}

// EvmOp returns the originating EVM opcode byte for this MIR instruction.
func (m *MIR) EvmOp() byte {
	if m == nil {
		return 0
	}
	return m.evmOp
}

func newVoidMIR(operation MirOperation) *MIR {
	mir := new(MIR)
	mir.op = operation
	mir.operands = nil
	// no deprecated alias
	return mir
}

func newNopMIR(operation MirOperation, original_opnds []*Value) *MIR {
	mir := new(MIR)
	mir.op = MirNOP
	mir.operands = original_opnds
	// no deprecated alias
	mir.meta = []byte{byte(operation)}
	return mir
}

// Package-local variables used during CFG build to annotate MIR with EVM mapping.
// These are set in opcodeParser.buildBasicBlock before each MIR creation.
var currentEVMBuildPC uint
var currentEVMBuildOp byte

// currentCFGBuild points at the CFG currently being built. Used to allocate MIR resIdx.
// NOTE: CFG building already relies on package-level globals for EVM mapping, so this
// is not concurrency-safe by design.
var currentCFGBuild *CFG

func newUnaryOpMIR(operation MirOperation, opnd *Value, stack *ValueStack) *MIR {
	// todo clyde add peephole optimization later

	// if doPeepHole(operation, opnd, nil, stack, nil) {
	// 	return newNopMIR(operation, []*Value{opnd})
	// }
	mir := new(MIR)
	mir.op = operation
	opnd.use = append(opnd.use, mir)
	mir.operands = []*Value{opnd}
	// no deprecated alias
	// If the operand is a live-in from a parent BB, tag the defining MIR as global at build time
	if opnd != nil && opnd.liveIn && opnd.def != nil {
		// No direct global table here; interpreter will use globalResults by def pointer.
		// We preserve liveIn on Value to signal cross-BB origin to later passes if needed.
	}
	return mir
}

func newBinaryOpMIR(operation MirOperation, opnd1 *Value, opnd2 *Value, stack *ValueStack) *MIR {
	// todo clyde add peephole optimization later

	// if doPeepHole(operation, opnd1, opnd2, stack, nil) {
	// 	return newNopMIR(operation, []*Value{opnd1, opnd2})
	// }
	mir := new(MIR)
	mir.op = operation
	opnd1.use = append(opnd1.use, mir)
	opnd2.use = append(opnd2.use, mir)
	mir.operands = []*Value{opnd1, opnd2}
	// no deprecated alias
	if (opnd1 != nil && opnd1.liveIn && opnd1.def != nil) || (opnd2 != nil && opnd2.liveIn && opnd2.def != nil) {
		// Marker only; interpreter resolves by def pointer.
	}
	return mir
}

// newTernaryOpMIR creates a MIR instruction for 3-operand operations
func newTernaryOpMIR(operation MirOperation, opnd1 *Value, opnd2 *Value, opnd3 *Value, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = operation
	opnd1.use = append(opnd1.use, mir)
	opnd2.use = append(opnd2.use, mir)
	opnd3.use = append(opnd3.use, mir)
	mir.operands = []*Value{opnd1, opnd2, opnd3}
	// no deprecated alias
	return mir
}

func (m *MIR) Result() *Value {
	if m.op == MirNOP {
		return nil
	}
	return newValue(Variable, m, nil, nil)
}

// func doPeepHole(operation MirOperation, opnd1 *Value, opnd2 *Value, stack *ValueStack, memoryAccessoraccessor *MemoryAccessor) bool {
// 	optimized := true
// 	var val1 *uint256.Int

// 	if opnd1.kind == Konst {
// 		val1 = uint256.NewInt(0).SetBytes(opnd1.payload)
// 		if opnd2 == nil {
// 			switch operation {
// 			case MirNOT:
// 				val1 = val1.Not(val1)
// 			case MirISZERO:
// 				isZero := val1.IsZero()
// 				if isZero {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			}
// 		} else if opnd2.kind == Konst {
// 			val2 := uint256.NewInt(0).SetBytes(opnd2.payload)
// 			switch operation {
// 			case MirADD:
// 				val1 = val1.Add(val1, val2)
// 			case MirMUL:
// 				val1 = val1.Mul(val1, val2)
// 			case MirSUB:
// 				val1 = val1.Sub(val1, val2)
// 			case MirDIV:
// 				val1 = val1.Div(val1, val2)
// 			case MirSDIV:
// 				val1 = val1.SDiv(val1, val2)
// 			case MirMOD:
// 				val1 = val1.Mod(val1, val2)
// 			case MirSMOD:
// 				val1 = val1.SMod(val1, val2)
// 			case MirEXP:
// 				val1 = val1.Exp(val1, val2)
// 			case MirSIGNEXT:
// 				val1 = val1.ExtendSign(val2, val1)
// 			case MirLT:
// 				isLt := val1.Lt(val2)
// 				if isLt {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			case MirGT:
// 				isGt := val1.Gt(val2)
// 				if isGt {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			case MirSLT:
// 				isSlt := val1.Slt(val2)
// 				if isSlt {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			case MirSGT:
// 				isSgt := val1.Sgt(val2)
// 				if isSgt {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			case MirEQ:
// 				isEq := val1.Eq(val2)
// 				if isEq {
// 					val1.SetOne()
// 				} else {
// 					val1.SetUint64(0)
// 				}
// 			case MirAND:
// 				val1 = val1.And(val1, val2)
// 			case MirOR:
// 				val1 = val1.Or(val1, val2)
// 			case MirXOR:
// 				val1 = val1.Xor(val1, val2)
// 			case MirBYTE:
// 				val1 = val2.Byte(val1)
// 			case MirSHL:
// 				// EVM SHL semantics: result = value << shift
// 				// Stack order: [ ... shift, value ] (top-first pop order)
// 				// opnd1 = shift, opnd2 = value
// 				val1 = val2.Lsh(val2, uint(val1.Uint64()))
// 			case MirSHR:
// 				// Logical right shift: result = value >> shift
// 				val1 = val2.Rsh(val2, uint(val1.Uint64()))
// 			case MirSAR:
// 				// Arithmetic right shift: result = value >>> shift (sign-propagating)
// 				val1 = val2.SRsh(val2, uint(val1.Uint64()))
// 			case MirKECCAK256:
// 				// KECCAK256 takes offset (val1) and size (val2) as operands
// 				// Check if the memory range is known and can be loaded
// 				if memoryAccessoraccessor != nil {
// 					// Try to load data from memory at the specified offset and size
// 					memData := memoryAccessoraccessor.getValueWithOffset(val1, val2)
// 					if memData.kind == Konst && len(memData.payload) > 0 {
// 						// Calculate Keccak256 hash of the known data
// 						hash := crypto.Keccak256(memData.payload)
// 						val1 = uint256.NewInt(0).SetBytes(hash)
// 					} else {
// 						// Disable single-constant peephole identities
// 						optimized = false
// 					}
// 				} else {
// 					optimized = false
// 				}
// 			default:
// 				optimized = false
// 			}
// 		} else {
// 			optimized = false
// 		}
// 	} else {
// 		optimized = false
// 	}

// 	if optimized && val1 != nil {
// 		// Create a new constant value with the optimized result
// 		payload := val1.Bytes()
// 		// Handle special case where Bytes() returns empty slice for zero
// 		if len(payload) == 0 && val1.IsZero() {
// 			payload = []byte{0x00}
// 		}
// 		newVal := newValue(Konst, nil, nil, payload)
// 		stack.push(newVal)
// 	}

// 	return optimized
// }

// // doPeepHole3Ops performs peephole optimizations for 3-operand operations
// func doPeepHole3Ops(operation MirOperation, opnd1 *Value, opnd2 *Value, opnd3 *Value, stack *ValueStack, memoryAccessor *MemoryAccessor) bool {
// 	if opnd1 == nil || opnd2 == nil || opnd3 == nil {
// 		return false
// 	}

// 	// Only optimize if all operands are constants
// 	if opnd1.kind != Konst || opnd2.kind != Konst || opnd3.kind != Konst {
// 		return false
// 	}

// 	// Check if this operation is optimizable in current phase
// 	if !isOptimizable(operation) {
// 		return false
// 	}

// 	optimized := false
// 	val1 := uint256.NewInt(0).SetBytes(opnd1.payload)
// 	val2 := uint256.NewInt(0).SetBytes(opnd2.payload)
// 	val3 := uint256.NewInt(0).SetBytes(opnd3.payload)

// 	switch operation {
// 	case MirADDMOD:
// 		// ADDMOD: (val1 + val2) % val3
// 		if !val3.IsZero() { // Avoid division by zero
// 			temp := uint256.NewInt(0).Add(val1, val2)
// 			val1 = temp.Mod(temp, val3)
// 			optimized = true
// 		}
// 	case MirMULMOD:
// 		// MULMOD: (val1 * val2) % val3
// 		if !val3.IsZero() { // Avoid division by zero
// 			temp := uint256.NewInt(0).Mul(val1, val2)
// 			val1 = temp.Mod(temp, val3)
// 			optimized = true
// 		}
// 	}

// 	if optimized && val1 != nil {
// 		// Create a new constant value with the optimized result
// 		payload := val1.Bytes()
// 		// Handle special case where Bytes() returns empty slice for zero
// 		if len(payload) == 0 && val1.IsZero() {
// 			payload = []byte{0x00}
// 		}
// 		newVal := newValue(Konst, nil, nil, payload)
// 		stack.push(newVal)
// 	}

// 	return optimized
// }
