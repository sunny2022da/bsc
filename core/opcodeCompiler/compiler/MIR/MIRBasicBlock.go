package MIR

import (
	"github.com/holiman/uint256"
)

func newConstValueFromU(x *uint256.Int) *Value {
	if x == nil {
		return newValue(Konst, nil, nil, []byte{0x00})
	}
	// Canonical payload: minimal big-endian, but keep 0 as a single 0 byte so that
	// constants produced here match common PUSH encodings and are stable for dumps/tests.
	payload := x.Bytes()
	if len(payload) == 0 {
		payload = []byte{0x00}
	}
	v := newValue(Konst, nil, nil, payload)
	// Avoid re-decoding the payload; keep a direct copy of x.
	v.u = new(uint256.Int).Set(x)
	return v
}

func constU256(v *Value) (*uint256.Int, bool) {
	if v == nil || v.kind != Konst {
		return nil, false
	}
	if v.u != nil {
		return new(uint256.Int).Set(v.u), true
	}
	return uint256.NewInt(0).SetBytes(v.payload), true
}

func tryConstFoldUnary(op MirOperation, aVal *Value) (*Value, bool) {
	a, ok := constU256(aVal)
	if !ok {
		return nil, false
	}
	out := new(uint256.Int)
	switch op {
	case MirNOT:
		out.Not(a)
	case MirISZERO:
		if a.IsZero() {
			out.SetOne()
		} else {
			out.Clear()
		}
	default:
		return nil, false
	}
	return newConstValueFromU(out), true
}

func tryConstFoldBinary(op MirOperation, aVal, bVal *Value) (*Value, bool) {
	// IMPORTANT: operand order here must match MIRInterpreter, which evaluates operand0 as 'a'
	// and operand1 as 'b' and then executes the opcode-specific logic.
	a, okA := constU256(aVal)
	b, okB := constU256(bVal)
	if !okA || !okB {
		return nil, false
	}
	out := new(uint256.Int)
	switch op {
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
	case MirSIGNEXT:
		// Mirror the previously implemented peephole semantics: ExtendSign(byteIndex=b, value=a).
		out.ExtendSign(b, a)
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
	default:
		return nil, false
	}
	return newConstValueFromU(out), true
}

func tryConstFoldTernary(op MirOperation, aVal, bVal, cVal *Value) (*Value, bool) {
	a, okA := constU256(aVal)
	b, okB := constU256(bVal)
	c, okC := constU256(cVal)
	if !okA || !okB || !okC {
		return nil, false
	}
	out := new(uint256.Int)
	switch op {
	case MirADDMOD:
		// (a + b) % c, but EVM returns 0 if c==0.
		if c.IsZero() {
			out.Clear()
		} else {
			tmp := new(uint256.Int).Add(a, b)
			out.Mod(tmp, c)
		}
	case MirMULMOD:
		// (a * b) % c, but EVM returns 0 if c==0.
		if c.IsZero() {
			out.Clear()
		} else {
			tmp := new(uint256.Int).Mul(a, b)
			out.Mod(tmp, c)
		}
	default:
		return nil, false
	}
	return newConstValueFromU(out), true
}

// bitmap is a bit map which maps basicblock in to a bit
type bitmap []byte

func (bits *bitmap) ensure(pos uint64) {
	need := int(pos/8) + 1
	if need <= len(*bits) {
		return
	}
	*bits = append(*bits, make([]byte, need-len(*bits))...)
}

func (bits *bitmap) set1(pos uint64) {
	bits.ensure(pos)
	(*bits)[pos/8] |= 1 << (pos % 8)
}

func (bits *bitmap) setN(flag uint16, pos uint64) {
	bits.ensure(pos + 8)
	a := flag << (pos % 8)
	(*bits)[pos/8] |= byte(a)
	if b := byte(a >> 8); b != 0 {
		(*bits)[pos/8+1] = b
	}
}

// checks if the position is in a code segment.
func (bits *bitmap) isBitSet(pos uint64) bool {
	idx := int(pos / 8)
	if idx >= len(*bits) {
		return false
	}
	return (((*bits)[idx] >> (pos % 8)) & 1) == 1
}

type MIRBasicBlock struct {
	blockNum       uint
	firstPC        uint
	lastPC         uint
	initDepth      int
	parentsBitmap  *bitmap
	childrenBitmap *bitmap
	parents        []*MIRBasicBlock
	children       []*MIRBasicBlock
	instructions   []*MIR
	pos            int
	// EVM opcode accounting for gas parity
	// evmOpCounts counts every original EVM opcode encountered while building this block
	// emittedOpCounts counts only those opcodes for which a MIR instruction was emitted
	evmOpCounts     map[byte]uint32
	emittedOpCounts map[byte]uint32
	// evmOps records the original EVM opcode stream for this basic block (in PC order).
	// This enables correct constant-gas accounting and correct GAS/call-gas semantics.
	evmOps         []evmOpAtPC
	evmPCToOpIndex map[uint]int
	// SSA-like stack modeling
	entryStack     []Value
	exitStack      []Value
	incomingStacks map[*MIRBasicBlock][]Value
	// Precomputed live-outs: definitions (MIR) whose values are live at block exit
	liveOutDefs []*MIR
	// Build bookkeeping
	built  bool // set true after first successful build
	queued bool // true if currently enqueued for (re)build
	// Control-flow bookkeeping: indicates this block ends in a jump whose destination
	// cannot be resolved at build time (dynamic JUMP/JUMPI). Interpreter may backfill CFG.
	unresolvedJump bool
}

type evmOpAtPC struct {
	pc uint
	op byte
}

func (b *MIRBasicBlock) Size() uint {
	return uint(len(b.instructions))
}

func (b *MIRBasicBlock) BlockNum() uint {
	return b.blockNum
}

// Instructions returns the MIR instructions within this basic block
func (b *MIRBasicBlock) Instructions() []*MIR {
	return b.instructions
}

// EVMOpCounts returns a copy of the opcode counts encountered while building this block.
func (b *MIRBasicBlock) EVMOpCounts() map[byte]uint32 {
	if b == nil || b.evmOpCounts == nil {
		return nil
	}
	out := make(map[byte]uint32, len(b.evmOpCounts))
	for k, v := range b.evmOpCounts {
		out[k] = v
	}
	return out
}

// EmittedOpCounts returns a copy of the opcode counts that resulted in MIR emission.
func (b *MIRBasicBlock) EmittedOpCounts() map[byte]uint32 {
	if b == nil || b.emittedOpCounts == nil {
		return nil
	}
	out := make(map[byte]uint32, len(b.emittedOpCounts))
	for k, v := range b.emittedOpCounts {
		out[k] = v
	}
	return out
}

func (b *MIRBasicBlock) FirstPC() uint {
	return b.firstPC
}

func (b *MIRBasicBlock) SetFirstPC(firstPC uint) {
	b.firstPC = firstPC
}

func (b *MIRBasicBlock) LastPC() uint {
	return b.lastPC
}

func (b *MIRBasicBlock) SetLastPC(lastPC uint) {
	b.lastPC = lastPC
}

func (b *MIRBasicBlock) InitDepth() int {
	return b.initDepth
}

func (b *MIRBasicBlock) SetInitDepth(d int) {
	b.initDepth = d
}

func (b *MIRBasicBlock) SetInitDepthMax(d int) {
	if d > b.initDepth {
		b.initDepth = d
	}
}

func (b *MIRBasicBlock) Parents() []*MIRBasicBlock {
	return b.parents
}

func (b *MIRBasicBlock) SetParents(parents []*MIRBasicBlock) {
	for _, parent := range parents {
		if !b.parentsBitmap.isBitSet(uint64(parent.blockNum)) {
			b.parentsBitmap.set1(uint64(parent.blockNum))
			b.parents = append(b.parents, parent)
		}
	}
}

func (b *MIRBasicBlock) Children() []*MIRBasicBlock {
	return b.children
}

func (b *MIRBasicBlock) SetChildren(children []*MIRBasicBlock) {
	for _, child := range children {
		if !b.childrenBitmap.isBitSet(uint64(child.blockNum)) {
			b.childrenBitmap.set1(uint64(child.blockNum))
			b.children = append(b.children, child)
		}
	}
}

func (b *MIRBasicBlock) CreateVoidMIR(op MirOperation) (mir *MIR) {
	mir = newVoidMIR(op)
	// Do not emit runtime MIR for NOP; gas is accounted via block aggregation
	if mir.op == MirNOP {
		return nil
	}
	return b.appendMIR(mir)
}

func (b *MIRBasicBlock) appendMIR(mir *MIR) *MIR {
	mir.idx = len(b.instructions)
	mir.defBlockNum = b.blockNum
	// Attach EVM mapping captured by the CFG builder
	mir.evmPC = currentEVMBuildPC
	mir.evmOp = currentEVMBuildOp
	// Attach EVM op index (best-effort) for fast constant gas charging at runtime.
	// This is safe even during rebuild: evmPCToOpIndex is rebuilt alongside evmOps.
	mir.evmOpIndex = -1
	if b.evmPCToOpIndex != nil {
		if idx, ok := b.evmPCToOpIndex[mir.evmPC]; ok {
			mir.evmOpIndex = idx
		}
	}
	// Allocate a global result slot for this MIR (if we're in a CFG build context).
	// IMPORTANT: reuse existing resIdx for the same stable def key across rebuilds, otherwise
	// runtime rebuilds (dynamic jump backfill) can invalidate already-computed results and
	// lead to "missing result for def MirPHI".
	if currentCFGBuild != nil {
		if currentCFGBuild.defKeyToResIdx != nil {
			if ridx, ok := currentCFGBuild.defKeyToResIdx[keyForDef(mir)]; ok && ridx > 0 {
				mir.resIdx = ridx
			} else {
				mir.resIdx = currentCFGBuild.allocResIdx()
				currentCFGBuild.defKeyToResIdx[keyForDef(mir)] = mir.resIdx
			}
		} else {
			mir.resIdx = currentCFGBuild.allocResIdx()
		}
	}
	// Record that we emitted a MIR for this originating EVM opcode
	if b.emittedOpCounts != nil {
		b.emittedOpCounts[currentEVMBuildOp]++
	}
	// Pre-encode operand info to avoid runtime eval costs
	if len(mir.operands) > 0 {
		mir.opKinds = make([]byte, len(mir.operands))
		mir.opConst = make([]*uint256.Int, len(mir.operands))
		mir.opDefIdx = make([]int, len(mir.operands))
		for i, v := range mir.operands {
			if v == nil {
				mir.opKinds[i] = 2
				continue
			}
			switch v.kind {
			case Konst:
				mir.opKinds[i] = 0
				mir.opConst[i] = v.u
			case Variable, Arguments:
				mir.opKinds[i] = 1
				if v.def != nil {
					// Prefer rebuild-safe lookup via stable key mapping.
					if currentCFGBuild != nil && currentCFGBuild.defKeyToResIdx != nil {
						if ridx, ok := currentCFGBuild.defKeyToResIdx[keyForDef(v.def)]; ok {
							mir.opDefIdx[i] = ridx
						} else {
							mir.opDefIdx[i] = v.def.resIdx
						}
					} else {
						mir.opDefIdx[i] = v.def.resIdx
					}
				} else {
					mir.opDefIdx[i] = -1
				}
			default:
				mir.opKinds[i] = 2
			}
		}
	}
	// Record generation-time stack depth for debugging/dumps
	// Note: this uses the current stack size after any pushes done above callers.
	mir.genStackDepth = 0
	// Best-effort: if the basic block is appending after a push, ValueStack.size()
	// will include it; otherwise it reflects post-pop size. Good enough for traces.
	// We cannot read stack here without passing it, so we leave as 0 and set in callers that have the stack.
	b.instructions = append(b.instructions, mir)
	return mir
}

func (b *MIRBasicBlock) CreateUnaryOpMIR(op MirOperation, stack *ValueStack) (mir *MIR) {
	opnd1 := stack.pop()
	// Constant fold if possible (build-time only). If folded, do not emit MIR; gas is accounted
	// by per-block EVM opcode stream aggregation.
	switch op {
	case MirNOT, MirISZERO:
		if folded, ok := tryConstFoldUnary(op, &opnd1); ok {
			stack.push(folded)
			return nil
		}
	}

	mir = newUnaryOpMIR(op, &opnd1, stack)

	// Only push result if the operation wasn't optimized away (MirNOP)
	if mir.op != MirNOP {
		// Only push for producer ops; copy ops do not produce a stack item
		switch op {
		case MirCALLDATACOPY, MirCODECOPY, MirEXTCODECOPY, MirRETURNDATACOPY, MirDATACOPY:
			// no push
		default:
			stack.push(mir.Result())
		}
	}
	// If mir.op == MirNOP, peephole already pushed the optimized constant to stack.
	// Do not emit runtime MIR for NOP; gas is accounted via per-block opcode stream aggregation.
	if mir.op == MirNOP {
		return nil
	}
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	return mir
}

func (b *MIRBasicBlock) CreateBinOpMIR(op MirOperation, stack *ValueStack) (mir *MIR) {
	opnd1 := stack.pop()
	opnd2 := stack.pop()
	// Constant fold if possible (build-time only). If folded, do not emit MIR; gas is accounted
	// by per-block EVM opcode stream aggregation.
	if folded, ok := tryConstFoldBinary(op, &opnd1, &opnd2); ok {
		stack.push(folded)
		return nil
	}
	mir = newBinaryOpMIR(op, &opnd1, &opnd2, stack)

	// Only push result if the operation wasn't optimized away (MirNOP)
	if mir.op != MirNOP {
		stack.push(mir.Result())
	}
	// If mir.op == MirNOP, doPeepHole already pushed the optimized constant to stack
	if mir.op == MirNOP {
		// Do not emit runtime MIR for NOP; gas is accounted via block aggregation
		return nil
	}
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

// CreateTernaryOpMIR creates a MIR instruction for 3-operand operations like ADDMOD, MULMOD
func (b *MIRBasicBlock) CreateTernaryOpMIR(op MirOperation, stack *ValueStack) (mir *MIR) {
	// EVM stack before ternary ops like ADDMOD/MULMOD: [..., third, second, first(top)]
	// Pop order: first(top) -> second -> third
	opndA := stack.pop() // first (top)
	opndB := stack.pop() // second
	opndC := stack.pop() // third (e.g., modulus)

	// Constant fold if possible (build-time only). If folded, do not emit MIR; gas is accounted
	// by per-block EVM opcode stream aggregation.
	if folded, ok := tryConstFoldTernary(op, &opndA, &opndB, &opndC); ok {
		stack.push(folded)
		return nil
	}

	// Try peephole optimization for 3-operand operations  // todo clyde add peephole optimization later
	// if doPeepHole3Ops(op, &opndA, &opndB, &opndC, stack, nil) {
	// 	// Optimized away; do not emit MirNOP
	// 	return nil
	// }

	// Create regular ternary operation MIR in (first, second, third) order
	mir = newTernaryOpMIR(op, &opndA, &opndB, &opndC, stack)

	// Only push result if the operation wasn't optimized away (MirNOP)
	if mir.op != MirNOP {
		stack.push(mir.Result())
	}
	// If mir.op == MirNOP, doPeepHole3Ops already pushed the optimized constant to stack
	if mir.op == MirNOP {
		// Do not emit runtime MIR for NOP; gas is accounted via block aggregation
		return nil
	}
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	return mir
}

func (b *MIRBasicBlock) newKeccakMIR(data *Value, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = MirKECCAK256
	mir.operands = []*Value{data}
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func NewMIRBasicBlock(blockNum, pc uint) *MIRBasicBlock {
	bb := new(MIRBasicBlock)
	bb.blockNum = blockNum
	bb.firstPC = pc
	bb.initDepth = 0
	bb.parentsBitmap = &bitmap{0}  // Initialize with at least 1 byte
	bb.childrenBitmap = &bitmap{0} // Initialize with at least 1 byte
	bb.instructions = []*MIR{}
	bb.evmOpCounts = make(map[byte]uint32)
	bb.emittedOpCounts = make(map[byte]uint32)
	bb.evmOps = make([]evmOpAtPC, 0, 256)
	bb.evmPCToOpIndex = make(map[uint]int, 256)
	bb.entryStack = nil
	bb.exitStack = nil
	bb.incomingStacks = make(map[*MIRBasicBlock][]Value)
	bb.built = false
	bb.queued = false

	return bb
}

type MIRBasicBlockStack struct {
	data []*MIRBasicBlock
}

func (s *MIRBasicBlockStack) Push(ptr *MIRBasicBlock) {
	if s == nil {
		return
	}
	s.data = append(s.data, ptr)
}

func (s *MIRBasicBlockStack) Pop() *MIRBasicBlock {
	val := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return val
}

func (s *MIRBasicBlockStack) Size() int {
	return len(s.data)
}

func (b *MIRBasicBlock) CreateStackOpMIR(op MirOperation, stack *ValueStack) *MIR {
	// For DUP operations
	if op >= MirDUP1 && op <= MirDUP16 {
		n := int(op - MirDUP1 + 1) // DUP1 = 1, DUP2 = 2, etc.
		return b.CreateDupMIR(n, stack)
	}

	// For SWAP operations
	if op >= MirSWAP1 && op <= MirSWAP16 {
		n := int(op - MirSWAP1 + 1) // SWAP1 = 1, SWAP2 = 2, etc.
		return b.CreateSwapMIR(n, stack)
	}

	// Fallback for other stack operations
	mir := new(MIR)
	mir.op = op
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	return mir
}

func (b *MIRBasicBlock) CreateDupMIR(n int, stack *ValueStack) *MIR {
	// DUPn duplicates the nth stack item (1-indexed) to the top
	// Stack before: [..., item_n, ..., item_2, item_1]
	// Stack after:  [..., item_n, ..., item_2, item_1, item_n]

	if stack.size() < n {
		// Depth underflow: no-op emission
		return nil
	}

	// Get the value to duplicate (n-1 because stack is 0-indexed from top)
	dupValue := stack.peek(n - 1)

	// todo clyde add getOptimizableOps()  later
	// // Check if we can optimize this DUP operation
	// if isOptimizable(MirOperation(0x80+byte(n-1))) && dupValue.kind == Konst {
	// 	// If the value to duplicate is a constant, duplicate by pushing same constant
	// 	optimizedValue := newValue(Konst, nil, nil, dupValue.payload)
	// 	stack.push(optimizedValue)

	// 	// No runtime MIR for DUP; gas handled via per-block opcode counts
	// 	return nil
	// }

	// For non-constant values, perform the actual duplication on the stack
	duplicatedValue := *dupValue // Copy the value
	stack.push(&duplicatedValue)

	// No runtime MIR for DUP; gas handled via per-block opcode counts
	return nil
}

func (b *MIRBasicBlock) CreateSwapMIR(n int, stack *ValueStack) *MIR {
	// SWAPn swaps the top stack item with the nth stack item (1-indexed)
	// Stack before: [..., item_n+1, item_n, ..., item_2, item_1]
	// Stack after:  [..., item_n+1, item_1, ..., item_2, item_n]

	if stack.size() <= n {
		// Depth underflow: no-op emission
		return nil
	}

	// // Check if we can optimize this SWAP operation
	// topValue := stack.peek(0)  // item_1 (top of stack)
	// swapValue := stack.peek(n) // item_n+1 (the item to swap with)
	// // Diagnostics: before swap snapshot
	// // removed verbose SWAP diagnostics

	// if isOptimizable(MirOperation(0x90+byte(n-1))) &&
	// 	topValue.kind == Konst && swapValue.kind == Konst {
	// 	// Both values are constants, just swap in stack
	// 	stack.swap(0, n)
	// 	// No runtime MIR for SWAP; gas handled via per-block opcode counts
	// 	return nil
	// }

	// For non-constant values, perform the actual swap on the stack
	stack.swap(0, n)

	// Diagnostics: after swap snapshot removed
	// No runtime MIR for SWAP; gas handled via per-block opcode counts
	return nil
}

// CreatePhiMIR creates a PHI node merging incoming stack values.
// phiStackIndex is 0 for top-of-stack.
func (b *MIRBasicBlock) CreatePhiMIR(ops []*Value, stack *ValueStack, phiStackIndex int) *MIR {
	mir := new(MIR)
	mir.op = MirPHI
	mir.operands = ops
	mir.phiStackIndex = phiStackIndex
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	return mir
}

// AddIncomingStack records a parent's exit stack as an incoming stack for this block.
func (b *MIRBasicBlock) AddIncomingStack(parent *MIRBasicBlock, values []Value) {
	if parent == nil || values == nil {
		return
	}

	// Copy to decouple from caller mutations
	copied := make([]Value, len(values))
	copy(copied, values)
	b.incomingStacks[parent] = copied
}

// IncomingStacks returns the recorded incoming stacks by parent.
func (b *MIRBasicBlock) IncomingStacks() map[*MIRBasicBlock][]Value {
	return b.incomingStacks
}

// SetExitStack records the block's exit stack snapshot.
func (b *MIRBasicBlock) SetExitStack(values []Value) {
	if values == nil {
		b.exitStack = nil
		b.liveOutDefs = nil
		return
	}
	copied := make([]Value, len(values))
	copy(copied, values)
	b.exitStack = copied
	// Recompute liveOutDefs from exit stack: collect defs for variable values
	if len(values) == 0 {
		b.liveOutDefs = nil
		return
	}
	defs := make([]*MIR, 0, len(values))
	for i := range values {
		v := values[i]
		if v.kind == Variable && v.def != nil {
			defs = append(defs, v.def)
		}
	}
	b.liveOutDefs = defs
}

// ExitStack returns the block's exit stack snapshot.
func (b *MIRBasicBlock) ExitStack() []Value { return b.exitStack }

// SetEntryStack sets the precomputed entry stack snapshot.
func (b *MIRBasicBlock) SetEntryStack(values []Value) {
	if values == nil {
		b.entryStack = nil
		return
	}
	copied := make([]Value, len(values))
	copy(copied, values)
	b.entryStack = copied
}

// EntryStack returns the block's entry stack snapshot.
func (b *MIRBasicBlock) EntryStack() []Value { return b.entryStack }

// LiveOutDefs returns the MIR definitions that are live at block exit.
func (b *MIRBasicBlock) LiveOutDefs() []*MIR { return b.liveOutDefs }

func (b *MIRBasicBlock) CreateBlockInfoMIR(op MirOperation, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = op

	// Populate operands based on the specific block/tx info operation
	switch op {
	// No-operand producers
	case MirADDRESS, MirORIGIN, MirCALLER, MirCALLVALUE,
		MirCALLDATASIZE, MirCODESIZE, MirGASPRICE,
		MirRETURNDATASIZE, MirPC, MirGAS,
		MirDATASIZE, MirBLOBBASEFEE:
		// No stack pops; just produce a result

	case MirBALANCE:
		// pops: address
		addr := stack.pop()
		mir.operands = []*Value{&addr}

	case MirCALLDATALOAD:
		// pops: offset
		offset := stack.pop()
		mir.operands = []*Value{&offset}

	case MirCALLDATACOPY:
		// pops (EVM order): dest(memOffset), offset(dataOffset), size(length)
		dest := stack.pop()
		offset := stack.pop()
		size := stack.pop()
		mir.operands = []*Value{&dest, &offset, &size}

	case MirCODECOPY:
		// pops (EVM order): dest(memOffset), offset(codeOffset), size(length)
		dest := stack.pop()
		offset := stack.pop()
		size := stack.pop()
		mir.operands = []*Value{&dest, &offset, &size}

	case MirEXTCODESIZE:
		// pops: address
		addr := stack.pop()
		mir.operands = []*Value{&addr}

	case MirEXTCODECOPY:
		// EVM stack (top to bottom): address, destOffset, offset, size
		// Pop order: address (first/top), dest, offset, size (last/bottom)
		addr := stack.pop()
		dest := stack.pop()
		offset := stack.pop()
		size := stack.pop()
		mir.operands = []*Value{&addr, &dest, &offset, &size}

	case MirRETURNDATACOPY:
		// pops (EVM order): dest(memOffset), offset(returnDataOffset), size(length)
		dest := stack.pop()
		offset := stack.pop()
		size := stack.pop()
		mir.operands = []*Value{&dest, &offset, &size}

	case MirEXTCODEHASH:
		// pops: address
		addr := stack.pop()
		mir.operands = []*Value{&addr}

	// EOF data operations
	case MirDATALOAD:
		// pops: offset
		offset := stack.pop()
		mir.operands = []*Value{&offset}

	case MirDATALOADN:
		// Immediate-indexed load in EOF; not modeled via stack here

	case MirDATACOPY:
		// pops: dest, offset, size
		size := stack.pop()
		offset := stack.pop()
		dest := stack.pop()
		mir.operands = []*Value{&dest, &offset, &size}

	case MirRETURNDATALOAD:
		// pops: offset
		offset := stack.pop()
		mir.operands = []*Value{&offset}

	case MirBLOBHASH:
		// pops: index
		index := stack.pop()
		mir.operands = []*Value{&index}

	default:
		// leave operands empty for any not explicitly handled
	}

	// Only push result for producer ops; copy ops do not produce a stack item
	switch op {
	case MirCALLDATACOPY, MirCODECOPY, MirEXTCODECOPY, MirRETURNDATACOPY, MirDATACOPY, MirDATALOADN:
		// no push
	default:
		stack.push(mir.Result())
	}
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func (b *MIRBasicBlock) CreateBlockOpMIR(op MirOperation, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = op
	// Only MirBLOCKHASH consumes one stack operand (block number). Others are producers.
	if op == MirBLOCKHASH {
		blk := stack.pop()
		mir.operands = []*Value{&blk}
	}
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func (b *MIRBasicBlock) CreateJumpMIR(op MirOperation, stack *ValueStack, bbStack *MIRBasicBlockStack) *MIR {
	mir := new(MIR)
	mir.op = op

	// EVM semantics:
	// - JUMP consumes 1 operand: destination
	// - JUMPI consumes 2 operands: destination and condition
	// Stack top holds the last pushed item; pop order reflects that.

	switch op {
	case MirJUMP:
		dest := stack.pop()
		mir.operands = []*Value{&dest}
	case MirJUMPI:
		dest := stack.pop()
		cond := stack.pop()
		mir.operands = []*Value{&dest, &cond}
	default:
		// Other jump-like ops not implemented here
	}

	// JUMP/JUMPI do not produce a stack value; do not push a result
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func (b *MIRBasicBlock) CreateControlFlowMIR(op MirOperation, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = op
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func (b *MIRBasicBlock) CreateSystemOpMIR(op MirOperation, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = op
	stack.push(mir.Result())
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

func (b *MIRBasicBlock) CreateLogMIR(op MirOperation, stack *ValueStack) *MIR {
	mir := new(MIR)
	mir.op = op

	// Calculate number of topics based on LOG operation
	numTopics := int(op - MirLOG0)

	// EVM pops in order: dataOffset, dataSize, topic1, topic2, ..., topicN
	// (stack top has dataOffset, then dataSize, then topics)
	// Total operands: 2 (offset+size) + numTopics
	totalOperands := 2 + numTopics

	// Pop all values - they come in the right order!
	operands := make([]*Value, totalOperands)
	for i := 0; i < totalOperands; i++ {
		val := stack.pop()
		operands[i] = &val
	}
	mir.operands = operands

	// LOGx consume operands and do not push a result
	mir = b.appendMIR(mir)
	mir.genStackDepth = stack.size()
	// noisy generation logging removed
	return mir
}

// stacksEqual reports whether two Value slices are equal element-wise using Value semantics.
// Constants are compared by numeric value, variables by stable def identity (op, evmPC, phiSlot).
func stacksEqual(a, b []Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		va := &a[i]
		vb := &b[i]
		if !equalValueForFlow(va, vb) {
			return false
		}
	}
	return true
}

// equalValueForFlow compares two Values for CFG flow purposes.
//
// Correctness note: For Variable values, using only (op, evmPC, phiSlot) is NOT sufficient
// because different variants/blocks can produce distinct defs at the same evmPC. Treating them
// as equal can incorrectly simplify away PHIs and cause uses to reference defs that were never
// executed on the chosen path (consensus divergence).
func equalValueForFlow(a, b *Value) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case Konst:
		// Compare numeric value
		var av, bv *uint256.Int
		if a.u != nil {
			av = a.u
		} else {
			av = uint256.NewInt(0).SetBytes(a.payload)
		}
		if b.u != nil {
			bv = b.u
		} else {
			bv = uint256.NewInt(0).SetBytes(b.payload)
		}
		return av != nil && bv != nil && av.Eq(bv)
	case Variable:
		if a.def == nil || b.def == nil {
			return a.def == nil && b.def == nil
		}
		// Stable definition identity across rebuilds:
		// (defBlockNum, evmPC, op, phiStackIndex)
		da, db := a.def, b.def
		return da.defBlockNum == db.defBlockNum &&
			da.evmPC == db.evmPC &&
			da.op == db.op &&
			da.phiStackIndex == db.phiStackIndex
	case Arguments, Unknown:
		return true
	default:
		return false
	}
}

// ResetForRebuild clears transient build artifacts so the block can be rebuilt cleanly
// without duplicating MIR instructions. It preserves structural CFG data and entry/incoming
// stacks so PHIs can be regenerated deterministically.
func (b *MIRBasicBlock) ResetForRebuild(preserveEntry bool) {
	// Clear previously generated instructions and iteration cursor
	b.instructions = nil
	b.pos = 0
	// Clear opcode accounting; it will be recomputed during rebuild.
	//
	// Important: both maps must be cleared. `evmOpCounts` drives constant gas charging
	// and must not accumulate across rebuilds, otherwise MIR will overcharge gas.
	if b.evmOpCounts != nil {
		for k := range b.evmOpCounts {
			delete(b.evmOpCounts, k)
		}
	}
	if b.emittedOpCounts != nil {
		for k := range b.emittedOpCounts {
			delete(b.emittedOpCounts, k)
		}
	}
	// Clear recorded EVM opcode stream for this block; it will be recomputed during rebuild.
	b.evmOps = b.evmOps[:0]
	if b.evmPCToOpIndex != nil {
		for k := range b.evmPCToOpIndex {
			delete(b.evmPCToOpIndex, k)
		}
	}
	// Clear exit-related metadata; it will be recomputed during rebuild
	b.lastPC = 0
	b.exitStack = nil
	b.liveOutDefs = nil
	// Optionally preserve entry stack snapshot; most rebuilds depend on it
	if !preserveEntry {
		b.entryStack = nil
	}
	// Do not touch parents, children or incomingStacks here; they represent CFG topology
}

func (b *MIRBasicBlock) CreatePushMIR(n int, value []byte, stack *ValueStack) *MIR {
	stack.push(newValue(Konst, nil, nil, value))
	// No runtime MIR for PUSH; gas handled via per-block opcode counts
	return nil
}

func (bb *MIRBasicBlock) GetNextOp() *MIR {
	if bb.pos >= len(bb.instructions) {
		return nil
	}
	op := bb.instructions[bb.pos]
	bb.pos++
	return op
}

// recordEVMOp records the original EVM opcode stream for this basic block.
// It should be called by the CFG builder once per decoded EVM opcode (in increasing pc order).
func (b *MIRBasicBlock) recordEVMOp(pc uint, op byte) {
	if b == nil {
		return
	}
	if b.evmOps == nil {
		b.evmOps = make([]evmOpAtPC, 0, 256)
	}
	if b.evmPCToOpIndex == nil {
		b.evmPCToOpIndex = make(map[uint]int, 256)
	}
	// Only record first opcode seen at a given pc.
	if _, ok := b.evmPCToOpIndex[pc]; ok {
		return
	}
	b.evmPCToOpIndex[pc] = len(b.evmOps)
	b.evmOps = append(b.evmOps, evmOpAtPC{pc: pc, op: op})
}
