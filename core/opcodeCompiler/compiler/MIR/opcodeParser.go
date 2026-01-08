package MIR

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
)

// cfgNonConvergentPrefix is used as a stable marker so higher-level callers (runner/tools)
// can identify a non-convergent CFG build without importing extra error types.
const cfgNonConvergentPrefix = "MIR CFG parse did not converge"

// CFGNonConvergentError reports that CFG.Parse exceeded its build bound and did not reach a fixpoint.
// This should be treated as a correctness/debugging failure that must be fixed (not silently ignored).
type CFGNonConvergentError struct {
	Builds    int
	MaxBuilds int
	CodeHash  common.Hash
	CodeLen   int
}

func (e *CFGNonConvergentError) Error() string {
	if e == nil {
		return cfgNonConvergentPrefix
	}
	return fmt.Sprintf("%s after %d block builds (max=%d) codeHash=%s codeLen=%d",
		cfgNonConvergentPrefix, e.Builds, e.MaxBuilds, e.CodeHash.Hex(), e.CodeLen)
}

// CFG is the IR record the control flow of the contract.
// It records not only the control flow info but also the state and memory accesses.
// CFG is mapping to <addr, code> pair, and there is no need to record CFG for every contract
// since it is just an IR, although the analyzing/compiling results are saved to the related cache.
type CFG struct {
	codeAddr        common.Hash
	rawCode         []byte
	basicBlocks     []*MIRBasicBlock
	basicBlockCount uint
	// nextResIdx allocates global MIR result slots for this CFG.
	// Index 0 is reserved for "unassigned".
	nextResIdx int
	// defKeyToResIdx maps stable MIR def identity -> latest allocated resIdx.
	// This is used to repair stale *MIR pointers captured in incoming stack snapshots
	// across block rebuilds during CFG construction.
	defKeyToResIdx map[mirDefKey]int

	// Mapping from EVM PC to the BasicBlock starting at that PC
	pcToBlock map[uint]*MIRBasicBlock

	// Cached valid JUMPDEST map (computed once from rawCode)
	jumpDests map[uint]bool
}

func NewCFG(hash common.Hash, code []byte) (c *CFG) {
	c = &CFG{}
	c.codeAddr = hash
	c.rawCode = code
	c.basicBlocks = []*MIRBasicBlock{}
	c.basicBlockCount = 0
	c.nextResIdx = 1
	c.defKeyToResIdx = make(map[mirDefKey]int, 4096)

	c.pcToBlock = make(map[uint]*MIRBasicBlock)
	c.jumpDests = nil
	return c
}

func (c *CFG) allocResIdx() int {
	if c == nil {
		return 0
	}
	idx := c.nextResIdx
	c.nextResIdx++
	return idx
}

// JumpDests returns the cached map of valid JUMPDEST PCs, computing it once if needed.
func (c *CFG) JumpDests() map[uint]bool {
	if c == nil {
		return nil
	}
	if c.jumpDests == nil {
		c.jumpDests = c.scanJumpDests()
	}
	return c.jumpDests
}

func (c *CFG) addBlock(block *MIRBasicBlock) {
	c.basicBlocks = append(c.basicBlocks, block)
	c.basicBlockCount++
	c.pcToBlock[block.firstPC] = block
}

// getOrCreateBlock returns the block starting at the given PC, creating it if it doesn't exist.
func (c *CFG) getOrCreateBlock(pc uint) *MIRBasicBlock {
	// Check if we've already created a block for this PC
	if block, exists := c.pcToBlock[pc]; exists {
		return block
	}

	// Create new block (now without the parent argument)
	newBlock := NewMIRBasicBlock(c.basicBlockCount, pc)

	// Use addBlock helper to register it
	c.addBlock(newBlock)

	return newBlock
}

// scanJumpDests identifies all valid JUMPDEST locations in the bytecode.
func (c *CFG) scanJumpDests() map[uint]bool {
	dests := make(map[uint]bool)
	pc := uint(0)
	codeLen := uint(len(c.rawCode))

	for pc < codeLen {
		// cast byte to ByteCode type from compiler package
		op := compiler.ByteCode(c.rawCode[pc])

		// 1. Is it a JUMPDEST?
		if op == compiler.JUMPDEST {
			dests[pc] = true
			pc++
			continue
		}

		// 2. Is it a PUSH instruction?
		if op >= compiler.PUSH1 && op <= compiler.PUSH32 {
			// Calculate how many data bytes follow
			// PUSH1 is 0x60. if op is PUSH1, size is 1.
			dataSize := uint(op - compiler.PUSH1 + 1)

			// Skip the data bytes
			pc += 1 + dataSize
			continue
		}

		// 3. Any other instruction
		pc++
	}

	return dests
}

// Parse builds the Control Flow Graph from the raw EVM code.
func (c *CFG) Parse() error {
	// Set current CFG build context for MIR resIdx allocation.
	currentCFGBuild = c
	defer func() { currentCFGBuild = nil }()

	// 1. Identify all valid JUMPDESTs (critical for security/validity)
	// You can use a bitset or map for fast lookup.
	validJumpDests := c.JumpDests()

	// 2. Create the Entry Block (Block 0) at PC 0
	entryBlock := c.getOrCreateBlock(0)

	// 3. Worklist for processing blocks
	// Queue stores blocks that need to be built.
	queue := []*MIRBasicBlock{entryBlock}
	// Safety valve: in the presence of complex back-edges/dynamic CFG backfill, the iterative
	// rebuild process should converge quickly. If it doesn't, it's safer to fall back to the
	// native EVM than to spin indefinitely during block processing.
	//
	// The bound is intentionally generous and scales with bytecode size.
	maxBuilds := 1024 + 64*len(c.rawCode)
	builds := 0

	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]

		// If already built and no one invalidated it, skip
		if block.built {
			continue
		}

		// If we're rebuilding, clear previously generated MIR and force entry-stack recompute.
		// Preserving entryStack is unsafe because it can contain Value.def pointers to
		// MIR instructions we are about to discard (e.g. PHIs), which leads to
		// "missing result for def MirPHI" at runtime after rebuild.
		if len(block.instructions) > 0 {
			block.ResetForRebuild(false)
		}

		// Build the block (emit MIR instructions)
		builds++
		if builds > maxBuilds {
			return &CFGNonConvergentError{
				Builds:    builds,
				MaxBuilds: maxBuilds,
				CodeHash:  c.codeAddr,
				CodeLen:   len(c.rawCode),
			}
		}
		err := c.buildBasicBlock(block, validJumpDests)
		if err != nil {
			return err
		}

		// Add successors (children) to the queue
		for _, child := range block.children {
			// Check if child needs processing...
			queue = append(queue, child)
		}
	}
	return nil
}

// getEntryStackForBlock determines the initial stack state for a block.
func (c *CFG) getEntryStackForBlock(block *MIRBasicBlock) *ValueStack {
	stack := new(ValueStack)

	// Case 1: Entry block (true entry, no predecessors).
	//
	// IMPORTANT: the entry block can still gain predecessors later (e.g. due to a back-edge/self-loop
	// discovered while building the CFG). In that case we must NOT early-return an empty stack,
	// otherwise CFG build can get stuck in a rebuild loop for self-loops. Only treat it as a "true"
	// entry when there are no recorded incomings at all.
	if block.blockNum == 0 && block.entryStack == nil && len(block.parents) == 0 && len(block.incomingStacks) == 0 {
		// Make the "known empty" entry snapshot explicit (non-nil) so later logic can distinguish
		// between "unknown/uncomputed" vs "computed empty".
		block.SetEntryStack([]Value{})
		return stack
	}

	// Case 2: First visit or invalidated entry (entryStack == nil)
	//
	// Build entry stack from recorded incomingStacks, inserting PHIs when values differ.
	if block.entryStack == nil {
		// Gather incoming snapshots in a deterministic order based on parents slice.
		incomings := make([][]Value, 0, len(block.parents))
		for _, p := range block.parents {
			if p == nil {
				continue
			}
			if s, ok := block.incomingStacks[p]; ok {
				incomings = append(incomings, s)
			}
		}
		// Fallback: if parents list is empty but incomingStacks exists, use all snapshots.
		if len(incomings) == 0 && len(block.incomingStacks) > 0 {
			for _, s := range block.incomingStacks {
				incomings = append(incomings, s)
			}
		}
		if len(incomings) == 0 {
			return stack
		}
		// EVM requires identical stack height at merge points. During dynamic CFG expansion we can
		// temporarily record infeasible edges with a different stack height; padding them with
		// Unknown values poisons PHI generation (and later leads to Unknown->0 at runtime).
		//
		// Strategy: keep only the most common incoming stack height, breaking ties toward the
		// smaller height (safer than assuming extra values exist).
		modeLen := len(incomings[0])
		if len(incomings) > 1 {
			counts := make(map[int]int, 4)
			for _, s := range incomings {
				counts[len(s)]++
			}
			modeCnt := -1
			modeLen = -1
			for l, c := range counts {
				if c > modeCnt || (c == modeCnt && (modeLen < 0 || l < modeLen)) {
					modeLen = l
					modeCnt = c
				}
			}
			filtered := make([][]Value, 0, len(incomings))
			for _, s := range incomings {
				if len(s) == modeLen {
					filtered = append(filtered, s)
				}
			}
			if len(filtered) > 0 {
				incomings = filtered
			}
		}
		height := modeLen

		for i := 0; i < height; i++ {
			base := incomings[0][i]
			same := true
			for j := 1; j < len(incomings); j++ {
				v := incomings[j][i]
				if !equalValueForFlow(&base, &v) {
					same = false
					break
				}
			}
			if same {
				valCopy := base
				valCopy.liveIn = true
				stack.push(&valCopy)
				continue
			}
			// Create PHI merging all incoming values at this stack slot.
			ops := make([]*Value, 0, len(incomings))
			for _, s := range incomings {
				v := s[i]
				v.liveIn = true
				vv := v // heap allocate per-operand
				ops = append(ops, &vv)
			}
			// phiStackIndex is 0 for top-of-stack.
			phiStackIndex := (height - 1) - i
			block.CreatePhiMIR(ops, stack, phiStackIndex)
		}
		block.SetEntryStack(stack.data)
		return stack
	}

	// Case 3: Re-visit (Block already has an entry stack snapshot)
	// We instantiate a working stack from the snapshot.
	for _, val := range block.entryStack {
		stack.push(&val)
	}
	return stack
}

// connectEdge links parent -> child and records the incoming stack snapshot for child.
// If the incoming snapshot for this (parent,child) pair changed, invalidate child's entry stack
// and mark it for rebuild (PHI may be required later).
func (c *CFG) connectEdge(parent, child *MIRBasicBlock, exitSnapshot []Value) {
	if parent == nil || child == nil {
		return
	}
	// Append edge (parent -> child) without clobbering existing edges.
	// Many real-world contracts (jump tables, loops) have multiple predecessors/successors.
	// Overwriting here corrupts CFG structure and PHI construction.
	{
		children := parent.Children()
		found := false
		for _, ch := range children {
			if ch == child {
				found = true
				break
			}
		}
		if !found {
			children = append(children, child)
			parent.SetChildren(children)
		}
	}
	{
		parents := child.Parents()
		found := false
		for _, p := range parents {
			if p == parent {
				found = true
				break
			}
		}
		if !found {
			parents = append(parents, parent)
			child.SetParents(parents)
		}
	}
	// Treat nil snapshot as an empty stack snapshot (important to record the predecessor).
	if exitSnapshot == nil {
		exitSnapshot = []Value{}
	}
	// Only invalidate if this parent's incoming snapshot changed.
	if prev, ok := child.incomingStacks[parent]; ok {
		if stacksEqual(prev, exitSnapshot) {
			return
		}
	}
	child.AddIncomingStack(parent, exitSnapshot)
	child.SetEntryStack(nil)
	child.built = false
	// Conservative: when a block's incoming stack changes, its PHI set (and thus defs) can change,
	// which can invalidate downstream blocks that captured stale defs. Mark descendants for rebuild
	// so we don't attempt to execute with dangling def pointers.
	c.markDescendantsForRebuild(child)
}

func (c *CFG) markDescendantsForRebuild(start *MIRBasicBlock) {
	if start == nil {
		return
	}
	visited := make(map[*MIRBasicBlock]struct{}, 32)
	q := []*MIRBasicBlock{start}
	visited[start] = struct{}{}
	for len(q) > 0 {
		b := q[0]
		q = q[1:]
		// Force rebuild on next entry.
		b.built = false
		b.SetEntryStack(nil)
		for _, ch := range b.Children() {
			if ch == nil {
				continue
			}
			if _, ok := visited[ch]; ok {
				continue
			}
			visited[ch] = struct{}{}
			q = append(q, ch)
		}
	}
}

func (c *CFG) buildBasicBlock(block *MIRBasicBlock, validJumpDests map[uint]bool) error {
	// Set current CFG build context for MIR resIdx allocation.
	// This also covers dynamic backfill builds invoked at runtime.
	currentCFGBuild = c
	defer func() { currentCFGBuild = nil }()

	pc := block.firstPC
	codeLen := uint(len(c.rawCode))

	// 1. Initialize Stack
	// Ensure any PHIs created as part of entry stack construction get a stable EVM mapping
	// (otherwise they may inherit a stale currentEVMBuildPC/currentEVMBuildOp from a previous block).
	currentEVMBuildPC = pc
	if pc < codeLen {
		currentEVMBuildOp = c.rawCode[pc]
	} else {
		currentEVMBuildOp = 0
	}
	stack := c.getEntryStackForBlock(block)

	for pc < codeLen {
		op := compiler.ByteCode(c.rawCode[pc])

		// Global tracking for MIR generation
		currentEVMBuildPC = pc
		currentEVMBuildOp = byte(op)

		// 2. Check for Basic Block Boundaries (Implicit)
		// If we are NOT at the start of the block, but we hit a JUMPDEST,
		// then this block MUST end here (fallthrough to the next block).
		if pc != block.firstPC && op == compiler.JUMPDEST {
			// Record block end. This is a fallthrough edge, not an executed JUMP opcode.
			block.SetLastPC(pc)
			// Record exit stack snapshot (used by later PHI/merge logic)
			exitSnap := stack.clone()
			block.SetExitStack(exitSnap)
			// Link to next block and record incoming snapshot
			nextBlock := c.getOrCreateBlock(pc)
			c.connectEdge(block, nextBlock, exitSnap)

			block.built = true
			return nil
		}

		// Count every originating EVM opcode for gas parity bookkeeping.
		// IMPORTANT: this must happen *after* the boundary split check above, otherwise
		// we'd count a boundary JUMPDEST in the predecessor block and overcharge by 1 gas.
		if block.evmOpCounts != nil {
			block.evmOpCounts[byte(op)]++
		}
		// Also record the exact opcode stream (pc,op) for this block (used for GAS/call gas correctness).
		block.recordEVMOp(pc, byte(op))

		// 2.5 Handle no-op JUMPDEST (valid instruction, may only appear at block start here)
		if op == compiler.JUMPDEST {
			// We don't need to emit MIR for JUMPDEST; it is a marker.
			pc++
			continue
		}

		// 3. Dispatch Opcode Groups
		var err error
		switch {
		case isStackOp(op): // PUSH, DUP, SWAP, POP
			pc, err = c.handleStackOp(block, op, stack, pc)
		case isUnaryOp(op):
			// Map EVM unary opcode to MIR op by meaning
			var mirOp MirOperation
			switch op {
			case compiler.NOT:
				mirOp = MirNOT
			case compiler.ISZERO:
				mirOp = MirISZERO
			default:
				return fmt.Errorf("unhandled unary opcode: %x at %d", op, pc)
			}
			block.CreateUnaryOpMIR(mirOp, stack)
			pc++
		case isTernaryOp(op):
			var mirOp MirOperation
			switch op {
			case compiler.ADDMOD:
				mirOp = MirADDMOD
			case compiler.MULMOD:
				mirOp = MirMULMOD
			default:
				return fmt.Errorf("unhandled ternary opcode: %x at %d", op, pc)
			}
			block.CreateTernaryOpMIR(mirOp, stack)
			pc++
		case isBinaryOp(op):
			// Most binary ops share the same numeric encoding for MIR up to 0x5e.
			// Map explicitly for clarity and to avoid relying on enum alignment.
			var mirOp MirOperation
			switch op {
			case compiler.ADD:
				mirOp = MirADD
			case compiler.MUL:
				mirOp = MirMUL
			case compiler.SUB:
				mirOp = MirSUB
			case compiler.DIV:
				mirOp = MirDIV
			case compiler.SDIV:
				mirOp = MirSDIV
			case compiler.MOD:
				mirOp = MirMOD
			case compiler.SMOD:
				mirOp = MirSMOD
			case compiler.EXP:
				mirOp = MirEXP
			case compiler.SIGNEXTEND:
				mirOp = MirSIGNEXT
			case compiler.LT:
				mirOp = MirLT
			case compiler.GT:
				mirOp = MirGT
			case compiler.SLT:
				mirOp = MirSLT
			case compiler.SGT:
				mirOp = MirSGT
			case compiler.EQ:
				mirOp = MirEQ
			case compiler.AND:
				mirOp = MirAND
			case compiler.OR:
				mirOp = MirOR
			case compiler.XOR:
				mirOp = MirXOR
			case compiler.BYTE:
				mirOp = MirBYTE
			case compiler.SHL:
				mirOp = MirSHL
			case compiler.SHR:
				mirOp = MirSHR
			case compiler.SAR:
				mirOp = MirSAR
			case compiler.KECCAK256:
				mirOp = MirKECCAK256
			default:
				return fmt.Errorf("unhandled binary opcode: %x at %d", op, pc)
			}
			block.CreateBinOpMIR(mirOp, stack)
			pc++
		case isMemoryOp(op):
			switch op {
			case compiler.MLOAD:
				// MLOAD pops: offset, pushes: value
				offset := stack.pop()
				mir := new(MIR)
				mir.op = MirMLOAD
				mir.operands = []*Value{&offset}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSTORE:
				// MSTORE pops: offset(top), value. No return value.
				offset := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirMSTORE
				mir.operands = []*Value{&offset, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSTORE8:
				// MSTORE8 pops: offset(top), value. No return value.
				offset := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirMSTORE8
				mir.operands = []*Value{&offset, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSIZE:
				// MSIZE pushes current memory size. No pops.
				mir := new(MIR)
				mir.op = MirMSIZE
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MCOPY:
				// MCOPY pops: dst, src, size (EIP-5656). No return value.
				dst := stack.pop()
				src := stack.pop()
				sz := stack.pop()
				mir := new(MIR)
				mir.op = MirMCOPY
				mir.operands = []*Value{&dst, &src, &sz}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled memory opcode: %x at %d", op, pc)
			}
			pc++
		case isStorageOp(op):
			switch op {
			case compiler.SLOAD:
				// SLOAD pops: key, pushes: value
				key := stack.pop()
				mir := new(MIR)
				mir.op = MirSLOAD
				mir.operands = []*Value{&key}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.SSTORE:
				// SSTORE pops: key(top), value. No return value.
				key := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirSSTORE
				mir.operands = []*Value{&key, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.TLOAD:
				// TLOAD pops: key, pushes: value
				key := stack.pop()
				mir := new(MIR)
				mir.op = MirTLOAD
				mir.operands = []*Value{&key}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.TSTORE:
				// TSTORE pops: key(top), value. No return value.
				key := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirTSTORE
				mir.operands = []*Value{&key, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled storage opcode: %x at %d", op, pc)
			}
			pc++
		case isBlockInfoOp(op):
			// Closure/tx/env info ops handled by CreateBlockInfoMIR
			block.CreateBlockInfoMIR(MirOperation(byte(op)), stack)
			pc++
		case isBlockOp(op):
			// Block ops handled by CreateBlockOpMIR
			block.CreateBlockOpMIR(MirOperation(byte(op)), stack)
			pc++
		case isLogOp(op):
			block.CreateLogMIR(MirLOG0+MirOperation(op-compiler.LOG0), stack)
			pc++
		case isSystemCallOp(op):
			// Implement core CALL/CREATE family with correct stack effects.
			// Note: opcode values in compiler package differ from MirOperation for some calls.
			switch op {
			case compiler.CALL:
				// EVM stack (top to bottom): gas, to, value, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				value := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirCALL
				mir.operands = []*Value{&gas, &to, &value, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CALLCODE:
				// EVM stack (top to bottom): gas, to, value, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				value := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirCALLCODE
				mir.operands = []*Value{&gas, &to, &value, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.DELEGATECALL:
				// EVM stack (top to bottom): gas, to, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirDELEGATECALL
				mir.operands = []*Value{&gas, &to, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.STATICCALL:
				// EVM stack (top to bottom): gas, to, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirSTATICCALL
				mir.operands = []*Value{&gas, &to, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CREATE:
				sz := stack.pop()
				off := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirCREATE
				mir.operands = []*Value{&value, &off, &sz}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CREATE2:
				salt := stack.pop()
				sz := stack.pop()
				off := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirCREATE2
				mir.operands = []*Value{&value, &off, &sz, &salt}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTCALL:
				// Treat as system op: stack semantics are chain-specific; placeholder to keep CFG build going.
				mir := new(MIR)
				mir.op = MirEXTCALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTDELEGATECALL:
				mir := new(MIR)
				mir.op = MirEXTDELEGATECALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTSTATICCALL:
				mir := new(MIR)
				mir.op = MirEXTSTATICCALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled system/call opcode: %x at %d", op, pc)
			}
			pc++
		// Terminators / control flow
		case op == compiler.STOP:
			// STOP: end execution, no operands
			mir := new(MIR)
			mir.op = MirSTOP
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.RETURN:
			// RETURN pops: offset, size
			offset := stack.pop()
			size := stack.pop()
			mir := new(MIR)
			mir.op = MirRETURN
			mir.operands = []*Value{&offset, &size}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.REVERT:
			// REVERT pops: offset, size
			offset := stack.pop()
			size := stack.pop()
			mir := new(MIR)
			mir.op = MirREVERT
			mir.operands = []*Value{&offset, &size}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.SELFDESTRUCT:
			// SELFDESTRUCT pops: address
			addr := stack.pop()
			mir := new(MIR)
			mir.op = MirSELFDESTRUCT
			mir.operands = []*Value{&addr}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.INVALID:
			// INVALID: immediate exceptional halt
			mir := new(MIR)
			mir.op = MirINVALID
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.JUMP:
			// JUMP pops: dest
			dest := stack.pop()
			mir := new(MIR)
			mir.op = MirJUMP
			mir.operands = []*Value{&dest}
			block.appendMIR(mir)

			// Resolve successor if constant; otherwise mark as unresolved for runtime backfill.
			exitSnap := stack.clone()
			if dest.kind == Konst {
				target := uint(0)
				if dest.u != nil {
					target = uint(dest.u.Uint64())
				} else {
					target = uint(dest.ConstValue())
				}
				if !validJumpDests[target] {
					return fmt.Errorf("invalid jumpdest 0x%x at pc %d", target, pc)
				}
				targetBlock := c.getOrCreateBlock(target)
				c.connectEdge(block, targetBlock, exitSnap)
				// Self-loop may invalidate this block's entryStack; request rebuild by leaving built=false.
				if targetBlock == block && block.entryStack == nil {
					block.SetLastPC(pc + 1)
					block.SetExitStack(exitSnap)
					block.built = false
					return nil
				}
			} else {
				block.unresolvedJump = true
			}

			block.SetLastPC(pc + 1)
			block.SetExitStack(exitSnap)
			block.built = true
			return nil
		case op == compiler.JUMPI:
			// JUMPI pops: dest, cond (note: CreateJumpMIR in MIRBasicBlock.go pops dest then cond)
			dest := stack.pop()
			cond := stack.pop()
			mir := new(MIR)
			mir.op = MirJUMPI
			mir.operands = []*Value{&dest, &cond}
			block.appendMIR(mir)

			// Fallthrough successor (pc+1)
			exitSnap := stack.clone()
			fallthroughPC := pc + 1
			fallthroughBlock := c.getOrCreateBlock(fallthroughPC)
			c.connectEdge(block, fallthroughBlock, exitSnap)

			// Branch successor if constant dest
			if dest.kind == Konst {
				target := uint(0)
				if dest.u != nil {
					target = uint(dest.u.Uint64())
				} else {
					target = uint(dest.ConstValue())
				}
				if !validJumpDests[target] {
					return fmt.Errorf("invalid jumpdest 0x%x at pc %d", target, pc)
				}
				targetBlock := c.getOrCreateBlock(target)
				c.connectEdge(block, targetBlock, exitSnap)
				if targetBlock == block && block.entryStack == nil {
					block.SetLastPC(pc + 1)
					block.SetExitStack(exitSnap)
					block.built = false
					return nil
				}
			} else {
				// Dynamic target: keep fallthrough edge; runtime will resolve jump target and backfill CFG.
				block.unresolvedJump = true
			}

			block.SetLastPC(pc + 1)
			block.SetExitStack(exitSnap)
			block.built = true
			return nil
		default:
			// Placeholder for now
			return fmt.Errorf("unsupported opcode: %x at %d", op, pc)
		}

		if err != nil {
			return err
		}
	}

	// End of code reached without explicit terminator
	block.CreateSystemOpMIR(MirSTOP, stack)
	block.SetLastPC(pc)
	block.SetExitStack(stack.clone())
	block.built = true
	return nil
}

// Helpers

func isStackOp(op compiler.ByteCode) bool {
	return (op == compiler.PUSH0) ||
		(op >= compiler.PUSH1 && op <= compiler.PUSH32) ||
		(op >= compiler.DUP1 && op <= compiler.DUP16) ||
		(op >= compiler.SWAP1 && op <= compiler.SWAP16) ||
		(op == compiler.POP)
}

func (c *CFG) handleStackOp(block *MIRBasicBlock, op compiler.ByteCode, stack *ValueStack, pc uint) (uint, error) {
	// PUSH0 pushes a single zero byte (EIP-3855)
	if op == compiler.PUSH0 {
		block.CreatePushMIR(0, []byte{0x00}, stack)
		return pc + 1, nil
	}

	// Handle PUSH specially because it has immediate data
	if op >= compiler.PUSH1 && op <= compiler.PUSH32 {
		size := uint(op - compiler.PUSH1 + 1)
		if pc+1+size > uint(len(c.rawCode)) {
			return pc, fmt.Errorf("truncated PUSH instruction at %d", pc)
		}
		data := c.rawCode[pc+1 : pc+1+size]
		block.CreatePushMIR(int(size), data, stack)
		return pc + 1 + size, nil
	}

	// Map EVM opcode to MIR Operation
	var mirOp MirOperation
	switch {
	case op == compiler.POP:
		// POP pops 1 element, produces no result
		v := stack.pop()
		mir := new(MIR)
		mir.op = MirPOP
		mir.operands = []*Value{&v}
		mir = block.appendMIR(mir)
		mir.genStackDepth = stack.size()
		return pc + 1, nil
	case op >= compiler.DUP1 && op <= compiler.DUP16:
		mirOp = MirDUP1 + MirOperation(op-compiler.DUP1)
	case op >= compiler.SWAP1 && op <= compiler.SWAP16:
		mirOp = MirSWAP1 + MirOperation(op-compiler.SWAP1)
	}

	block.CreateStackOpMIR(mirOp, stack)
	return pc + 1, nil
}

func isLogOp(op compiler.ByteCode) bool {
	return op >= compiler.LOG0 && op <= compiler.LOG4
}

func isUnaryOp(op compiler.ByteCode) bool {
	return op == compiler.NOT || op == compiler.ISZERO
}

func isTernaryOp(op compiler.ByteCode) bool {
	return op == compiler.ADDMOD || op == compiler.MULMOD
}

func isBinaryOp(op compiler.ByteCode) bool {
	// Arithmetic & bitwise & compare & shifts & byte & signextend & keccak
	switch op {
	case compiler.ADD, compiler.MUL, compiler.SUB, compiler.DIV, compiler.SDIV, compiler.MOD, compiler.SMOD,
		compiler.EXP, compiler.SIGNEXTEND,
		compiler.LT, compiler.GT, compiler.SLT, compiler.SGT, compiler.EQ,
		compiler.AND, compiler.OR, compiler.XOR, compiler.BYTE, compiler.SHL, compiler.SHR, compiler.SAR,
		compiler.KECCAK256:
		return true
	default:
		return false
	}
}

func isMemoryOp(op compiler.ByteCode) bool {
	switch op {
	case compiler.MLOAD, compiler.MSTORE, compiler.MSTORE8, compiler.MSIZE, compiler.MCOPY:
		return true
	default:
		return false
	}
}

func isStorageOp(op compiler.ByteCode) bool {
	return op == compiler.SLOAD || op == compiler.SSTORE || op == compiler.TLOAD || op == compiler.TSTORE
}

func isBlockInfoOp(op compiler.ByteCode) bool {
	// closure state + a few misc producers/consumers handled by CreateBlockInfoMIR
	return (op >= compiler.ADDRESS && op <= compiler.EXTCODEHASH) ||
		op == compiler.PC || op == compiler.GAS
}

func isBlockOp(op compiler.ByteCode) bool {
	// block environment ops
	return op >= compiler.BLOCKHASH && op <= compiler.BLOBBASEFEE
}

func isSystemCallOp(op compiler.ByteCode) bool {
	// CALL-family + CREATE-family + STATICCALL (note: opcode values may differ from MIR op enum)
	switch op {
	case compiler.CREATE, compiler.CALL, compiler.CALLCODE, compiler.DELEGATECALL, compiler.CREATE2, compiler.STATICCALL,
		compiler.EXTCALL, compiler.EXTDELEGATECALL, compiler.EXTSTATICCALL:
		return true
	default:
		return false
	}
}
