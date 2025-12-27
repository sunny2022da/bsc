package MIR

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
)

// CFG is the IR record the control flow of the contract.
// It records not only the control flow info but also the state and memory accesses.
// CFG is mapping to <addr, code> pair, and there is no need to record CFG for every contract
// since it is just an IR, although the analyzing/compiling results are saved to the related cache.
type CFG struct {
	codeAddr        common.Hash
	rawCode         []byte
	basicBlocks     []*MIRBasicBlock
	basicBlockCount uint

	// Mapping from EVM PC to the BasicBlock starting at that PC
	pcToBlock map[uint]*MIRBasicBlock
}

func NewCFG(hash common.Hash, code []byte) (c *CFG) {
	c = &CFG{}
	c.codeAddr = hash
	c.rawCode = code
	c.basicBlocks = []*MIRBasicBlock{}
	c.basicBlockCount = 0

	c.pcToBlock = make(map[uint]*MIRBasicBlock)
	return c
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
	// 1. Identify all valid JUMPDESTs (critical for security/validity)
	// You can use a bitset or map for fast lookup.
	validJumpDests := c.scanJumpDests()

	// 2. Create the Entry Block (Block 0) at PC 0
	entryBlock := c.getOrCreateBlock(0)

	// 3. Worklist for processing blocks
	// Queue stores blocks that need to be built.
	queue := []*MIRBasicBlock{entryBlock}

	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]

		// If already built successfully with compatible stack, skip
		if block.built {
			continue
		}

		// Build the block (emit MIR instructions)
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

	// Case 1: Entry Block (No parents)
	if block.blockNum == 0 {
		return stack
	}

	// Case 2: First visit (No established entry stack yet)
	if block.entryStack == nil {
		if len(block.parents) > 0 {
			// Inherit blindly from the first parent.
			// Ideally, we check all parents, but in a worklist algo, we usually
			// process one parent first.
			parent := block.parents[0]
			if parent.exitStack != nil {
				for _, val := range parent.exitStack {
					valCopy := val
					// Mark as LiveIn so we know it came from outside this block.
					// This effectively treats it as a "variable" or "parameter" to the block.
					valCopy.liveIn = true
					// Clear definition pointer if we want to be strict about not optimizing across blocks yet
					// valCopy.def = nil
					stack.push(&valCopy)
				}
				block.SetEntryStack(stack.data)
			}
		}
		return stack
	}

	// Case 3: Re-visit (Block already has an entry stack snapshot)
	// We instantiate a working stack from the snapshot.
	for _, val := range block.entryStack {
		stack.push(&val)
	}
	return stack
}

func (c *CFG) buildBasicBlock(block *MIRBasicBlock, validJumpDests map[uint]bool) error {
	pc := block.firstPC
	codeLen := uint(len(c.rawCode))

	// 1. Initialize Stack
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
			// Link to the next block
			nextBlock := c.getOrCreateBlock(pc)
			block.SetChildren([]*MIRBasicBlock{nextBlock})
			nextBlock.SetParents([]*MIRBasicBlock{block})

			// Emit a Jump to it (Conceptually a fallthrough)
			block.CreateControlFlowMIR(MirJUMP, stack)

			block.built = true
			return nil
		}

		// 3. Dispatch Opcode Groups
		var err error
		switch {
		case isStackOp(op): // PUSH, DUP, SWAP, POP
			pc, err = c.handleStackOp(block, op, stack, pc)
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
	block.built = true
	return nil
}

// Helpers

func isStackOp(op compiler.ByteCode) bool {
	return (op >= compiler.PUSH1 && op <= compiler.PUSH32) ||
		(op >= compiler.DUP1 && op <= compiler.DUP16) ||
		(op >= compiler.SWAP1 && op <= compiler.SWAP16) ||
		(op == compiler.POP)
}

func (c *CFG) handleStackOp(block *MIRBasicBlock, op compiler.ByteCode, stack *ValueStack, pc uint) (uint, error) {
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
		mirOp = MirPOP
	case op >= compiler.DUP1 && op <= compiler.DUP16:
		mirOp = MirDUP1 + MirOperation(op-compiler.DUP1)
	case op >= compiler.SWAP1 && op <= compiler.SWAP16:
		mirOp = MirSWAP1 + MirOperation(op-compiler.SWAP1)
	}

	block.CreateStackOpMIR(mirOp, stack)
	return pc + 1, nil
}
