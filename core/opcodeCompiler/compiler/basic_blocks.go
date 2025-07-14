package compiler

import (
	"errors"
)

// BasicBlock represents a basic block in the bytecode
type BasicBlock struct {
	StartPC    uint64  // Program counter where this block starts
	EndPC      uint64  // Program counter where this block ends (exclusive)
	Opcodes    []byte  // The actual opcodes in this block
	JumpTarget *uint64 // If this block ends with a jump, the target PC
	IsJumpDest bool    // Whether this block starts with a JUMPDEST
}

// GenerateBasicBlocks generates basic blocks from bytecode
func GenerateBasicBlocks(code []byte) []BasicBlock {
	if len(code) == 0 {
		return nil
	}

	var blocks []BasicBlock
	var currentBlock BasicBlock
	currentBlock.StartPC = 0

	for pc := uint64(0); pc < uint64(len(code)); {
		op := ByteCode(code[pc])

		// Check if this is a JUMPDEST (start of a new block)
		if op == JUMPDEST {
			// End the current block if it has content
			if currentBlock.EndPC > currentBlock.StartPC {
				currentBlock.Opcodes = code[currentBlock.StartPC:currentBlock.EndPC]
				blocks = append(blocks, currentBlock)
			}

			// Start a new block
			currentBlock = BasicBlock{
				StartPC:    pc,
				EndPC:      pc,
				IsJumpDest: true,
			}
		}

		// Check if this instruction is a terminator
		if isBlockTerminator(op) {
			currentBlock.EndPC = pc + 1
			currentBlock.Opcodes = code[currentBlock.StartPC:currentBlock.EndPC]

			// Extract jump target if this is a jump instruction
			if op == JUMP || op == JUMPI {
				target := extractJumpTarget(currentBlock, code)
				currentBlock.JumpTarget = &target
			}

			blocks = append(blocks, currentBlock)

			// Start a new block (if not at the end)
			if pc+1 < uint64(len(code)) {
				currentBlock = BasicBlock{
					StartPC: pc + 1,
					EndPC:   pc + 1,
				}
			}
		} else {
			// Skip data bytes for PUSH instructions
			skip, steps := calculateSkipSteps(code, int(pc))
			if skip {
				pc += uint64(steps)
			} else {
				pc++
			}
			currentBlock.EndPC = pc
		}
	}

	// Add the last block if it has content
	if currentBlock.EndPC > currentBlock.StartPC {
		currentBlock.Opcodes = code[currentBlock.StartPC:currentBlock.EndPC]
		blocks = append(blocks, currentBlock)
	}

	return blocks
}

// isBlockTerminator checks if an opcode terminates a basic block
func isBlockTerminator(op ByteCode) bool {
	switch op {
	case STOP, RETURN, REVERT, SELFDESTRUCT, // Exit instructions
		JUMP, JUMPI, // Jump instructions
		RJUMP, RJUMPI, RJUMPV, // Relative jump instructions
		CALLF, RETF, JUMPF: // Function call instructions
		return true
	default:
		return false
	}
}

// CFGNode represents a node in the Control Flow Graph
type CFGNode struct {
	BlockIndex     int        // Index of the basic block in the blocks array
	Block          BasicBlock // The basic block this node represents
	Successors     []int      // Indices of successor blocks
	Predecessors   []int      // Indices of predecessor blocks
	Dominators     []int      // Indices of blocks that dominate this block
	PostDominators []int      // Indices of blocks that post-dominate this block
}

// CFG represents a Control Flow Graph
type CFG struct {
	Nodes  []CFGNode    // All nodes in the CFG
	Blocks []BasicBlock // The basic blocks
	Entry  int          // Index of the entry block
	Exit   int          // Index of the exit block (if any)
}

// buildCFG builds a Control Flow Graph from basic blocks
func buildCFG(blocks []BasicBlock, code []byte) (*CFG, error) {
	if len(blocks) == 0 {
		return nil, errors.New("no basic blocks to build CFG from")
	}

	cfg := &CFG{
		Blocks: blocks,
		Entry:  0,
		Exit:   -1,
	}

	// Initialize nodes
	cfg.Nodes = make([]CFGNode, len(blocks))
	for i, block := range blocks {
		cfg.Nodes[i] = CFGNode{
			BlockIndex: i,
			Block:      block,
		}
	}

	// Build edges
	for i, block := range blocks {
		successors := findBlockSuccessors(block, blocks, code)
		cfg.Nodes[i].Successors = successors

		// Add this block as a predecessor to its successors
		for _, succ := range successors {
			if succ >= 0 && succ < len(cfg.Nodes) {
				cfg.Nodes[succ].Predecessors = append(cfg.Nodes[succ].Predecessors, i)
			}
		}
	}

	// Compute dominators
	computeDominators(cfg)

	// Compute post-dominators
	computePostDominators(cfg)

	return cfg, nil
}

// findBlockSuccessors finds the successor blocks of a given block
func findBlockSuccessors(block BasicBlock, blocks []BasicBlock, code []byte) []int {
	var successors []int

	// If block has a jump target, add it as successor
	if block.JumpTarget != nil {
		targetBlock := findBlockByPC(blocks, *block.JumpTarget)
		if targetBlock >= 0 {
			successors = append(successors, targetBlock)
		}
	}

	// If block doesn't end with an exit instruction, add the next block
	if len(block.Opcodes) > 0 {
		lastOp := ByteCode(block.Opcodes[len(block.Opcodes)-1])
		if !isExitOpcode(lastOp) {
			nextBlock := findNextBlock(blocks, block.EndPC)
			if nextBlock >= 0 {
				successors = append(successors, nextBlock)
			}
		}
	}

	// For conditional jumps, add both the jump target and the fall-through
	if len(block.Opcodes) > 0 {
		lastOp := ByteCode(block.Opcodes[len(block.Opcodes)-1])
		if lastOp == JUMPI {
			// Add fall-through block
			nextBlock := findNextBlock(blocks, block.EndPC)
			if nextBlock >= 0 {
				successors = append(successors, nextBlock)
			}
		}
	}

	// For dynamic jumps, conservatively add all JUMPDEST blocks
	if len(block.Opcodes) > 0 {
		lastOp := ByteCode(block.Opcodes[len(block.Opcodes)-1])
		if lastOp == JUMP || lastOp == JUMPI {
			// Check if this is a dynamic jump (no constant target)
			if block.JumpTarget == nil {
				// Add all JUMPDEST blocks as potential successors
				for i, b := range blocks {
					if b.IsJumpDest {
						successors = append(successors, i)
					}
				}
			}
		}
	}

	return successors
}

// extractJumpTarget extracts the jump target from a block
func extractJumpTarget(block BasicBlock, code []byte) uint64 {
	// Look for PUSH1 followed by JUMP/JUMPI pattern (constant targets only)
	for i := 0; i < len(block.Opcodes)-2; i++ {
		if ByteCode(block.Opcodes[i]) == PUSH1 {
			// Check if the next instruction is JUMP or JUMPI
			if i+2 < len(block.Opcodes) {
				nextOp := ByteCode(block.Opcodes[i+2])
				if nextOp == JUMP || nextOp == JUMPI {
					// Extract the 1-byte target
					return uint64(block.Opcodes[i+1])
				}
			}
		}
	}

	// Look for PUSH2 followed by JUMP/JUMPI pattern (constant targets only)
	for i := 0; i < len(block.Opcodes)-3; i++ {
		if ByteCode(block.Opcodes[i]) == PUSH2 {
			// Check if the next instruction is JUMP or JUMPI
			if i+3 < len(block.Opcodes) {
				nextOp := ByteCode(block.Opcodes[i+3])
				if nextOp == JUMP || nextOp == JUMPI {
					// Extract the 2-byte target
					return uint64(block.Opcodes[i+1])<<8 | uint64(block.Opcodes[i+2])
				}
			}
		}
	}

	return 0
}

// findBlockByPC finds the block containing a given PC
func findBlockByPC(blocks []BasicBlock, pc uint64) int {
	for i, block := range blocks {
		if pc >= block.StartPC && pc < block.EndPC {
			return i
		}
	}
	return -1
}

// findNextBlock finds the block that starts at the given PC
func findNextBlock(blocks []BasicBlock, pc uint64) int {
	for i, block := range blocks {
		if block.StartPC == pc {
			return i
		}
	}
	return -1
}

// isExitOpcode checks if an opcode causes the program to exit
func isExitOpcode(op ByteCode) bool {
	switch op {
	case STOP, RETURN, REVERT, SELFDESTRUCT:
		return true
	default:
		return false
	}
}

// computeDominators computes the dominators for each node in the CFG
func computeDominators(cfg *CFG) {
	// Initialize dominators
	for i := range cfg.Nodes {
		cfg.Nodes[i].Dominators = make([]int, len(cfg.Nodes))
		for j := range cfg.Nodes[i].Dominators {
			cfg.Nodes[i].Dominators[j] = j
		}
	}

	// Entry node dominates only itself
	cfg.Nodes[cfg.Entry].Dominators = []int{cfg.Entry}

	// Iteratively compute dominators
	changed := true
	for changed {
		changed = false
		for i := range cfg.Nodes {
			if i == cfg.Entry {
				continue
			}

			// Find intersection of dominators of predecessors
			var newDominators []int
			for _, pred := range cfg.Nodes[i].Predecessors {
				if len(newDominators) == 0 {
					newDominators = append(newDominators, cfg.Nodes[pred].Dominators...)
				} else {
					newDominators = intersect(newDominators, cfg.Nodes[pred].Dominators)
				}
			}

			// Add this node to its own dominators
			newDominators = append(newDominators, i)

			// Check if dominators changed
			if !equalSlices(cfg.Nodes[i].Dominators, newDominators) {
				cfg.Nodes[i].Dominators = newDominators
				changed = true
			}
		}
	}
}

// computePostDominators computes the post-dominators for each node in the CFG
func computePostDominators(cfg *CFG) {
	// Initialize post-dominators
	for i := range cfg.Nodes {
		cfg.Nodes[i].PostDominators = make([]int, len(cfg.Nodes))
		for j := range cfg.Nodes[i].PostDominators {
			cfg.Nodes[i].PostDominators[j] = j
		}
	}

	// Find exit nodes (nodes with no successors)
	var exitNodes []int
	for i, node := range cfg.Nodes {
		if len(node.Successors) == 0 {
			exitNodes = append(exitNodes, i)
		}
	}

	// If no exit nodes, use the last node
	if len(exitNodes) == 0 {
		exitNodes = []int{len(cfg.Nodes) - 1}
	}

	// Exit nodes post-dominate only themselves
	for _, exit := range exitNodes {
		cfg.Nodes[exit].PostDominators = []int{exit}
	}

	// Iteratively compute post-dominators
	changed := true
	for changed {
		changed = false
		for i := range cfg.Nodes {
			isExit := false
			for _, exit := range exitNodes {
				if i == exit {
					isExit = true
					break
				}
			}
			if isExit {
				continue
			}

			// Find intersection of post-dominators of successors
			var newPostDominators []int
			for _, succ := range cfg.Nodes[i].Successors {
				if len(newPostDominators) == 0 {
					newPostDominators = append(newPostDominators, cfg.Nodes[succ].PostDominators...)
				} else {
					newPostDominators = intersect(newPostDominators, cfg.Nodes[succ].PostDominators)
				}
			}

			// Add this node to its own post-dominators
			newPostDominators = append(newPostDominators, i)

			// Check if post-dominators changed
			if !equalSlices(cfg.Nodes[i].PostDominators, newPostDominators) {
				cfg.Nodes[i].PostDominators = newPostDominators
				changed = true
			}
		}
	}
}

// intersect returns the intersection of two sorted slices
func intersect(a, b []int) []int {
	var result []int
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			result = append(result, a[i])
			i++
			j++
		} else if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return result
}

// equalSlices checks if two slices are equal
func equalSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
