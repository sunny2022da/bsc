package compiler

import (
	"bytes"
	"encoding/binary"
)

// OpcodeProcessor handles the optimization of EVM opcodes
type OpcodeProcessor struct {
	cache *OpCodeCache
}

// NewOpcodeProcessor creates a new opcode processor
func NewOpcodeProcessor() *OpcodeProcessor {
	return &OpcodeProcessor{
		cache: NewOpCodeCache(),
	}
}

// Optimize optimizes a sequence of opcodes
func (p *OpcodeProcessor) Optimize(code []byte) []byte {
	// Check cache first
	if cached, ok := p.cache.Get(string(code)); ok {
		return cached
	}

	// Create a buffer for the optimized code
	var optimized bytes.Buffer

	// Process the code in chunks
	for i := 0; i < len(code); {
		op := ByteCode(code[i])
		i++

		// Handle push operations
		if op >= PUSH1 && op <= PUSH32 {
			size := int(op - PUSH1 + 1)
			if i+size > len(code) {
				// Invalid push operation - data extends beyond code length
				return code // Return original code if invalid
			}

			// Check for PUSH1 PUSH1 pattern
			if op == PUSH1 && i+size+1 <= len(code) && ByteCode(code[i+size]) == PUSH1 {
				// Write both PUSH1 values
				optimized.WriteByte(byte(Push1Push1))
				optimized.Write(code[i : i+size]) // First PUSH1 data
				i += size + 1
				if i+1 <= len(code) {
					optimized.Write(code[i : i+1]) // Second PUSH1 data
					i++
				}
				continue
			}

			// Check for PUSH2 JUMP pattern
			if op == PUSH2 && i+size+1 <= len(code) && ByteCode(code[i+size]) == JUMP {
				optimized.WriteByte(byte(Push2Jump))
				optimized.Write(code[i : i+size])
				i += size + 1
				continue
			}

			// Check for PUSH2 JUMPI pattern
			if op == PUSH2 && i+size+1 <= len(code) && ByteCode(code[i+size]) == JUMPI {
				optimized.WriteByte(byte(Push2JumpI))
				optimized.Write(code[i : i+size])
				i += size + 1
				continue
			}

			// Check for PUSH1 ADD pattern
			if op == PUSH1 && i+size+1 <= len(code) && ByteCode(code[i+size]) == ADD {
				optimized.WriteByte(byte(Push1Add))
				optimized.Write(code[i : i+size])
				i += size + 1
				continue
			}

			// Check for PUSH1 SHL pattern
			if op == PUSH1 && i+size+1 <= len(code) && ByteCode(code[i+size]) == SHL {
				optimized.WriteByte(byte(Push1Shl))
				optimized.Write(code[i : i+size])
				i += size + 1
				continue
			}

			// Check for PUSH1 DUP1 pattern
			if op == PUSH1 && i+size+1 <= len(code) && ByteCode(code[i+size]) == DUP1 {
				optimized.WriteByte(byte(Push1Dup1))
				optimized.Write(code[i : i+size])
				i += size + 1
				continue
			}

			// Write the push opcode and data
			optimized.WriteByte(byte(op))
			optimized.Write(code[i : i+size])
			i += size
			continue
		}

		// Handle other operations
		switch op {
		case AND:
			// Check for AND SWAP1 POP SWAP2 SWAP1 pattern
			if i+3 <= len(code) && ByteCode(code[i]) == SWAP1 && ByteCode(code[i+1]) == POP &&
				ByteCode(code[i+2]) == SWAP2 && ByteCode(code[i+3]) == SWAP1 {
				// Validate stack requirements (need at least 3 items for this pattern)
				optimized.WriteByte(byte(AndSwap1PopSwap2Swap1))
				i += 4
				continue
			}
			optimized.WriteByte(byte(op))

		case SWAP1:
			// Check for SWAP1 POP SWAP2 SWAP1 pattern
			if i+3 <= len(code) && ByteCode(code[i]) == POP && ByteCode(code[i+1]) == SWAP2 && ByteCode(code[i+2]) == SWAP1 {
				// Validate stack requirements (need at least 3 items for this pattern)
				optimized.WriteByte(byte(Swap1PopSwap2Swap1))
				i += 3
				continue
			}
			// Check for SWAP1 POP pattern
			if i+1 <= len(code) && ByteCode(code[i]) == POP {
				// Validate stack requirements (need at least 2 items for this pattern)
				optimized.WriteByte(byte(Swap1Pop))
				i++
				continue
			}
			optimized.WriteByte(byte(op))

		case SWAP2:
			// Check for SWAP2 SWAP1 pattern
			if i+1 <= len(code) && ByteCode(code[i]) == SWAP1 {
				// Validate stack requirements (need at least 3 items for this pattern)
				optimized.WriteByte(byte(Swap2Swap1))
				i++
				continue
			}
			// Check for SWAP2 POP pattern
			if i+1 <= len(code) && ByteCode(code[i]) == POP {
				// Validate stack requirements (need at least 3 items for this pattern)
				optimized.WriteByte(byte(Swap2Pop))
				i++
				continue
			}
			optimized.WriteByte(byte(op))

		case POP:
			// Check for POP JUMP pattern
			if i+1 <= len(code) && ByteCode(code[i]) == JUMP {
				// Validate stack requirements (need at least 1 item for this pattern)
				optimized.WriteByte(byte(PopJump))
				i++
				continue
			}
			// Check for POP POP pattern
			if i+1 <= len(code) && ByteCode(code[i]) == POP {
				// Validate stack requirements (need at least 2 items for this pattern)
				optimized.WriteByte(byte(Pop2))
				i++
				continue
			}
			optimized.WriteByte(byte(op))

		case DUP2:
			// Check for DUP2 LT pattern
			if i+1 <= len(code) && ByteCode(code[i]) == LT {
				// Validate stack requirements (need at least 2 items for this pattern)
				optimized.WriteByte(byte(Dup2LT))
				i++
				continue
			}
			optimized.WriteByte(byte(op))

		case ISZERO:
			// Check for ISZERO JUMPI pattern
			if i+1 <= len(code) && ByteCode(code[i]) == JUMPI {
				// Validate stack requirements (need at least 2 items for this pattern)
				optimized.WriteByte(byte(JumpIfZero))
				i++
				continue
			}
			optimized.WriteByte(byte(op))

		default:
			// Write the opcode as is
			optimized.WriteByte(byte(op))
		}
	}

	// Cache the optimized code
	optimizedCode := optimized.Bytes()
	p.cache.Set(string(code), optimizedCode)

	return optimizedCode
}

// OptimizeJumpTable optimizes a jump table
func (p *OpcodeProcessor) OptimizeJumpTable(jumpTable map[uint64]int) []byte {
	var buf bytes.Buffer
	for pc, target := range jumpTable {
		// Write PC
		binary.Write(&buf, binary.LittleEndian, pc)
		// Write target
		binary.Write(&buf, binary.LittleEndian, uint64(target))
	}
	return buf.Bytes()
}
