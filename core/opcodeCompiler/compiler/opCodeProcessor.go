package compiler

import (
	"errors"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
)

var (
	enabled     bool
	codeCache   *OpCodeCache
	taskChannel chan optimizeTask
)

var (
	ErrFailPreprocessing = errors.New("fail to do preprocessing")
	ErrOptimizedDisabled = errors.New("opcode optimization is disabled")
)

const taskChannelSize = 1024 * 1024

const (
	generate optimizeTaskType = 1
	flush    optimizeTaskType = 2

	minOptimizedOpcode = 0xb0
	maxOptimizedOpcode = 0xc8
)

type OpCodeProcessorConfig struct {
	DoOpcodeFusion bool
}

type optimizeTaskType byte

type CodeType uint8

type optimizeTask struct {
	taskType optimizeTaskType
	hash     common.Hash
	rawCode  []byte
}

func init() {
	taskChannel = make(chan optimizeTask, taskChannelSize)
	taskNumber := runtime.NumCPU() * 3 / 8
	if taskNumber < 1 {
		taskNumber = 1
	}
	codeCache = getOpCodeCacheInstance()

	for i := 0; i < taskNumber; i++ {
		go taskProcessor()
	}
}

func EnableOptimization() {
	if enabled {
		return
	}
	enabled = true
}

func DisableOptimization() {
	enabled = false
}

func IsEnabled() bool {
	return enabled
}

func LoadOptimizedCode(hash common.Hash) []byte {
	if !enabled {
		return nil
	}
	processedCode := codeCache.GetCachedCode(hash)
	return processedCode
}

func LoadBitvec(codeHash common.Hash) []byte {
	if !enabled {
		return nil
	}
	bitvec := codeCache.GetCachedBitvec(codeHash)
	return bitvec
}

func StoreBitvec(codeHash common.Hash, bitvec []byte) {
	if !enabled {
		return
	}
	codeCache.AddBitvecCache(codeHash, bitvec)
}

func GenOrLoadOptimizedCode(hash common.Hash, code []byte) {
	if !enabled {
		return
	}
	task := optimizeTask{generate, hash, code}
	taskChannel <- task
}

func taskProcessor() {
	for {
		task := <-taskChannel
		// Process the message here
		handleOptimizationTask(task)
	}
}

func handleOptimizationTask(task optimizeTask) {
	switch task.taskType {
	case generate:
		TryGenerateOptimizedCode(task.hash, task.rawCode)
	case flush:
		DeleteCodeCache(task.hash)
	}
}

// GenOrRewriteOptimizedCode generate the optimized code and refresh the code cache.
func GenOrRewriteOptimizedCode(hash common.Hash, code []byte) ([]byte, error) {
	if !enabled {
		return nil, ErrOptimizedDisabled
	}
	processedCode, err := processByteCodes(code)
	if err != nil {
		return nil, err
	}
	codeCache.AddCodeCache(hash, processedCode)
	return processedCode, err
}

func TryGenerateOptimizedCode(hash common.Hash, code []byte) ([]byte, error) {
	processedCode := codeCache.GetCachedCode(hash)
	var err error = nil
	if len(processedCode) == 0 {
		processedCode, err = GenOrRewriteOptimizedCode(hash, code)
	}
	return processedCode, err
}

func DeleteCodeCache(hash common.Hash) {
	if !enabled {
		return
	}
	// flush in case there are invalid cached code
	codeCache.RemoveCachedCode(hash)
}

func processByteCodes(code []byte) ([]byte, error) {
	//return doOpcodesProcess(code)
	return DoCFGBasedOpcodeFusion(code)
}

func doOpcodesProcess(code []byte) ([]byte, error) {
	code, err := doCodeFusion(code)
	if err != nil {
		return nil, ErrFailPreprocessing
	}
	return code, nil
}

// Exported version of doCodeFusion for use in benchmarks and external tests
func DoCodeFusion(code []byte) ([]byte, error) {
	// return doCodeFusion(code)
	return DoCFGBasedOpcodeFusion(code)
}

// DoCFGBasedOpcodeFusion performs opcode fusion within basic blocks, skipping blocks of type "others"
func DoCFGBasedOpcodeFusion(code []byte) ([]byte, error) {
	// Generate basic blocks
	blocks := GenerateBasicBlocks(code)
	if len(blocks) == 0 {
		return code, nil
	}

	// Create a copy of the original code (only after checking for optimized opcodes)
	fusedCode := make([]byte, len(code))
	copy(fusedCode, code)

	// Process each basic block
	for i, block := range blocks {
		// Skip blocks of type "others"
		blockType := getBlockType(block, blocks, i)
		if blockType == "others" {
			continue
		}

		// Check if the block contains optimized opcodes in the original code
		hasOptimized := false
		for pc := block.StartPC; pc < block.EndPC && pc < uint64(len(code)); {
			if code[pc] >= minOptimizedOpcode && code[pc] <= maxOptimizedOpcode {
				hasOptimized = true
				break
			}
			// Skip data bytes for PUSH instructions
			skip, steps := calculateSkipSteps(code, int(pc))
			if skip {
				pc += uint64(steps) + 1 // Add 1 for the opcode byte
			} else {
				pc++
			}
		}
		if hasOptimized {
			// If any block being processed contains optimized opcodes, return nil, ErrFailPreprocessing
			return nil, ErrFailPreprocessing
		}

		// Check if the block contains INVALID opcodes in the original code
		hasInvalid := false
		for pc := block.StartPC; pc < block.EndPC && pc < uint64(len(code)); {
			if ByteCode(code[pc]) == INVALID {
				hasInvalid = true
				break
			}
			// Skip data bytes for PUSH instructions
			skip, steps := calculateSkipSteps(code, int(pc))
			if skip {
				pc += uint64(steps) + 1 // Add 1 for the opcode byte
			} else {
				pc++
			}
		}
		if hasInvalid {
			// Skip processing this block if it contains INVALID opcodes
			continue
		}

		// Apply fusion within this block
		err := fuseBlock(fusedCode, block)
		if err != nil {
			return code, err
		}
	}

	return fusedCode, nil
}

// fuseBlock applies opcode fusion to a single basic block
func fuseBlock(code []byte, block BasicBlock) error {
	startPC := int(block.StartPC)
	endPC := int(block.EndPC)

	// Process the block's opcodes
	for i := startPC; i < endPC; {
		if i >= len(code) {
			break
		}

		// Apply fusion patterns within the block
		skipSteps := applyFusionPatterns(code, i, endPC)
		if skipSteps > 0 {
			i += skipSteps + 1 // Add 1 for the opcode byte
		} else {
			// Skip data bytes for PUSH instructions
			skip, steps := calculateSkipSteps(code, i)
			if skip {
				i += steps + 1 // Add 1 for the opcode byte
			} else {
				i++
			}
		}
	}

	return nil
}

// applyFusionPatterns applies known fusion patterns and returns the number of steps to skip
func applyFusionPatterns(code []byte, cur int, endPC int) int {
	length := len(code)

	// Pattern 1: 15-byte pattern
	if length > cur+15 && cur+15 < endPC {
		code0 := ByteCode(code[cur+0])
		code2 := ByteCode(code[cur+2])
		code3 := ByteCode(code[cur+3])
		code5 := ByteCode(code[cur+5])
		code6 := ByteCode(code[cur+6])
		code7 := ByteCode(code[cur+7])
		code12 := ByteCode(code[cur+12])
		code13 := ByteCode(code[cur+13])

		if code0 == PUSH1 && code2 == CALLDATALOAD && code3 == PUSH1 && code5 == SHR &&
			code6 == DUP1 && code7 == PUSH4 && code12 == GT && code13 == PUSH2 {
			op := Push1CalldataloadPush1ShrDup1Push4GtPush2
			code[cur] = byte(op)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			code[cur+5] = byte(Nop)
			code[cur+6] = byte(Nop)
			code[cur+7] = byte(Nop)
			code[cur+12] = byte(Nop)
			code[cur+13] = byte(Nop)
			return 15
		}
	}

	// Pattern 2: 12-byte pattern
	if length > cur+12 && cur+12 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])
		code3 := ByteCode(code[cur+3])
		code4 := ByteCode(code[cur+4])
		code5 := ByteCode(code[cur+5])
		code6 := ByteCode(code[cur+6])
		code7 := ByteCode(code[cur+7])
		code8 := ByteCode(code[cur+8])
		code9 := ByteCode(code[cur+9])
		code10 := ByteCode(code[cur+10])
		code11 := ByteCode(code[cur+11])
		code12 := ByteCode(code[cur+12])

		if code0 == SWAP1 && code1 == PUSH1 && code3 == DUP1 && code4 == NOT &&
			code5 == SWAP2 && code6 == ADD && code7 == AND && code8 == DUP2 &&
			code9 == ADD && code10 == SWAP1 && code11 == DUP2 && code12 == LT {
			op := Swap1Push1Dup1NotSwap2AddAndDup2AddSwap1Dup2LT
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+3] = byte(Nop)
			code[cur+4] = byte(Nop)
			code[cur+5] = byte(Nop)
			code[cur+6] = byte(Nop)
			code[cur+7] = byte(Nop)
			code[cur+8] = byte(Nop)
			code[cur+9] = byte(Nop)
			code[cur+10] = byte(Nop)
			code[cur+11] = byte(Nop)
			code[cur+12] = byte(Nop)
			return 12
		}
	}

	// Pattern 3: 9-byte pattern
	if length > cur+9 && cur+9 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])
		code6 := ByteCode(code[cur+6])
		code7 := ByteCode(code[cur+7])

		if code0 == DUP1 && code1 == PUSH4 && code6 == EQ && code7 == PUSH2 {
			op := Dup1Push4EqPush2
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+6] = byte(Nop)
			code[cur+7] = byte(Nop)
			return 9
		}
	}

	// Pattern 4: 7-byte pattern
	if length > cur+7 && cur+7 < endPC {
		code0 := ByteCode(code[cur+0])
		code2 := ByteCode(code[cur+2])
		code4 := ByteCode(code[cur+4])
		code6 := ByteCode(code[cur+6])
		code7 := ByteCode(code[cur+7])

		if code0 == PUSH1 && code2 == PUSH1 && code4 == PUSH1 && code6 == SHL && code7 == SUB {
			op := Push1Push1Push1SHLSub
			code[cur] = byte(op)
			code[cur+2] = byte(Nop)
			code[cur+4] = byte(Nop)
			code[cur+6] = byte(Nop)
			code[cur+7] = byte(Nop)
			return 7
		}
	}

	// Pattern 5: 5-byte pattern
	if length > cur+5 && cur+5 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])
		code2 := ByteCode(code[cur+2])
		code3 := ByteCode(code[cur+3])
		code4 := ByteCode(code[cur+4])
		code5 := ByteCode(code[cur+5])

		if code0 == AND && code1 == DUP2 && code2 == ADD && code3 == SWAP1 && code4 == DUP2 && code5 == LT {
			op := AndDup2AddSwap1Dup2LT
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			code[cur+4] = byte(Nop)
			code[cur+5] = byte(Nop)
			return 5
		}
	}

	// Pattern 6: 4-byte pattern
	if length > cur+4 && cur+4 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])
		code2 := ByteCode(code[cur+2])
		code3 := ByteCode(code[cur+3])
		code4 := ByteCode(code[cur+4])

		if code0 == AND && code1 == SWAP1 && code2 == POP && code3 == SWAP2 && code4 == SWAP1 {
			op := AndSwap1PopSwap2Swap1
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			code[cur+4] = byte(Nop)
			return 4
		}

		// Test zero and Jump. target offset at code[2-3]
		if code0 == ISZERO && code1 == PUSH2 && code4 == JUMPI {
			op := JumpIfZero
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+4] = byte(Nop)
			return 4
		}

		if code0 == DUP2 && code1 == MSTORE && code2 == PUSH1 && code4 == ADD {
			op := Dup2MStorePush1Add
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+4] = byte(Nop)
			return 4
		}
	}

	// Pattern 7: 3-byte pattern
	if length > cur+3 && cur+3 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])
		code2 := ByteCode(code[cur+2])
		code3 := ByteCode(code[cur+3])

		if code0 == SWAP2 && code1 == SWAP1 && code2 == POP && code3 == JUMP {
			op := Swap2Swap1PopJump
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			return 3
		}

		if code0 == SWAP1 && code1 == POP && code2 == SWAP2 && code3 == SWAP1 {
			op := Swap1PopSwap2Swap1
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			return 3
		}

		if code0 == POP && code1 == SWAP2 && code2 == SWAP1 && code3 == POP {
			op := PopSwap2Swap1Pop
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			code[cur+2] = byte(Nop)
			code[cur+3] = byte(Nop)
			return 3
		}

		// push and jump
		if code0 == PUSH2 && code3 == JUMP {
			op := Push2Jump
			code[cur] = byte(op)
			code[cur+3] = byte(Nop)
			return 3
		}

		if code0 == PUSH2 && code3 == JUMPI {
			op := Push2JumpI
			code[cur] = byte(op)
			code[cur+3] = byte(Nop)
			return 3
		}

		if code0 == PUSH1 && code2 == PUSH1 {
			op := Push1Push1
			code[cur] = byte(op)
			code[cur+2] = byte(Nop)
			return 3
		}

		if code0 == ISZERO && code1 == PUSH2 {
			op := IsZeroPush2
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 3
		}
	}

	// Pattern 8: 2-byte pattern
	if length > cur+2 && cur+2 < endPC {
		code0 := ByteCode(code[cur+0])
		code2 := ByteCode(code[cur+2])

		if code0 == PUSH1 {
			if code2 == ADD {
				op := Push1Add
				code[cur] = byte(op)
				code[cur+2] = byte(Nop)
				return 2
			}
			if code2 == SHL {
				op := Push1Shl
				code[cur] = byte(op)
				code[cur+2] = byte(Nop)
				return 2
			}
			if code2 == DUP1 {
				op := Push1Dup1
				code[cur] = byte(op)
				code[cur+2] = byte(Nop)
				return 2
			}
		}
	}

	// Pattern 9: 1-byte pattern
	if length > cur+1 && cur+1 < endPC {
		code0 := ByteCode(code[cur+0])
		code1 := ByteCode(code[cur+1])

		if code0 == SWAP1 && code1 == POP {
			op := Swap1Pop
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
		if code0 == POP && code1 == JUMP {
			op := PopJump
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
		if code0 == POP && code1 == POP {
			op := Pop2
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
		if code0 == SWAP2 && code1 == SWAP1 {
			op := Swap2Swap1
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
		if code0 == SWAP2 && code1 == POP {
			op := Swap2Pop
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
		if code0 == DUP2 && code1 == LT {
			op := Dup2LT
			code[cur] = byte(op)
			code[cur+1] = byte(Nop)
			return 1
		}
	}

	return 0
}

// getBlockType categorizes a basic block based on its content
func getBlockType(block BasicBlock, blocks []BasicBlock, blockIndex int) string {
	if len(block.Opcodes) == 0 {
		return "Empty"
	}

	// Check for entry basic block (first block)
	if block.StartPC == 0 {
		return "entryBB"
	}

	// Check for jump destination blocks (begin with JUMPDEST)
	if block.IsJumpDest {
		return "JumpDest"
	}

	// Check for conditional fallthrough (previous block ends with JUMPI)
	if blockIndex > 0 {
		prevBlock := blocks[blockIndex-1]
		if len(prevBlock.Opcodes) > 0 {
			lastOp := ByteCode(prevBlock.Opcodes[len(prevBlock.Opcodes)-1])
			if lastOp == JUMPI {
				return "conditional fallthrough"
			}
		}
	}

	// Default categorization
	return "others"
}

func doCodeFusion(code []byte) ([]byte, error) {
	fusedCode := make([]byte, len(code))
	length := copy(fusedCode, code)
	skipToNext := false
	for i := 0; i < length; i++ {
		cur := i
		skipToNext = false

		if fusedCode[cur] == byte(INVALID) {
			return fusedCode, nil
		}
		if fusedCode[cur] >= minOptimizedOpcode && fusedCode[cur] <= maxOptimizedOpcode {
			return code, ErrFailPreprocessing
		}

		if length > cur+15 {
			code0 := ByteCode(fusedCode[cur+0])
			code2 := ByteCode(fusedCode[cur+2])
			code3 := ByteCode(fusedCode[cur+3])
			code5 := ByteCode(fusedCode[cur+5])
			code6 := ByteCode(fusedCode[cur+6])
			code7 := ByteCode(fusedCode[cur+7])
			code12 := ByteCode(fusedCode[cur+12])
			code13 := ByteCode(fusedCode[cur+13])

			if code0 == PUSH1 && code2 == CALLDATALOAD && code3 == PUSH1 && code5 == SHR &&
				code6 == DUP1 && code7 == PUSH4 && code12 == GT && code13 == PUSH2 {
				op := Push1CalldataloadPush1ShrDup1Push4GtPush2
				fusedCode[cur] = byte(op)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				fusedCode[cur+5] = byte(Nop)
				fusedCode[cur+6] = byte(Nop)
				fusedCode[cur+7] = byte(Nop)
				fusedCode[cur+12] = byte(Nop)
				fusedCode[cur+13] = byte(Nop)
				skipToNext = true
			}

			if skipToNext {
				i += 15
				continue
			}
		}

		if length > cur+12 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])
			code3 := ByteCode(fusedCode[cur+3])
			code4 := ByteCode(fusedCode[cur+4])
			code5 := ByteCode(fusedCode[cur+5])
			code6 := ByteCode(fusedCode[cur+6])
			code7 := ByteCode(fusedCode[cur+7])
			code8 := ByteCode(fusedCode[cur+8])
			code9 := ByteCode(fusedCode[cur+9])
			code10 := ByteCode(fusedCode[cur+10])
			code11 := ByteCode(fusedCode[cur+11])
			code12 := ByteCode(fusedCode[cur+12])

			if code0 == SWAP1 && code1 == PUSH1 && code3 == DUP1 && code4 == NOT &&
				code5 == SWAP2 && code6 == ADD && code7 == AND && code8 == DUP2 &&
				code9 == ADD && code10 == SWAP1 && code11 == DUP2 && code12 == LT {
				op := Swap1Push1Dup1NotSwap2AddAndDup2AddSwap1Dup2LT
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)
				fusedCode[cur+5] = byte(Nop)
				fusedCode[cur+6] = byte(Nop)
				fusedCode[cur+7] = byte(Nop)
				fusedCode[cur+8] = byte(Nop)
				fusedCode[cur+9] = byte(Nop)
				fusedCode[cur+10] = byte(Nop)
				fusedCode[cur+11] = byte(Nop)
				fusedCode[cur+12] = byte(Nop)
				skipToNext = true
			}

			if skipToNext {
				i += 12
				continue
			}
		}

		if length > cur+9 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])
			code6 := ByteCode(fusedCode[cur+6])
			code7 := ByteCode(fusedCode[cur+7])

			if code0 == DUP1 && code1 == PUSH4 && code6 == EQ && code7 == PUSH2 {
				op := Dup1Push4EqPush2
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+6] = byte(Nop)
				fusedCode[cur+7] = byte(Nop)
				skipToNext = true
			}

			if skipToNext {
				i += 9
				continue
			}
		}

		if length > cur+7 {
			code0 := ByteCode(fusedCode[cur+0])
			code2 := ByteCode(fusedCode[cur+2])
			code4 := ByteCode(fusedCode[cur+4])
			code6 := ByteCode(fusedCode[cur+6])
			code7 := ByteCode(fusedCode[cur+7])

			if code0 == PUSH1 && code2 == PUSH1 && code4 == PUSH1 && code6 == SHL && code7 == SUB {
				op := Push1Push1Push1SHLSub
				fusedCode[cur] = byte(op)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)
				fusedCode[cur+6] = byte(Nop)
				fusedCode[cur+7] = byte(Nop)
				skipToNext = true
			}
			if skipToNext {
				i += 7
				continue
			}
		}

		if length > cur+5 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])
			code2 := ByteCode(fusedCode[cur+2])
			code3 := ByteCode(fusedCode[cur+3])
			code4 := ByteCode(fusedCode[cur+4])
			code5 := ByteCode(fusedCode[cur+5])

			if code0 == AND && code1 == DUP2 && code2 == ADD && code3 == SWAP1 && code4 == DUP2 && code5 == LT {
				op := AndDup2AddSwap1Dup2LT
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)
				fusedCode[cur+5] = byte(Nop)
				skipToNext = true
			}
			if skipToNext {
				i += 5
				continue
			}
		}

		if length > cur+4 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])
			code2 := ByteCode(fusedCode[cur+2])
			code3 := ByteCode(fusedCode[cur+3])
			code4 := ByteCode(fusedCode[cur+4])
			if code0 == AND && code1 == SWAP1 && code2 == POP && code3 == SWAP2 && code4 == SWAP1 {
				op := AndSwap1PopSwap2Swap1
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)
				skipToNext = true
			}

			// Test zero and Jump. target offset at code[2-3]
			if code0 == ISZERO && code1 == PUSH2 && code4 == JUMPI {
				op := JumpIfZero
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)

				skipToNext = true
			}

			if code0 == DUP2 && code1 == MSTORE && code2 == PUSH1 && code4 == ADD {
				op := Dup2MStorePush1Add
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+4] = byte(Nop)

				skipToNext = true
			}

			if skipToNext {
				i += 4
				continue
			}
		}

		if length > cur+3 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])
			code2 := ByteCode(fusedCode[cur+2])
			code3 := ByteCode(fusedCode[cur+3])
			if code0 == SWAP2 && code1 == SWAP1 && code2 == POP && code3 == JUMP {
				op := Swap2Swap1PopJump
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				skipToNext = true
			}

			if code0 == SWAP1 && code1 == POP && code2 == SWAP2 && code3 == SWAP1 {
				op := Swap1PopSwap2Swap1
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				skipToNext = true
			}

			if code0 == POP && code1 == SWAP2 && code2 == SWAP1 && code3 == POP {
				op := PopSwap2Swap1Pop
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				fusedCode[cur+2] = byte(Nop)
				fusedCode[cur+3] = byte(Nop)
				skipToNext = true
			}
			// push and jump
			if code0 == PUSH2 && code3 == JUMP {
				op := Push2Jump
				fusedCode[cur] = byte(op)
				fusedCode[cur+3] = byte(Nop)
				skipToNext = true
			}

			if code0 == PUSH2 && code3 == JUMPI {
				op := Push2JumpI
				fusedCode[cur] = byte(op)
				fusedCode[cur+3] = byte(Nop)
				skipToNext = true
			}

			if code0 == PUSH1 && code2 == PUSH1 {
				op := Push1Push1
				fusedCode[cur] = byte(op)
				fusedCode[cur+2] = byte(Nop)
				skipToNext = true
			}

			if code0 == ISZERO && code1 == PUSH2 {
				op := IsZeroPush2
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if skipToNext {
				i += 3
				continue
			}
		}

		if length > cur+2 {
			code0 := ByteCode(fusedCode[cur+0])
			_ = ByteCode(fusedCode[cur+1])
			code2 := ByteCode(fusedCode[cur+2])
			if code0 == PUSH1 {
				if code2 == ADD {
					op := Push1Add
					fusedCode[cur] = byte(op)
					fusedCode[cur+2] = byte(Nop)
					skipToNext = true
				}
				if code2 == SHL {
					op := Push1Shl
					fusedCode[cur] = byte(op)
					fusedCode[cur+2] = byte(Nop)
					skipToNext = true
				}

				if code2 == DUP1 {
					op := Push1Dup1
					fusedCode[cur] = byte(op)
					fusedCode[cur+2] = byte(Nop)
					skipToNext = true
				}
			}
			if skipToNext {
				i += 2
				continue
			}
		}

		if length > cur+1 {
			code0 := ByteCode(fusedCode[cur+0])
			code1 := ByteCode(fusedCode[cur+1])

			if code0 == SWAP1 && code1 == POP {
				op := Swap1Pop
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}
			if code0 == POP && code1 == JUMP {
				op := PopJump
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if code0 == POP && code1 == POP {
				op := Pop2
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if code0 == SWAP2 && code1 == SWAP1 {
				op := Swap2Swap1
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if code0 == SWAP2 && code1 == POP {
				op := Swap2Pop
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if code0 == DUP2 && code1 == LT {
				op := Dup2LT
				fusedCode[cur] = byte(op)
				fusedCode[cur+1] = byte(Nop)
				skipToNext = true
			}

			if skipToNext {
				i++
				continue
			}
		}

		skip, steps := calculateSkipSteps(fusedCode, cur)
		if skip {
			i += steps
			continue
		}
	}
	return fusedCode, nil
}

func calculateSkipSteps(code []byte, cur int) (skip bool, steps int) {
	inst := ByteCode(code[cur])
	if inst >= PUSH1 && inst <= PUSH32 {
		// skip the data.
		steps = int(inst - PUSH1 + 1)
		skip = true
		return skip, steps
	}

	switch inst {
	case Push2Jump, Push2JumpI:
		steps = 3
		skip = true
	case Push1Push1:
		steps = 3
		skip = true
	case Push1Add, Push1Shl, Push1Dup1:
		steps = 2
		skip = true
	case JumpIfZero:
		steps = 4
		skip = true
	default:
		return false, 0
	}
	return skip, steps
}

// BasicBlock represents a sequence of opcodes that can be executed linearly
// without any jumps in or out except at the beginning and end.
type BasicBlock struct {
	StartPC    uint64  // Program counter where this block starts
	EndPC      uint64  // Program counter where this block ends (exclusive)
	Opcodes    []byte  // The actual opcodes in this block
	JumpTarget *uint64 // If this block ends with a jump, the target PC
	IsJumpDest bool    // Whether this block starts with a JUMPDEST
}

// GenerateBasicBlocks takes a byte array of opcodes and returns an array of BasicBlocks.
// This function parses the opcodes to identify basic blocks - sequences of instructions
// that can be executed linearly without jumps in the middle.
func GenerateBasicBlocks(code []byte) []BasicBlock {
	if len(code) == 0 {
		return nil
	}

	var blocks []BasicBlock
	jumpDests := make(map[uint64]bool)
	var pc uint64

	// First pass: identify all JUMPDEST locations
	for pc < uint64(len(code)) {
		op := ByteCode(code[pc])
		if op == JUMPDEST {
			jumpDests[pc] = true
		}
		skip, steps := calculateSkipSteps(code, int(pc))
		if skip {
			pc += uint64(steps) + 1 // Add 1 for the opcode byte
		} else {
			pc++
		}
	}

	// Second pass: build basic blocks
	pc = 0
	var currentBlock *BasicBlock
	for pc < uint64(len(code)) {
		op := ByteCode(code[pc])

		// Start a new block if we encounter INVALID or if we're at a JUMPDEST
		if op == INVALID || jumpDests[pc] {
			if currentBlock != nil && len(currentBlock.Opcodes) > 0 {
				currentBlock.EndPC = pc
				blocks = append(blocks, *currentBlock)
			}
			currentBlock = &BasicBlock{
				StartPC:    pc,
				IsJumpDest: op == JUMPDEST, // Fix: set IsJumpDest if first opcode is JUMPDEST
			}
		} else if currentBlock == nil {
			currentBlock = &BasicBlock{
				StartPC:    pc,
				IsJumpDest: op == JUMPDEST, // Fix: set IsJumpDest if first opcode is JUMPDEST
			}
		}

		// Determine instruction length
		skip, steps := calculateSkipSteps(code, int(pc))
		instLen := uint64(1)
		if skip {
			instLen += uint64(steps)
		}
		// Check bounds before accessing
		if pc+instLen > uint64(len(code)) {
			// If we can't read the full instruction, just add what we can
			instLen = uint64(len(code)) - pc
		}
		// Add instruction bytes to block
		currentBlock.Opcodes = append(currentBlock.Opcodes, code[pc:pc+instLen]...)
		pc += instLen

		// If this is a block terminator (other than INVALID since we already handled it), end the block
		if isBlockTerminator(op) {
			currentBlock.EndPC = pc
			blocks = append(blocks, *currentBlock)
			currentBlock = nil
		}
	}
	// If there's a block in progress, add it
	if currentBlock != nil && len(currentBlock.Opcodes) > 0 {
		currentBlock.EndPC = pc
		blocks = append(blocks, *currentBlock)
	}
	return blocks
}

// isBlockTerminator checks if an opcode terminates a basic block
func isBlockTerminator(op ByteCode) bool {
	switch op {
	case STOP, RETURN, REVERT, SELFDESTRUCT:
		return true
	case JUMP, JUMPI:
		return true
	case RJUMP, RJUMPI, RJUMPV:
		return true
	case CALLF, RETF, JUMPF:
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

// CFG represents the Control Flow Graph of a contract
type CFG struct {
	Nodes  []CFGNode    // All nodes in the CFG
	Blocks []BasicBlock // The basic blocks
	Entry  int          // Index of the entry block
	Exit   int          // Index of the exit block (if any)
}

// BasicBlockOptimizations performs comprehensive basic block level optimizations
// including CFG construction and various optimization passes
func BasicBlockOptimizations(code []byte) ([]byte, error) {
	if len(code) == 0 {
		return code, nil
	}

	// Step 1: Generate basic blocks
	blocks := GenerateBasicBlocks(code)
	if len(blocks) == 0 {
		return code, nil
	}

	// Step 2: Build Control Flow Graph
	cfg, err := buildCFG(blocks, code)
	if err != nil {
		return code, err
	}

	// Step 3: Perform various optimization passes
	optimizedCode, err := performOptimizationPasses(code, blocks, cfg)
	if err != nil {
		return code, err
	}

	return optimizedCode, nil
}

// detectFunctionSelectorPattern detects if a block contains a function selector pattern
// This is common in Solidity contracts where the first 4 bytes of calldata determine the function
func detectFunctionSelectorPattern(block BasicBlock) bool {
	if len(block.Opcodes) < 4 {
		return false
	}

	// Look for the common pattern: PUSH1 0x04, CALLDATALOAD, PUSH1 0xe0, SHR
	// This extracts the function selector from calldata
	for i := 0; i <= len(block.Opcodes)-4; i++ {
		// Check for PUSH1 0x04
		if ByteCode(block.Opcodes[i]) == PUSH1 && block.Opcodes[i+1] == 0x04 {
			// Check for CALLDATALOAD
			if i+2 < len(block.Opcodes) && ByteCode(block.Opcodes[i+2]) == CALLDATALOAD {
				// Check for PUSH1 0xe0
				if i+3 < len(block.Opcodes) && ByteCode(block.Opcodes[i+3]) == PUSH1 && block.Opcodes[i+4] == 0xe0 {
					// Check for SHR
					if i+5 < len(block.Opcodes) && ByteCode(block.Opcodes[i+5]) == SHR {
						return true
					}
				}
			}
		}
	}

	return false
}

// buildCFG constructs a Control Flow Graph from basic blocks
func buildCFG(blocks []BasicBlock, code []byte) (*CFG, error) {
	if len(blocks) == 0 {
		return nil, errors.New("no basic blocks to build CFG from")
	}

	cfg := &CFG{
		Nodes:  make([]CFGNode, len(blocks)),
		Blocks: blocks,
		Entry:  0,
		Exit:   -1,
	}

	// Initialize nodes
	for i := range blocks {
		cfg.Nodes[i] = CFGNode{
			BlockIndex:     i,
			Block:          blocks[i],
			Successors:     []int{},
			Predecessors:   []int{},
			Dominators:     []int{},
			PostDominators: []int{},
		}
	}

	// Build edges between blocks
	for i, block := range blocks {
		// Find successors based on the last instruction
		successors := findBlockSuccessors(block, blocks, code)
		cfg.Nodes[i].Successors = successors

		// Update predecessors for successors
		for _, succ := range successors {
			if succ >= 0 && succ < len(cfg.Nodes) {
				cfg.Nodes[succ].Predecessors = append(cfg.Nodes[succ].Predecessors, i)
			}
		}
	}

	// Find exit blocks (blocks that end with STOP, RETURN, REVERT, etc.)
	for i, block := range blocks {
		if len(block.Opcodes) > 0 {
			lastOp := ByteCode(block.Opcodes[len(block.Opcodes)-1])
			if isExitOpcode(lastOp) {
				cfg.Exit = i
				break
			}
		}
	}

	// Compute dominators
	computeDominators(cfg)

	// Compute post-dominators
	computePostDominators(cfg)

	return cfg, nil
}

// findBlockSuccessors determines the successor blocks of a given block
func findBlockSuccessors(block BasicBlock, blocks []BasicBlock, code []byte) []int {
	var successors []int

	if len(block.Opcodes) == 0 {
		return successors
	}

	// Get the last instruction
	lastOp := ByteCode(block.Opcodes[len(block.Opcodes)-1])

	switch lastOp {
	case STOP, RETURN, REVERT, SELFDESTRUCT:
		// These are exit instructions, no successors
		return successors

	case JUMP:
		// Unconditional jump - try to find the target block
		targetPC := extractJumpTarget(block, code)
		if targetPC > 0 {
			// We found a constant target
			targetBlock := findBlockByPC(blocks, targetPC)
			if targetBlock >= 0 {
				successors = append(successors, targetBlock)
			}
		} else {
			// Dynamic jump - we can't determine the target statically
			// Conservatively add all JUMPDEST blocks as potential targets
			for i, b := range blocks {
				if b.IsJumpDest {
					successors = append(successors, i)
				}
			}
		}

	case JUMPI:
		// Conditional jump - has two successors: fallthrough and jump target
		// Fallthrough (next block)
		nextBlock := findNextBlock(blocks, block.EndPC)
		if nextBlock >= 0 {
			successors = append(successors, nextBlock)
		}

		// Jump target
		targetPC := extractJumpTarget(block, code)
		if targetPC > 0 {
			// We found a constant target
			targetBlock := findBlockByPC(blocks, targetPC)
			if targetBlock >= 0 {
				successors = append(successors, targetBlock)
			}
		} else {
			// Dynamic jump - we can't determine the target statically
			// Conservatively add all JUMPDEST blocks as potential targets
			for i, b := range blocks {
				if b.IsJumpDest {
					successors = append(successors, i)
				}
			}
		}

	default:
		// Fallthrough to next block
		nextBlock := findNextBlock(blocks, block.EndPC)
		if nextBlock >= 0 {
			successors = append(successors, nextBlock)
		}
	}

	return successors
}

// extractJumpTarget extracts the jump target from a jump instruction
// Note: This is a simplified approach that only handles constant jump targets
// For dynamic jumps, we need more sophisticated analysis
func extractJumpTarget(block BasicBlock, code []byte) uint64 {
	if len(block.Opcodes) < 3 {
		return 0
	}

	// Look for PUSH2 followed by JUMP/JUMPI pattern (constant targets only)
	for i := 0; i < len(block.Opcodes)-3; i++ {
		if ByteCode(block.Opcodes[i]) == PUSH2 {
			// Check if the next instruction is JUMP or JUMPI
			if i+3 < len(block.Opcodes) {
				nextOp := ByteCode(block.Opcodes[i+3])
				if nextOp == JUMP || nextOp == JUMPI {
					// Extract the 2-byte target
					target := uint64(block.Opcodes[i+1])<<8 | uint64(block.Opcodes[i+2])
					return target
				}
			}
		}
	}

	// Also check for PUSH1 followed by JUMP/JUMPI (1-byte targets)
	for i := 0; i < len(block.Opcodes)-2; i++ {
		if ByteCode(block.Opcodes[i]) == PUSH1 {
			// Check if the next instruction is JUMP or JUMPI
			if i+2 < len(block.Opcodes) {
				nextOp := ByteCode(block.Opcodes[i+2])
				if nextOp == JUMP || nextOp == JUMPI {
					// Extract the 1-byte target
					target := uint64(block.Opcodes[i+1])
					return target
				}
			}
		}
	}

	return 0
}

// findBlockByPC finds the block that contains the given PC
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

// isExitOpcode checks if an opcode is an exit instruction
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
	if len(cfg.Nodes) == 0 {
		return
	}

	// Initialize dominators as sets
	for i := range cfg.Nodes {
		cfg.Nodes[i].Dominators = []int{}
	}

	// Entry node dominates itself
	cfg.Nodes[cfg.Entry].Dominators = append(cfg.Nodes[cfg.Entry].Dominators, cfg.Entry)

	// Iterative algorithm to compute dominators
	changed := true
	iterations := 0
	maxIterations := len(cfg.Nodes) * 2 // Prevent infinite loops

	for changed && iterations < maxIterations {
		changed = false
		iterations++

		for i := range cfg.Nodes {
			if i == cfg.Entry {
				continue
			}

			// Find intersection of dominators of all predecessors
			var newDominators []int

			for _, pred := range cfg.Nodes[i].Predecessors {
				if len(cfg.Nodes[pred].Dominators) > 0 {
					if len(newDominators) == 0 {
						newDominators = append(newDominators, cfg.Nodes[pred].Dominators...)
					} else {
						newDominators = intersect(newDominators, cfg.Nodes[pred].Dominators)
					}
				}
			}

			// Add self to dominators
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
	if len(cfg.Nodes) == 0 || cfg.Exit == -1 {
		return
	}

	// Initialize post-dominators as sets
	for i := range cfg.Nodes {
		cfg.Nodes[i].PostDominators = []int{}
	}

	// Exit node post-dominates itself
	cfg.Nodes[cfg.Exit].PostDominators = append(cfg.Nodes[cfg.Exit].PostDominators, cfg.Exit)

	// Iterative algorithm to compute post-dominators
	changed := true
	iterations := 0
	maxIterations := len(cfg.Nodes) * 2 // Prevent infinite loops

	for changed && iterations < maxIterations {
		changed = false
		iterations++

		for i := range cfg.Nodes {
			if i == cfg.Exit {
				continue
			}

			// Find intersection of post-dominators of all successors
			var newPostDominators []int
			for _, succ := range cfg.Nodes[i].Successors {
				if len(cfg.Nodes[succ].PostDominators) > 0 {
					if len(newPostDominators) == 0 {
						newPostDominators = append(newPostDominators, cfg.Nodes[succ].PostDominators...)
					} else {
						newPostDominators = intersect(newPostDominators, cfg.Nodes[succ].PostDominators)
					}
				}
			}

			// Add self to post-dominators
			newPostDominators = append(newPostDominators, i)

			// Check if post-dominators changed
			if !equalSlices(cfg.Nodes[i].PostDominators, newPostDominators) {
				cfg.Nodes[i].PostDominators = newPostDominators
				changed = true
			}
		}
	}
}

// intersect returns the intersection of two slices
func intersect(a, b []int) []int {
	// Create a map for faster lookup
	bMap := make(map[int]bool)
	for _, val := range b {
		bMap[val] = true
	}

	var result []int
	for _, val := range a {
		if bMap[val] {
			result = append(result, val)
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

// performOptimizationPasses applies various optimization passes to the code
func performOptimizationPasses(code []byte, blocks []BasicBlock, cfg *CFG) ([]byte, error) {
	optimizedCode := make([]byte, len(code))
	copy(optimizedCode, code)

	// Pass 1: Unreachable Block Elimination
	optimizedCode = eliminateUnreachableBlocks(optimizedCode, blocks, cfg)

	// Pass 2: Constant Folding
	optimizedCode = foldConstants(optimizedCode, blocks)

	// Pass 3: Peephole Optimizations
	optimizedCode = applyPeepholeOptimizations(optimizedCode, blocks)

	// Pass 4: Opcode Fusion (existing logic)
	fusedCode, err := applyOpcodeFusion(optimizedCode, blocks)
	if err != nil {
		// If opcode fusion fails, continue with the original code
		// This is safe because opcode fusion is an optimization, not a requirement
	} else {
		optimizedCode = fusedCode
	}

	// Pass 5: Jump Optimization
	optimizedCode = optimizeJumps(optimizedCode, blocks, cfg)

	// Pass 6: Stack Optimization
	optimizedCode = optimizeStack(optimizedCode, blocks)

	return optimizedCode, nil
}

// applyPeepholeOptimizations applies various peephole optimizations
func applyPeepholeOptimizations(code []byte, blocks []BasicBlock) []byte {
	optimizedCode := make([]byte, len(code))
	copy(optimizedCode, code)

	// Process each block for peephole optimizations
	for _, block := range blocks {
		optimizedCode = applyPeepholeOptimizationsInBlock(optimizedCode, block)
	}

	return optimizedCode
}

// applyPeepholeOptimizationsInBlock applies peephole optimizations within a single block
func applyPeepholeOptimizationsInBlock(code []byte, block BasicBlock) []byte {
	startPC := int(block.StartPC)
	endPC := int(block.EndPC)

	// Look for peephole optimization patterns
	for i := startPC; i < endPC-1; i++ {
		if i >= len(code) {
			break
		}

		// Pattern 1: Arithmetic optimizations
		optimizedCode := applyArithmeticOptimizations(code, i, endPC)
		if optimizedCode != nil {
			code = optimizedCode
			continue
		}

		// Pattern 2: Comparison optimizations
		optimizedCode = applyComparisonOptimizations(code, i, endPC)
		if optimizedCode != nil {
			code = optimizedCode
			continue
		}

		// Pattern 3: Stack operation optimizations
		optimizedCode = applyStackOptimizations(code, i, endPC)
		if optimizedCode != nil {
			code = optimizedCode
			continue
		}

		// Pattern 4: Memory/Storage optimizations
		optimizedCode = applyMemoryOptimizations(code, i, endPC)
		if optimizedCode != nil {
			code = optimizedCode
			continue
		}

		// Pattern 5: Logical operation optimizations
		optimizedCode = applyLogicalOptimizations(code, i, endPC)
		if optimizedCode != nil {
			code = optimizedCode
			continue
		}
	}

	return code
}

// applyArithmeticOptimizations applies arithmetic peephole optimizations
func applyArithmeticOptimizations(code []byte, i int, endPC int) []byte {
	// Pattern 1: PUSH1 0 ADD -> NOP (add zero)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == ADD {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 2: PUSH1 0 MUL -> PUSH1 0 (multiply by zero)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == MUL {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 3: PUSH1 1 MUL -> NOP (multiply by one)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 1 && ByteCode(code[i+2]) == MUL {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 4: PUSH1 0 SUB -> NOP (subtract zero)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == SUB {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 5: PUSH1 1 DIV -> NOP (divide by one)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 1 && ByteCode(code[i+2]) == DIV {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 6: PUSH1 0 EXP -> PUSH1 1 (zero to any power is one)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == EXP {
			code[i] = byte(PUSH1)
			code[i+1] = 1
			code[i+2] = byte(Nop)
			return code
		}
	}

	return nil
}

// applyComparisonOptimizations applies comparison peephole optimizations
func applyComparisonOptimizations(code []byte, i int, endPC int) []byte {
	// Pattern 1: PUSH1 0 EQ -> ISZERO
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == EQ {
			code[i] = byte(ISZERO)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 2: PUSH1 0 GT -> PUSH1 0 (always false)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == GT {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 3: PUSH1 0 LT -> PUSH1 0 (always false)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == LT {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 4: PUSH1 0 SGT -> PUSH1 0 (always false)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == SGT {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 5: PUSH1 0 SLT -> PUSH1 0 (always false)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == SLT {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	return nil
}

// applyStackOptimizations applies stack operation peephole optimizations
func applyStackOptimizations(code []byte, i int, endPC int) []byte {
	// Pattern 1: DUP1 DUP1 -> DUP1 DUP2
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == DUP1 && ByteCode(code[i+1]) == DUP1 {
			code[i+1] = byte(DUP2)
			return code
		}
	}

	// Pattern 2: SWAP1 SWAP1 -> NOP (swap twice is no-op)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == SWAP1 && ByteCode(code[i+1]) == SWAP1 {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			return code
		}
	}

	// Pattern 3: DUP1 SWAP1 -> SWAP1 DUP2
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == DUP1 && ByteCode(code[i+1]) == SWAP1 {
			code[i] = byte(SWAP1)
			code[i+1] = byte(DUP2)
			return code
		}
	}

	// Pattern 4: POP POP -> POP2 (if available)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == POP && ByteCode(code[i+1]) == POP {
			code[i] = byte(Pop2)
			code[i+1] = byte(Nop)
			return code
		}
	}

	// Pattern 5: DUP1 POP -> NOP (duplicate then pop is no-op)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == DUP1 && ByteCode(code[i+1]) == POP {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			return code
		}
	}

	// Pattern 6: SWAP1 POP -> POP (swap then pop is just pop)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == SWAP1 && ByteCode(code[i+1]) == POP {
			code[i] = byte(POP)
			code[i+1] = byte(Nop)
			return code
		}
	}

	return nil
}

// applyMemoryOptimizations applies memory and storage peephole optimizations
func applyMemoryOptimizations(code []byte, i int, endPC int) []byte {
	// Pattern 1: PUSH1 0 MSTORE -> MSTORE8 (if value is small)
	if i+3 < endPC && i+3 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == MSTORE {
			// Check if the next instruction is a small value
			if i+4 < len(code) && ByteCode(code[i+4]) == PUSH1 {
				value := code[i+5]
				if value <= 255 {
					code[i+2] = byte(MSTORE8)
				}
			}
			return code
		}
	}

	// Pattern 2: PUSH1 0 SLOAD -> PUSH1 0 (load zero slot)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == SLOAD {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 3: PUSH1 0 SSTORE -> NOP (store to zero slot, but keep for side effects)
	// Note: We don't optimize this as SSTORE has side effects

	return nil
}

// applyLogicalOptimizations applies logical operation peephole optimizations
func applyLogicalOptimizations(code []byte, i int, endPC int) []byte {
	// Pattern 1: PUSH1 0 AND -> PUSH1 0 (AND with zero is zero)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == AND {
			code[i] = byte(PUSH1)
			code[i+1] = 0
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 2: PUSH1 0 OR -> NOP (OR with zero is no-op)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == OR {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 3: PUSH1 0 XOR -> NOP (XOR with zero is no-op)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == XOR {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 4: PUSH1 0xFF AND -> NOP (AND with 0xFF is no-op for single byte)
	if i+2 < endPC && i+2 < len(code) {
		if ByteCode(code[i]) == PUSH1 && code[i+1] == 0xFF && ByteCode(code[i+2]) == AND {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			code[i+2] = byte(Nop)
			return code
		}
	}

	// Pattern 5: NOT NOT -> NOP (double negation)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == NOT && ByteCode(code[i+1]) == NOT {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			return code
		}
	}

	// Pattern 6: ISZERO ISZERO -> NOP (double iszero)
	if i+1 < endPC && i+1 < len(code) {
		if ByteCode(code[i]) == ISZERO && ByteCode(code[i+1]) == ISZERO {
			code[i] = byte(Nop)
			code[i+1] = byte(Nop)
			return code
		}
	}

	return nil
}

// eliminateUnreachableBlocks removes unreachable basic blocks using CFG-based reachability analysis
// This is different from traditional "dead code elimination" because basic blocks by definition
// don't contain dead code - they end at terminators. This function removes entire blocks
// that cannot be reached from the entry point.
func eliminateUnreachableBlocks(code []byte, blocks []BasicBlock, cfg *CFG) []byte {
	if len(blocks) == 0 {
		return code
	}

	// Mark all reachable blocks starting from entry
	reachable := make(map[int]bool)
	markReachable(cfg.Entry, cfg, reachable)

	// Create new code with only reachable blocks
	var newCode []byte
	lastEndPC := uint64(0)

	for i, block := range blocks {
		if reachable[i] {
			// Add any gap between blocks
			if block.StartPC > lastEndPC {
				// Fill gap with NOPs or keep original bytes
				gapSize := block.StartPC - lastEndPC
				for j := uint64(0); j < gapSize; j++ {
					newCode = append(newCode, byte(Nop))
				}
			}

			// Add the reachable block
			newCode = append(newCode, block.Opcodes...)
			lastEndPC = block.EndPC
		}
	}

	// If no reachable blocks, return original code
	if len(newCode) == 0 {
		return code
	}

	return newCode
}

// markReachable recursively marks all reachable blocks
func markReachable(blockIndex int, cfg *CFG, reachable map[int]bool) {
	if reachable[blockIndex] {
		return
	}
	reachable[blockIndex] = true

	// Mark all successors as reachable
	for _, succ := range cfg.Nodes[blockIndex].Successors {
		if succ >= 0 && succ < len(cfg.Nodes) {
			markReachable(succ, cfg, reachable)
		}
	}
}

// foldConstants performs constant folding optimization
func foldConstants(code []byte, blocks []BasicBlock) []byte {
	// Create a copy of the code
	optimizedCode := make([]byte, len(code))
	copy(optimizedCode, code)

	// Process each block for constant folding
	for _, block := range blocks {
		optimizedCode = foldConstantsInBlock(optimizedCode, block)
	}

	return optimizedCode
}

// foldConstantsInBlock performs constant folding within a single block
func foldConstantsInBlock(code []byte, block BasicBlock) []byte {
	startPC := int(block.StartPC)
	endPC := int(block.EndPC)

	// Simple constant folding patterns
	for i := startPC; i < endPC-2; i++ {
		if i >= len(code) {
			break
		}

		// Pattern 1: PUSH1 x PUSH1 y ADD -> PUSH1 (x+y)
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == PUSH1 && ByteCode(code[i+2]) == PUSH1 && ByteCode(code[i+4]) == ADD {
				val1 := uint64(code[i+1])
				val2 := uint64(code[i+2+1])
				result := val1 + val2
				if result <= 255 {
					// Replace with single PUSH1
					code[i] = byte(PUSH1)
					code[i+1] = byte(result)
					// NOP out the rest
					code[i+2] = byte(Nop)
					code[i+3] = byte(Nop)
					code[i+4] = byte(Nop)
				}
			}
		}

		// Pattern 2: PUSH1 x PUSH1 y SUB -> PUSH1 (x-y) if x >= y
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == PUSH1 && ByteCode(code[i+2]) == PUSH1 && ByteCode(code[i+4]) == SUB {
				val1 := uint64(code[i+1])
				val2 := uint64(code[i+2+1])
				if val1 >= val2 {
					result := val1 - val2
					// Replace with single PUSH1
					code[i] = byte(PUSH1)
					code[i+1] = byte(result)
					// NOP out the rest
					code[i+2] = byte(Nop)
					code[i+3] = byte(Nop)
					code[i+4] = byte(Nop)
				}
			}
		}

		// Pattern 3: PUSH1 0 ISZERO -> PUSH1 1
		if i+2 < endPC && i+2 < len(code) {
			if ByteCode(code[i]) == PUSH1 && code[i+1] == 0 && ByteCode(code[i+2]) == ISZERO {
				code[i] = byte(PUSH1)
				code[i+1] = 1
				code[i+2] = byte(Nop)
			}
		}

		// Pattern 4: PUSH1 x PUSH1 0 ADD -> PUSH1 x
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == PUSH1 && ByteCode(code[i+2]) == PUSH1 && code[i+2+1] == 0 && ByteCode(code[i+4]) == ADD {
				// Keep the first PUSH1, NOP out the rest
				code[i+2] = byte(Nop)
				code[i+3] = byte(Nop)
				code[i+4] = byte(Nop)
			}
		}

		// Pattern 5: PUSH1 x PUSH1 0 MUL -> PUSH1 0
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == PUSH1 && ByteCode(code[i+2]) == PUSH1 && code[i+2+1] == 0 && ByteCode(code[i+4]) == MUL {
				code[i] = byte(PUSH1)
				code[i+1] = 0
				code[i+2] = byte(Nop)
				code[i+3] = byte(Nop)
				code[i+4] = byte(Nop)
			}
		}
	}

	return code
}

// applyOpcodeFusion applies the existing opcode fusion logic
func applyOpcodeFusion(code []byte, blocks []BasicBlock) ([]byte, error) {
	// Use the existing CFG-based fusion logic
	return DoCFGBasedOpcodeFusion(code)
}

// optimizeJumps optimizes jump instructions
func optimizeJumps(code []byte, blocks []BasicBlock, cfg *CFG) []byte {
	optimizedCode := make([]byte, len(code))
	copy(optimizedCode, code)

	// Process each block for jump optimizations
	for _, block := range blocks {
		optimizedCode = optimizeJumpsInBlock(optimizedCode, block, blocks)
	}

	return optimizedCode
}

// optimizeJumpsInBlock performs jump optimizations within a single block
func optimizeJumpsInBlock(code []byte, block BasicBlock, blocks []BasicBlock) []byte {
	startPC := int(block.StartPC)
	endPC := int(block.EndPC)

	// Look for jump optimization patterns
	for i := startPC; i < endPC-2; i++ {
		if i >= len(code) {
			break
		}

		// Pattern 1: Remove unnecessary jumps (jump to next instruction)
		if i+3 < endPC && i+3 < len(code) {
			if ByteCode(code[i]) == PUSH2 && ByteCode(code[i+3]) == JUMP {
				target := uint64(code[i+1])<<8 | uint64(code[i+2])
				if target == uint64(i+4) { // Jump to next instruction
					// Replace with NOPs
					code[i] = byte(Nop)
					code[i+1] = byte(Nop)
					code[i+2] = byte(Nop)
					code[i+3] = byte(Nop)
				}
			}
		}

		// Pattern 2: Optimize conditional jumps with constant conditions
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == PUSH1 && ByteCode(code[i+2]) == PUSH2 && ByteCode(code[i+5]) == JUMPI {
				condition := code[i+1]
				if condition == 0 { // Always false condition
					// Remove the conditional jump entirely
					code[i] = byte(Nop)
					code[i+1] = byte(Nop)
					code[i+2] = byte(Nop)
					code[i+3] = byte(Nop)
					code[i+4] = byte(Nop)
					code[i+5] = byte(Nop)
				} else if condition == 1 { // Always true condition
					// Convert to unconditional jump
					target := uint64(code[i+3])<<8 | uint64(code[i+4])
					code[i] = byte(PUSH2)
					code[i+1] = byte(target >> 8)
					code[i+2] = byte(target & 0xFF)
					code[i+3] = byte(JUMP)
					code[i+4] = byte(Nop)
					code[i+5] = byte(Nop)
				}
			}
		}

		// Pattern 3: Optimize ISZERO + JUMPI patterns
		if i+4 < endPC && i+4 < len(code) {
			if ByteCode(code[i]) == ISZERO && ByteCode(code[i+1]) == PUSH2 && ByteCode(code[i+4]) == JUMPI {
				// This is already optimized by the existing fusion patterns
				// Just ensure it's properly handled
			}
		}
	}

	return code
}

// optimizeStack optimizes stack operations
func optimizeStack(code []byte, blocks []BasicBlock) []byte {
	optimizedCode := make([]byte, len(code))
	copy(optimizedCode, code)

	// Process each block for stack optimizations
	for _, block := range blocks {
		optimizedCode = optimizeStackInBlock(optimizedCode, block)
	}

	return optimizedCode
}

// optimizeStackInBlock performs stack optimizations within a single block
func optimizeStackInBlock(code []byte, block BasicBlock) []byte {
	startPC := int(block.StartPC)
	endPC := int(block.EndPC)

	// Look for stack optimization patterns
	for i := startPC; i < endPC-1; i++ {
		if i >= len(code) {
			break
		}

		// Pattern 1: Remove unnecessary DUP operations
		if i+2 < endPC && i+2 < len(code) {
			if ByteCode(code[i]) == DUP1 && ByteCode(code[i+1]) == POP {
				// DUP1 followed by POP is a no-op
				code[i] = byte(Nop)
				code[i+1] = byte(Nop)
			}
		}

		// Pattern 2: Optimize SWAP sequences
		if i+3 < endPC && i+3 < len(code) {
			if ByteCode(code[i]) == SWAP1 && ByteCode(code[i+1]) == SWAP1 {
				// SWAP1 SWAP1 is a no-op
				code[i] = byte(Nop)
				code[i+1] = byte(Nop)
			}
		}

		// Pattern 3: Remove dead code after STOP/RETURN/REVERT
		if i < endPC && i < len(code) {
			op := ByteCode(code[i])
			if op == STOP || op == RETURN || op == REVERT {
				// NOP out any remaining instructions in this block
				for j := i + 1; j < endPC && j < len(code); j++ {
					code[j] = byte(Nop)
				}
				break
			}
		}
	}

	return code
}
