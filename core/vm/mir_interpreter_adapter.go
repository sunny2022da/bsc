package vm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/tracing"
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func shouldTraceBlock966Tx0(evm *EVM, contract *Contract) bool {
	if os.Getenv("MIR_TRACE_BLOCK966") != "1" {
		return false
	}
	if evm == nil || evm.Context.BlockNumber == nil {
		return false
	}
	if evm.Context.BlockNumber.Uint64() != 966 {
		return false
	}
	// tx0 sender / callee
	if evm.TxContext.Origin != common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540") {
		return false
	}
	// Ensure it's tx index 0 when available.
	if idxDB, ok := evm.StateDB.(interface{ TxIndex() int }); ok {
		if idxDB.TxIndex() != 0 {
			return false
		}
	}
	return true
}

// mirGasProbe is an optional test hook to observe MIR gas after each instruction
var mirGasProbe func(pc uint64, op byte, gasLeft uint64)

// mirGasPreProbe is an optional test hook to observe MIR gas before charging an instruction.
// This is especially useful when the instruction OOGs during gas charging and we never reach
// the "after" probe.
var mirGasPreProbe func(pc uint64, op byte, gasLeft uint64, isBlockEntry bool)

// mirGasTimingHook, when set (testing only), receives time spent inside the
// adapter's pre-op hook (i.e., gas accounting for the originating EVM opcode).
var mirGasTimingHook func(pc uint64, op byte, dur time.Duration)

// mirBlockEntryCountsProbe, when set (testing only), receives the opcode counts used for
// block-entry charging, keyed by originating EVM opcode byte.
var mirBlockEntryCountsProbe func(firstPC uint, counts map[byte]uint32)

// mirGasChargeProbe, when set (testing only), receives how much gas MIR charged for a pre-op step.
// Note: block-entry charging for elided opcodes is not attributed to their original op here; it is
// applied during the block-entry step for the first MIR instruction of the block.
var mirGasChargeProbe func(pc uint64, op byte, charged uint64, isBlockEntry bool)

// SetMIRGasTimingHook installs a callback to observe MIR gas calculation time per-op (testing only).
func SetMIRGasTimingHook(cb func(pc uint64, op byte, dur time.Duration)) { mirGasTimingHook = cb }

// SetMIRGasProbe installs a callback to observe MIR gas after each instruction (testing only)
func SetMIRGasProbe(cb func(pc uint64, op byte, gasLeft uint64)) {
	mirGasProbe = cb
}

// SetMIRGasPreProbe installs a callback to observe MIR gas before each instruction is charged (testing only).
func SetMIRGasPreProbe(cb func(pc uint64, op byte, gasLeft uint64, isBlockEntry bool)) {
	mirGasPreProbe = cb
}

// SetMIRBlockEntryCountsProbe installs a callback to observe opcode counts charged at block entry (testing only).
func SetMIRBlockEntryCountsProbe(cb func(firstPC uint, counts map[byte]uint32)) {
	mirBlockEntryCountsProbe = cb
}

// SetMIRGasChargeProbe installs a callback to observe MIR's gas deduction per pre-op step (testing only).
func SetMIRGasChargeProbe(cb func(pc uint64, op byte, charged uint64, isBlockEntry bool)) {
	mirGasChargeProbe = cb
}

// MIRInterpreterAdapter adapts MIRInterpreter to work with EVM's interpreter interface
type MIRInterpreterAdapter struct {
	evm             *EVM
	mirInterpreter  *compiler.MIRInterpreter
	currentSelf     common.Address
	currentContract *Contract
	table           *JumpTable
	memShadow       *Memory
	// Warm caches to avoid repeated EIP-2929 checks within a single Run
	warmAccounts map[[20]byte]struct{}
	// storageCache caches SLOAD values within a single Run (key is 32-byte slot)
	storageCache map[[32]byte][32]byte
	// Track block entry gas charges per block (for GAS opcode to add back)
	blockEntryGasCharges map[*compiler.MIRBasicBlock]uint64
	// Current block being executed (for GAS opcode to know which block entry charges to add back)
	currentBlock *compiler.MIRBasicBlock
	// Track whether the last executed opcode was a control transfer (JUMP/JUMPI)
	lastWasJump bool
	// Dedup JUMPDEST charge at first instruction of landing block
	lastJdPC           uint32
	lastJdBlockFirstPC uint32
	// Debug: last observed EVM pc/op/gas before MIR pre-op hook (to pinpoint OOG)
	lastTracePC      uint64
	lastTraceOp      byte
	lastTraceGasLeft uint64
	lastTraceAddr    common.Address
}

// countOpcodesInBlock counts opcodes belonging to the given MIR basic block by scanning the
// underlying bytecode from block.FirstPC until just before the earliest child block start
// (or until a terminator is encountered).
//
// This avoids both:
// - overcharging by scanning past the block into the next block, and
// - undercharging when block.LastPC is earlier than the last EVM opcode in the block.
func countOpcodesInBlock(code []byte, block *compiler.MIRBasicBlock) map[byte]uint32 {
	counts := make(map[byte]uint32)
	if block == nil || code == nil {
		return counts
	}
	firstPC := block.FirstPC()
	if firstPC >= uint(len(code)) {
		return counts
	}
	// Determine an exclusive stop point from successor PCs.
	//
	// We want the earliest *forward* successor PC (i.e. > firstPC). This captures:
	// - normal fallthrough blocks (single successor at next PC),
	// - JUMPI blocks where the fallthrough successor is the smaller forward PC,
	// while ignoring back-edges (loops) whose successor PC is < firstPC.
	stopBefore := uint(len(code)) // exclusive
	if ch := block.Children(); len(ch) > 0 {
		for _, c := range ch {
			if c == nil {
				continue
			}
			cp := c.FirstPC()
			if cp > firstPC && cp < stopBefore {
				stopBefore = cp
			}
		}
	}

	pc := firstPC
	for pc < uint(len(code)) {
		// Stop at child boundary (exclusive).
		if pc == stopBefore && pc > firstPC {
			break
		}
		op := OpCode(code[pc])
		// If we hit a JUMPDEST after the first instruction, it's the next block's entry.
		if op == JUMPDEST && pc > firstPC {
			break
		}
		counts[byte(op)]++

		// Compute next PC (skipping PUSH data).
		nextPC := pc + 1
		if op >= PUSH1 && op <= PUSH32 {
			nextPC = pc + 1 + uint(op-PUSH1+1)
		}
		// If the child boundary lands inside PUSH data, shift it forward to the next instruction boundary.
		if stopBefore > pc && stopBefore < nextPC {
			stopBefore = nextPC
		}

		// Terminators end the basic block (include them, then stop).
		if op == STOP || op == RETURN || op == REVERT || op == SELFDESTRUCT || op == JUMP || op == JUMPI {
			break
		}
		pc = nextPC
	}
	return counts
}

// NewMIRInterpreterAdapter creates a new MIR interpreter adapter for EVM
func NewMIRInterpreterAdapter(evm *EVM) *MIRInterpreterAdapter {
	// Create adapter early so closures can reference cached fields
	adapter := &MIRInterpreterAdapter{evm: evm}

	// Create MIR execution environment from EVM context
	var chainID uint64
	if evm.ChainConfig() != nil && evm.ChainConfig().ChainID != nil {
		chainID = evm.ChainConfig().ChainID.Uint64()
	}
	var blockNumber uint64
	if evm.Context.BlockNumber != nil {
		blockNumber = evm.Context.BlockNumber.Uint64()
	}

	env := &compiler.MIRExecutionEnv{
		Memory:      make([]byte, 0, 1024),
		Storage:     make(map[[32]byte][32]byte),
		BlockNumber: blockNumber,
		Timestamp:   evm.Context.Time,
		ChainID:     chainID,
		GasPrice:    0, // Will be set from transaction context
		BaseFee:     0, // Will be set from block context
		SelfBalance: 0, // Will be set from contract context
	}

	// Set values from contexts if available
	if evm.Context.BaseFee != nil {
		env.BaseFee = evm.Context.BaseFee.Uint64()
	}

	// Install runtime linkage hooks once; they read dynamic data from env/evm
	env.SLoadFunc = func(key [32]byte) [32]byte {
		// Use cached currentSelf to avoid per-access address conversions
		val := evm.StateDB.GetState(adapter.currentSelf, common.BytesToHash(key[:]))
		var out [32]byte
		copy(out[:], val[:])
		return out
	}
	env.SStoreFunc = func(key [32]byte, value [32]byte) {
		// PERFORMANCE: Only evaluate expensive Hex() and fmt.Sprintf when debug logging is enabled
		if compiler.DebugLogsEnabled {
			compiler.MirDebugInfo("SStoreFunc", "addr", adapter.currentSelf.Hex(), "key", fmt.Sprintf("%x", key[:8]), "value", fmt.Sprintf("%x", value[:8]))
		}
		evm.StateDB.SetState(adapter.currentSelf, common.BytesToHash(key[:]), common.BytesToHash(value[:]))
	}
	env.TLoadFunc = func(key [32]byte) [32]byte {
		// Transient storage (EIP-1153)
		return evm.StateDB.GetTransientState(adapter.currentSelf, common.BytesToHash(key[:]))
	}
	env.TStoreFunc = func(key [32]byte, value [32]byte) {
		// Transient storage (EIP-1153)
		evm.StateDB.SetTransientState(adapter.currentSelf, common.BytesToHash(key[:]), common.BytesToHash(value[:]))
	}
	env.GetBalanceFunc = func(addr20 [20]byte) *uint256.Int {
		addr := common.BytesToAddress(addr20[:])
		b := evm.StateDB.GetBalance(addr)
		if b == nil {
			return uint256.NewInt(0)
		}
		return new(uint256.Int).Set(b)
	}

	adapter.mirInterpreter = compiler.NewMIRInterpreter(env)
	// Install pre-op hook once; it will read the current contract from adapter.currentContract
	adapter.mirInterpreter.SetBeforeOpHook(func(ctx *compiler.MIRPreOpContext) error {
		contract := adapter.currentContract
		if ctx == nil || ctx.M == nil || contract == nil {
			return nil
		}
		var timingStart time.Time
		if mirGasTimingHook != nil {
			timingStart = time.Now()
		}
		// The following body mirrors the per-run innerHook logic
		evmOp := OpCode(ctx.EvmOp)
		// Call EVM tracer for all MIR instructions that correspond to EVM opcodes (not PHI, not NOP)
		if adapter.evm != nil && adapter.evm.Config.Tracer != nil && adapter.evm.Config.Tracer.OnOpcode != nil {
			// Only trace actual EVM opcodes, not internal MIR operations like PHI
			if ctx.M.Op() != compiler.MirPHI && ctx.M.Op() != compiler.MirNOP {
				scope := &ScopeContext{Memory: adapter.memShadow, Stack: nil, Contract: contract}
				adapter.evm.Config.Tracer.OnOpcode(uint64(ctx.M.EvmPC()), byte(evmOp), contract.Gas, 0, scope, nil, adapter.evm.depth, nil)
			}
		}
		// IMPORTANT:
		// Gas accounting must happen exactly once. The per-run hook installed in Run()
		// already performs:
		// - block-entry constant gas charging
		// - per-op dynamic gas charging (including LOG1 at block 966 tx0)
		//
		// This "global" hook is therefore disabled for gas charging by default, and only
		// used for tracing/timing. Double-charging dynamic gas here caused block 966 tx0
		// to OOG at LOG1 (pc=5304).
		if os.Getenv("MIR_LEGACY_PREOP_GAS") != "1" {
			if mirGasTimingHook != nil {
				mirGasTimingHook(uint64(ctx.M.EvmPC()), ctx.EvmOp, time.Since(timingStart))
			}
			return nil
		}
		// Block entry gas charging is handled by the per-run innerHook (installed in Run method)
		// This hook only handles tracing and dynamic gas
		// Constant gas is charged at block entry, so we don't charge it per instruction
		// Dynamic gas will still be charged per instruction in the switch statement below
		if adapter.memShadow == nil {
			adapter.memShadow = NewMemory()
		}
		resizeShadow := func(sz uint64) {
			if sz > 0 {
				adapter.memShadow.Resize(sz)
			}
		}
		toWord := func(x uint64) uint64 { return (x + 31) / 32 }
		switch evmOp {
		case SLOAD:
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					st := newstack()
					defer returnStack(st)
					st.push(ctx.Operands[0])
					gas, err := gasSLoadEIP2929(adapter.evm, contract, st, adapter.memShadow, 0)
					if err != nil {
						if errors.Is(err, ErrGasUintOverflow) {
							err = nil
						}
						if err != nil {
							return err
						}
					}
					if gas > 0 {
						if contract.Gas < gas {
							return ErrOutOfGas
						}
						contract.Gas -= gas
					}
				}
			}
		case BALANCE, EXTCODESIZE, EXTCODEHASH:
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					st := newstack()
					defer returnStack(st)
					st.push(ctx.Operands[0])
					gas, err := gasEip2929AccountCheck(adapter.evm, contract, st, adapter.memShadow, 0)
					if err != nil {
						if errors.Is(err, ErrGasUintOverflow) {
							err = nil
						}
						if err != nil {
							return err
						}
					}
					if gas > 0 {
						if contract.Gas < gas {
							return ErrOutOfGas
						}
						contract.Gas -= gas
					}
				}
			}
		case EXP:
			if len(ctx.Operands) >= 2 {
				exp := ctx.Operands[1]
				expBytes := uint64((exp.BitLen() + 7) / 8)
				perByte := params.ExpByteFrontier
				if adapter.evm.chainRules.IsEIP158 {
					perByte = params.ExpByteEIP158
				}
				add := params.ExpGas + perByte*expBytes
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
			}
		case MLOAD, MSTORE, MSTORE8, RETURN, REVERT, CREATE, CREATE2:
			// Calculate the required memory size for the operation
			var needed uint64
			switch evmOp {
			case MLOAD, MSTORE:
				if len(ctx.Operands) > 0 {
					off := ctx.Operands[0].Uint64()
					needed = off + 32
				} else if ctx.MemorySize > 0 {
					// Some MIR pre-op contexts may not populate Operands; fall back to computed MemorySize.
					needed = ctx.MemorySize
				}
			case MSTORE8:
				if len(ctx.Operands) > 0 {
					off := ctx.Operands[0].Uint64()
					needed = off + 1
				} else if ctx.MemorySize > 0 {
					needed = ctx.MemorySize
				}
			case RETURN, REVERT:
				if len(ctx.Operands) >= 2 {
					off := ctx.Operands[0].Uint64()
					size := ctx.Operands[1].Uint64()
					needed = off + size
				} else if ctx.MemorySize > 0 {
					// Some MIR instructions may not populate Operands in the pre-op context.
					// Fall back to the interpreter-provided MemorySize (already computed in MIRInterpreter.exec).
					needed = ctx.MemorySize
				}
			case CREATE, CREATE2:
				// CREATE: value, offset, size
				// CREATE2: value, offset, size, salt
				if len(ctx.Operands) >= 3 {
					off := ctx.Operands[1].Uint64()
					size := ctx.Operands[2].Uint64()
					needed = off + size
				}
			}

			// Round up to 32 bytes
			memSize := (needed + 31) / 32 * 32
			if memSize < needed { // overflow check
				return ErrGasUintOverflow
			}

			if memSize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					}
					if err != nil {
						return err
					}
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
				if evmOp == CREATE || evmOp == CREATE2 {
					if len(ctx.Operands) >= 3 {
						size := ctx.Operands[2].Uint64()
						if size > params.MaxInitCodeSize {
							return fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
						}
						more := params.InitCodeWordGas * toWord(size)
						if contract.Gas < more {
							return ErrOutOfGas
						}
						contract.Gas -= more
					}
				}
				resizeShadow(memSize)
				// Pre-size MIR interpreter memory to move resize cost out of handler
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case CALLDATACOPY, CODECOPY, RETURNDATACOPY:
			// Always charge copy gas per word
			var size uint64
			if len(ctx.Operands) >= 3 {
				size = ctx.Operands[2].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas
			if contract.Gas < copyGas {
				return ErrOutOfGas
			}
			contract.Gas -= copyGas

			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			}
		case EXTCODECOPY:
			// Always charge copy gas per word
			var size uint64
			if len(ctx.Operands) >= 4 {
				size = ctx.Operands[3].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas
			if contract.Gas < copyGas {
				return ErrOutOfGas
			}
			contract.Gas -= copyGas

			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			}
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					var a [20]byte
					b := ctx.Operands[0].Bytes20()
					copy(a[:], b[:])
					if _, ok := adapter.warmAccounts[a]; !ok {
						st := newstack()
						defer returnStack(st)
						st.push(ctx.Operands[0])
						gas, err := gasEip2929AccountCheck(adapter.evm, contract, st, adapter.memShadow, 0)
						if err != nil {
							if errors.Is(err, ErrGasUintOverflow) {
								err = nil
							}
							if err != nil {
								return err
							}
						}
						if gas > 0 {
							if contract.Gas < gas {
								return ErrOutOfGas
							}
							contract.Gas -= gas
							adapter.warmAccounts[a] = struct{}{}
						}
					}
				}
			}
		case MCOPY:
			// Always charge copy gas per word
			var size uint64
			if len(ctx.Operands) >= 3 {
				size = ctx.Operands[2].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas
			if contract.Gas < copyGas {
				return ErrOutOfGas
			}
			contract.Gas -= copyGas

			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			}
		case KECCAK256:
			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						// align with base interpreter: don't surface overflow here
					} else {
						return err
					}
				}
				size := ctx.Length
				if size == 0 && len(ctx.Operands) >= 2 {
					size = ctx.Operands[1].Uint64()
				}
				wordGas := toWord(size) * params.Keccak256WordGas
				add := gas + wordGas
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			} else {
				// No growth: only charge per-word keccak cost
				size := ctx.Length
				if size == 0 && len(ctx.Operands) >= 2 {
					size = ctx.Operands[1].Uint64()
				}
				wordGas := toWord(size) * params.Keccak256WordGas
				if contract.Gas < wordGas {
					return ErrOutOfGas
				}
				contract.Gas -= wordGas
			}
		case LOG0, LOG1, LOG2, LOG3, LOG4:
			// EVM LOG gas = mem expansion + LogGas + topics + data.
			// Some MIR pre-op contexts may not populate MemorySize for LOG, so derive it
			// from (offset,size) operands as a fallback.
			memSize := ctx.MemorySize
			if memSize == 0 && len(ctx.Operands) >= 2 {
				off := ctx.Operands[0].Uint64()
				size := ctx.Operands[1].Uint64()
				needed := off + size
				memSize = (needed + 31) / 32 * 32
				if memSize < needed {
					return ErrGasUintOverflow
				}
			}
			memGas, err := memoryGasCost(adapter.memShadow, memSize)
			if err != nil {
				return err
			}
			if os.Getenv("MIR_DEBUG_LOG_GAS") == "1" {
				var off, sz uint64
				if len(ctx.Operands) >= 2 {
					off = ctx.Operands[0].Uint64()
					sz = ctx.Operands[1].Uint64()
				}
				fmt.Printf("MIR_LOG_GAS pc=%d op=0x%x memShadow=%d ctxMemSize=%d off=%d size=%d memSize=%d memGas=%d\n",
					ctx.M.EvmPC(), byte(evmOp), adapter.memShadow.Len(), ctx.MemorySize, off, sz, memSize, memGas)
			}
			n := int(evmOp - LOG0)
			add := memGas + params.LogGas + uint64(n)*params.LogTopicGas
			var size uint64
			if len(ctx.Operands) >= 2 {
				size = ctx.Operands[1].Uint64()
			}
			add += size * params.LogDataGas
			if contract.Gas < add {
				if shouldTraceBlock966Tx0(adapter.evm, contract) {
					var be uint64
					var firstPC uint
					if adapter.currentBlock != nil {
						firstPC = adapter.currentBlock.FirstPC()
						be = adapter.blockEntryGasCharges[adapter.currentBlock]
					}
					log.Warn("MIR_TRACE_BLOCK966 OOG at LOG",
						"evmPC", ctx.M.EvmPC(),
						"op", byte(evmOp),
						"need", add,
						"have", contract.Gas,
						"topics", n,
						"size", size,
						"memSize", memSize,
						"blockFirstPC", firstPC,
						"blockEntryCharged", be,
						"refund", adapter.evm.StateDB.GetRefund(),
					)
				}
				return ErrOutOfGas
			}
			contract.Gas -= add
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case SELFDESTRUCT:
			var gas uint64
			var err error
			if adapter.evm.chainRules.IsLondon {
				st := newstack()
				defer returnStack(st)
				gas, err = gasSelfdestructEIP3529(adapter.evm, contract, st, adapter.memShadow, 0)
			} else if adapter.evm.chainRules.IsBerlin {
				st := newstack()
				defer returnStack(st)
				gas, err = gasSelfdestructEIP2929(adapter.evm, contract, st, adapter.memShadow, 0)
			}
			if err != nil {
				return err
			}
			if gas > 0 {
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
			}
		case SSTORE:
			if len(ctx.Operands) >= 2 {
				st := newstack()
				defer returnStack(st)
				st.push(ctx.Operands[1])
				st.push(ctx.Operands[0])
				gas, err := gasSStore(adapter.evm, contract, st, adapter.memShadow, 0)
				if err != nil {
					return err
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
			}
		case CALL, CALLCODE, DELEGATECALL, STATICCALL:
			// Use vm gas calculators to set evm.callGasTemp and deduct dynamic gas
			// Build stack so Back(0)=requestedGas, Back(1)=addr, Back(2)=value (if present)
			st := newstack()
			// Ensure ctx.Operands length checks per variant
			var memSize uint64
			// Calculate required memory size
			switch evmOp {
			case CALL, CALLCODE:
				if len(ctx.Operands) < 7 {
					return nil
				}
				// args: [3] [4] -> [3]+[4]
				// ret: [5] [6] -> [5]+[6]
				argsOff := ctx.Operands[3].Uint64()
				argsSize := ctx.Operands[4].Uint64()
				retOff := ctx.Operands[5].Uint64()
				retSize := ctx.Operands[6].Uint64()
				m1 := argsOff + argsSize
				m2 := retOff + retSize
				needed := m1
				if m2 > m1 {
					needed = m2
				}
				memSize = (needed + 31) / 32 * 32
				if memSize < needed {
					return ErrGasUintOverflow
				}

				st.push(ctx.Operands[2])
				st.push(ctx.Operands[1])
				st.push(ctx.Operands[0])
				var dyn uint64
				var err error
				hadOverflow := false
				if adapter.evm.chainRules.IsBerlin {
					if evmOp == CALL {
						dyn, err = gasCallEIP2929(adapter.evm, contract, st, adapter.memShadow, memSize)
					} else {
						dyn, err = gasCallCodeEIP2929(adapter.evm, contract, st, adapter.memShadow, memSize)
					}
				} else {
					if evmOp == CALL {
						dyn, err = gasCall(adapter.evm, contract, st, adapter.memShadow, memSize)
					} else {
						dyn, err = gasCallCode(adapter.evm, contract, st, adapter.memShadow, memSize)
					}
				}
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						// Match stock interpreter: do not surface overflow from call gas calculation here
						// Effective call stipend/cap handling happens later in the call path
						hadOverflow = true
						err = nil
					}
					if err != nil {
						return err
					}
				}
				if contract.Gas < dyn {
					return ErrOutOfGas
				}
				contract.Gas -= dyn
				if !hadOverflow && memSize > 0 {
					resizeShadow(memSize)
					adapter.mirInterpreter.EnsureMemorySize(memSize)
				}
			case DELEGATECALL, STATICCALL:
				if len(ctx.Operands) < 6 {
					return nil
				}
				// args: [2] [3] -> [2]+[3]
				// ret: [4] [5] -> [4]+[5]
				argsOff := ctx.Operands[2].Uint64()
				argsSize := ctx.Operands[3].Uint64()
				retOff := ctx.Operands[4].Uint64()
				retSize := ctx.Operands[5].Uint64()
				m1 := argsOff + argsSize
				m2 := retOff + retSize
				needed := m1
				if m2 > m1 {
					needed = m2
				}
				memSize = (needed + 31) / 32 * 32
				if memSize < needed {
					return ErrGasUintOverflow
				}

				st.push(ctx.Operands[0])
				var dyn uint64
				var err error
				hadOverflow := false
				if adapter.evm.chainRules.IsBerlin {
					if evmOp == DELEGATECALL {
						dyn, err = gasDelegateCallEIP2929(adapter.evm, contract, st, adapter.memShadow, memSize)
					} else {
						dyn, err = gasStaticCallEIP2929(adapter.evm, contract, st, adapter.memShadow, memSize)
					}
				} else {
					if evmOp == DELEGATECALL {
						dyn, err = gasDelegateCall(adapter.evm, contract, st, adapter.memShadow, memSize)
					} else {
						dyn, err = gasStaticCall(adapter.evm, contract, st, adapter.memShadow, memSize)
					}
				}
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						hadOverflow = true
						err = nil
					}
					if err != nil {
						return err
					}
				}
				if contract.Gas < dyn {
					return ErrOutOfGas
				}
				contract.Gas -= dyn
				if !hadOverflow && memSize > 0 {
					resizeShadow(memSize)
					adapter.mirInterpreter.EnsureMemorySize(memSize)
				}
			}
		}
		if mirGasProbe != nil {
			mirGasProbe(uint64(ctx.M.EvmPC()), ctx.EvmOp, contract.Gas)
		}
		if mirGasTimingHook != nil {
			mirGasTimingHook(uint64(ctx.M.EvmPC()), ctx.EvmOp, time.Since(timingStart))
		}
		return nil
	})
	// Build a jump table matching current chain rules for gas accounting
	switch {
	case evm.chainRules.IsVerkle:
		adapter.table = &verkleInstructionSet
	case evm.chainRules.IsPrague:
		adapter.table = &pragueInstructionSet
	case evm.chainRules.IsCancun:
		adapter.table = &cancunInstructionSet
	case evm.chainRules.IsShanghai:
		adapter.table = &shanghaiInstructionSet
	case evm.chainRules.IsMerge:
		adapter.table = &mergeInstructionSet
	case evm.chainRules.IsLondon:
		adapter.table = &londonInstructionSet
	case evm.chainRules.IsBerlin:
		adapter.table = &berlinInstructionSet
	case evm.chainRules.IsIstanbul:
		adapter.table = &istanbulInstructionSet
	case evm.chainRules.IsConstantinople:
		adapter.table = &constantinopleInstructionSet
	case evm.chainRules.IsByzantium:
		adapter.table = &byzantiumInstructionSet
	case evm.chainRules.IsEIP158:
		adapter.table = &spuriousDragonInstructionSet
	case evm.chainRules.IsEIP150:
		adapter.table = &tangerineWhistleInstructionSet
	case evm.chainRules.IsHomestead:
		adapter.table = &homesteadInstructionSet
	default:
		adapter.table = &frontierInstructionSet
	}
	// Initialize a shadow memory for dynamic memory gas accounting
	adapter.memShadow = NewMemory()
	adapter.warmAccounts = make(map[[20]byte]struct{})
	adapter.storageCache = make(map[[32]byte][32]byte)
	return adapter
}

// Run executes the contract using MIR interpreter
// This method should match the signature of EVMInterpreter.Run
func (adapter *MIRInterpreterAdapter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// PERFORMANCE: Only evaluate expensive Hex() when debug logging is enabled
	if compiler.DebugLogsEnabled {
		compiler.MirDebugWarn("MIRInterpreterAdapter.Run called", "contract", contract.Address().Hex(), "readOnly", readOnly)
	}
	// Check if we have MIR-optimized code
	if !contract.HasMIRCode() {
		return nil, fmt.Errorf("MIR code missing for %s", contract.Address())
	}
	if compiler.DebugLogsEnabled {
		compiler.MirDebugWarn("MIRInterpreterAdapter.Run: contract has MIR code")
	}
	// Reset JUMPDEST de-dup guard per top-level run
	adapter.lastJdPC = ^uint32(0)
	adapter.lastJdBlockFirstPC = ^uint32(0)

	// Pre-flight fork gating: if the bytecode contains opcodes not enabled at the current fork,
	// mirror EVM behavior by returning invalid opcode errors instead of running MIR.
	rules := adapter.evm.chainRules
	code := contract.Code
	if !rules.IsConstantinople {
		if bytes.IndexByte(code, byte(SHR)) >= 0 || bytes.IndexByte(code, byte(SHL)) >= 0 || bytes.IndexByte(code, byte(SAR)) >= 0 {
			return nil, fmt.Errorf("invalid opcode: SHR")
		}
	}

	// Get the MIR CFG from the contract (type assertion)
	cfgInterface := contract.GetMIRCFG()
	cfg, ok := cfgInterface.(*compiler.CFG)
	if !ok || cfg == nil {
		return nil, fmt.Errorf("MIR CFG invalid for %s", contract.Address())
	}

	// Set current contract for the pre-installed hook
	// Save old contract for restoration after nested calls
	oldContract := adapter.currentContract
	adapter.currentContract = contract
	defer func() { adapter.currentContract = oldContract }()

	// Save current env state before modifying it (for nested calls)
	env := adapter.mirInterpreter.GetEnv()
	if env == nil {
		return nil, fmt.Errorf("MIR interpreter env is nil")
	}
	oldSelf := env.Self
	oldCaller := env.Caller
	oldOrigin := env.Origin
	oldCallValue := env.CallValue
	oldCalldata := env.Calldata
	oldCode := env.Code
	oldCurrentSelf := adapter.currentSelf

	// Restore env after execution
	defer func() {
		env.Self = oldSelf
		env.Caller = oldCaller
		env.Origin = oldOrigin
		env.CallValue = oldCallValue
		env.Calldata = oldCalldata
		env.Code = oldCode
		adapter.currentSelf = oldCurrentSelf
	}()

	// Save and restore memShadow to prevent pollution across nested calls
	oldMemShadow := adapter.memShadow
	adapter.memShadow = NewMemory() // Each contract gets its own memory shadow
	defer func() {
		adapter.memShadow = oldMemShadow
	}()

	// Set up MIR execution environment with contract-specific data
	adapter.setupExecutionEnvironment(contract, input)

	// Initialize block entry gas charges tracking (clear per contract execution)
	adapter.blockEntryGasCharges = make(map[*compiler.MIRBasicBlock]uint64)
	// Wire gas left getter so MirGAS can read it if needed
	// GAS opcode should return the gas value BEFORE constant gas for future opcodes is charged
	// (In EVM, GAS reads gas before future opcodes' constant gas is charged)
	if adapter.mirInterpreter != nil && adapter.mirInterpreter.GetEnv() != nil {
		env := adapter.mirInterpreter.GetEnv()
		env.GasLeft = func() uint64 {
			if adapter.currentContract != nil {
				gas := adapter.currentContract.Gas
				// GAS opcode should read gas before constant gas for future opcodes is charged
				// Add back block entry gas charges for the current block (if any)
				// This assumes GAS is the first opcode in the block - a more precise solution
				// would track which opcodes come after GAS based on evmPC
				if adapter.currentBlock != nil {
					if blockEntryGas, ok := adapter.blockEntryGasCharges[adapter.currentBlock]; ok {
						// Add back block entry gas charges (for opcodes that come after GAS)
						gas += blockEntryGas
					}
				}
				return gas
			}
			return 0
		}
	}

	// Install a pre-op hook to charge constant gas per opcode and any eliminated-op constants per block entry
	innerHook := func(ctx *compiler.MIRPreOpContext) error {
		if ctx == nil {
			return nil
		}
		// Test probe: observe gas BEFORE any MIR charging for this originating EVM opcode.
		// Must run early so we still capture the failing opcode when we OOG during charging.
		if mirGasPreProbe != nil && ctx.M != nil {
			mirGasPreProbe(uint64(ctx.M.EvmPC()), ctx.EvmOp, contract.Gas, ctx.IsBlockEntry)
		}
		// Keep last seen MIR pc/op/gas so we can print a precise OOG location
		// if MIR ends up returning ErrOutOfGas.
		if ctx.M != nil {
			adapter.lastTracePC = uint64(ctx.M.EvmPC())
			adapter.lastTraceOp = ctx.EvmOp
			adapter.lastTraceGasLeft = contract.Gas
			adapter.lastTraceAddr = contract.Address()
		}
		gasBefore := contract.Gas
		// Track if previous op was a JUMP/JUMPI to decide landing-time JUMPDEST charge
		if ctx.M != nil {
			if OpCode(ctx.EvmOp) == JUMP || OpCode(ctx.EvmOp) == JUMPI || ctx.M.Op() == compiler.MirJUMP || ctx.M.Op() == compiler.MirJUMPI {
				adapter.lastWasJump = true
			}
		}
		// On block entry, charge constant gas for all EVM opcodes in the block
		// (including PUSH/DUP/SWAP that don't have MIR instructions)
		// Exception: EXP and KECCAK256 constant gas is charged per instruction (along with dynamic gas)
		// But if EXP has no MIR instruction (optimized away), we need to charge it at block entry
		// Allow block entry gas charging even when ctx.M == nil (for blocks with Size=0)
		if ctx.IsBlockEntry && ctx.Block != nil {
			// Update current block
			adapter.currentBlock = ctx.Block
			// Track total gas charged at block entry (for GAS opcode to add back)
			var blockEntryTotalGas uint64

			// If the first opcode of the underlying bytecode at this block is JUMPDEST, EVM charges 1 gas upon entering.
			// Charge it up-front here (once), and record for GAS to add back.
			if adapter.currentContract != nil {
				code := adapter.currentContract.Code
				firstPC := int(ctx.Block.FirstPC())
				if code != nil && firstPC >= 0 && firstPC < len(code) && OpCode(code[firstPC]) == JUMPDEST {
					jg := params.JumpdestGas
					if adapter.currentContract.Gas < jg {
						if os.Getenv("MIR_DEBUG_BLOCKENTRY") == "1" {
							fmt.Printf("MIR block-entry OOG on first JUMPDEST: firstPC=%d need=%d have=%d\n", ctx.Block.FirstPC(), jg, adapter.currentContract.Gas)
						}
						return ErrOutOfGas
					}
					adapter.currentContract.Gas -= jg
					if mirGasChargeProbe != nil {
						mirGasChargeProbe(uint64(ctx.Block.FirstPC()), byte(JUMPDEST), jg, true)
					}
					blockEntryTotalGas += jg
					// remember we charged this (block-first JUMPDEST)
					adapter.lastJdPC = uint32(ctx.Block.FirstPC())
					adapter.lastJdBlockFirstPC = uint32(ctx.Block.FirstPC())
				}
			}
			// Validate that we're only charging for the current block.
			// Charge block entry gas for all opcodes in the block.
			// Get counts from EVMOpCounts(), but validate against actual bytecode in block's PC range.
			// This fixes cases where EVMOpCounts() includes opcodes from other blocks.
			var counts map[byte]uint32
			// Use currentContract instead of captured contract to handle nested calls correctly
			currentContract := adapter.currentContract
			if currentContract == nil {
				currentContract = contract
			}
			if currentContract.Code != nil && ctx.Block != nil {
				// Count opcodes directly from bytecode for this block.
				counts = countOpcodesInBlock(currentContract.Code, ctx.Block)
			} else {
				counts = ctx.Block.EVMOpCounts()
			}
			if counts != nil {
				if mirBlockEntryCountsProbe != nil && ctx.Block != nil {
					// Copy to avoid mutation surprises.
					cp := make(map[byte]uint32, len(counts))
					for k, v := range counts {
						cp[k] = v
					}
					mirBlockEntryCountsProbe(ctx.Block.FirstPC(), cp)
				}
				// For each opcode, charge block-entry constant gas for the number of instances
				// that did NOT result in a *real* MIR instruction execution (i.e., optimized away).
				//
				// IMPORTANT: We must exclude MirNOP/MirPHI from "emitted", because MirNOP is skipped at
				// runtime (no per-instruction gas charging), and PHI is an internal MIR op.
				emittedReal := make(map[byte]uint32)
				if ctx.Block != nil {
					for _, m := range ctx.Block.Instructions() {
						if m == nil {
							continue
						}
						if m.Op() == compiler.MirNOP || m.Op() == compiler.MirPHI {
							continue
						}
						if m.EvmOp() == 0 {
							continue
						}
						emittedReal[m.EvmOp()]++
					}
				}
				if os.Getenv("MIR_DEBUG_BLOCKENTRY") == "1" && ctx.Block != nil {
					fmt.Printf("MIR block-entry debug: firstPC=%d lastPC=%d instr=%d hasMIR=%d\n",
						ctx.Block.FirstPC(), ctx.Block.LastPC(), len(ctx.Block.Instructions()), len(emittedReal))
				}
				if os.Getenv("MIR_DEBUG_BLOCKENTRY_COUNTS") == "1" && ctx.Block != nil {
					fp := ctx.Block.FirstPC()
					var push, dup, swap, pop uint32
					for opb, cnt := range counts {
						op := OpCode(opb)
						switch {
						case op == POP:
							pop += cnt
						case op == PUSH0 || (op >= PUSH1 && op <= PUSH32):
							push += cnt
						case op >= DUP1 && op <= DUP16:
							dup += cnt
						case op >= SWAP1 && op <= SWAP16:
							swap += cnt
						}
					}
					fmt.Printf("MIR block-entry counts: firstPC=%d push=%d dup=%d swap=%d pop=%d\n", fp, push, dup, swap, pop)
				}
				// MIR_DEBUG_BLOCKENTRY_HASMIR_STACKOPS debug removed: block-entry charging now uses
				// (EVMOpCounts - EmittedOpCounts) instead of a boolean hasMIRInstruction set.
				for opb, cnt := range counts {
					if cnt == 0 {
						continue
					}
					// How many instances were optimized away?
					miss := cnt
					if e := emittedReal[opb]; e > 0 {
						if e >= miss {
							continue
						}
						miss = miss - e
					}
					if miss == 0 {
						continue
					}
					op := OpCode(opb)
					// Skip KECCAK256 constant gas at block entry (charged per instruction)
					if op == KECCAK256 {
						continue
					}
					// Skip LOG0-LOG4 constant gas at block entry.
					// LOG opcodes are charged via the dynamic-gas path (LogGas + topics + data + mem expansion).
					// Charging their constant part here would double-charge LogGas and can cause OOG divergence
					// for transactions that consume the exact block-provided gas limit (e.g. block 249 tx0).
					if op >= LOG0 && op <= LOG4 {
						continue
					}
					// Skip JUMPDEST constant gas at block entry (always charged per instruction when executed)
					// JUMPDEST is a jump target and must be charged when executed, not at block entry
					if op == JUMPDEST {
						continue
					}
					// Skip GAS constant gas at block entry (charged per instruction, but GAS reads gas before its own charge)
					// GAS opcode should return the gas value BEFORE its own constant gas is charged
					if op == GAS {
						continue
					}
					if op == EXP {
						// EXP has both constant and dynamic gas
						// If EXP has a MIR instruction, gas will be charged per instruction
						// If EXP was optimized away (no MIR instruction), charge gas at block entry using operands from bytecode
						if miss > 0 {
							// EXP was optimized away, but we still need to charge gas. Dynamic EXP gas depends
							// on the exponent size (in bytes), which is a stack value. In the optimized-away
							// cases we care about (e.g. block 966 tx0), the exponent is a constant pushed
							// immediately before EXP within the same basic block.
							//
							// We compute per-EXP gas by scanning the bytecode range of this basic block and
							// extracting the exponent from the 2nd-most-recent PUSH before each EXP.
							var totalGas uint64
							perByte := params.ExpByteFrontier
							if adapter.evm.chainRules.IsEIP158 {
								perByte = params.ExpByteEIP158
							}
							if currentContract.Code != nil && ctx.Block != nil {
								code := currentContract.Code
								start := int(ctx.Block.FirstPC())
								if start < 0 {
									start = 0
								}
								if start > len(code) {
									start = len(code)
								}
								// Determine an exclusive stop boundary similar to countOpcodesInBlock.
								stopBefore := len(code)
								if ch := ctx.Block.Children(); len(ch) > 0 {
									for _, c := range ch {
										if c == nil {
											continue
										}
										cp := int(c.FirstPC())
										if cp > start && cp < stopBefore {
											stopBefore = cp
										}
									}
								}
								opStarts := make([]int, 0, 64)
								charged := uint32(0)
								for pc := start; pc < len(code); {
									if pc == stopBefore && pc > start {
										break
									}
									opStarts = append(opStarts, pc)
									evmop := OpCode(code[pc])
									if evmop == JUMPDEST && pc > start {
										break
									}
									if evmop == EXP {
										// Find the exponent PUSH: EXP pops base (top) then exponent (next),
										// so exponent is the 2nd-most-recent PUSH before this EXP.
										var expVal *uint256.Int
										foundPush := 0
										for j := len(opStarts) - 2; j >= 0 && foundPush < 2; j-- {
											ppc := opStarts[j]
											pop := OpCode(code[ppc])
											if pop >= PUSH1 && pop <= PUSH32 {
												pushSize := int(pop - PUSH1 + 1)
												if ppc+1+pushSize <= len(code) {
													if foundPush == 1 {
														valBytes := make([]byte, 32)
														copy(valBytes[32-pushSize:], code[ppc+1:ppc+1+pushSize])
														expVal = uint256.NewInt(0).SetBytes(valBytes)
													}
													foundPush++
												}
											}
										}
										expBytes := uint64(0)
										if expVal != nil {
											expBytes = uint64((expVal.BitLen() + 7) / 8)
										}
										expGas := params.ExpGas + perByte*expBytes
										totalGas += expGas
										charged++
										if charged >= miss {
											break
										}
									}
									// Advance to next opcode boundary (skip PUSH data).
									nextPC := pc + 1
									if evmop >= PUSH1 && evmop <= PUSH32 {
										nextPC = pc + 1 + int(evmop-PUSH1+1)
									}
									if stopBefore > pc && stopBefore < nextPC {
										stopBefore = nextPC
									}
									if evmop == STOP || evmop == RETURN || evmop == REVERT || evmop == SELFDESTRUCT || evmop == JUMP || evmop == JUMPI {
										break
									}
									pc = nextPC
								}
							} else {
								// Fallback: charge constant only (dynamic unknown). This is conservative in the
								// sense it avoids spurious OOG from overcharging.
								totalGas = params.ExpGas * uint64(miss)
							}
							if currentContract.Gas < totalGas {
								if os.Getenv("MIR_DEBUG_BLOCKENTRY") == "1" {
									var fp, lp uint
									if ctx.Block != nil {
										fp = ctx.Block.FirstPC()
										lp = ctx.Block.LastPC()
									}
									fmt.Printf("MIR block-entry OOG on EXP(optimized-away): firstPC=%d lastPC=%d cnt=%d need=%d have=%d\n",
										fp, lp, cnt, totalGas, currentContract.Gas)
								}
								return ErrOutOfGas
							}
							currentContract.Gas -= totalGas
							if mirGasChargeProbe != nil {
								mirGasChargeProbe(uint64(ctx.Block.FirstPC()), byte(EXP), totalGas, true)
							}
							blockEntryTotalGas += totalGas
						}
						// Skip EXP constant gas at block entry if it has a MIR instruction (will be charged per instruction)
						continue
					}
					jt := (*adapter.table)[op]
					if jt != nil && jt.constantGas > 0 {
						total := jt.constantGas * uint64(miss)
						if currentContract.Gas < total {
							if os.Getenv("MIR_DEBUG_BLOCKENTRY") == "1" {
								var fp, lp uint
								if ctx.Block != nil {
									fp = ctx.Block.FirstPC()
									lp = ctx.Block.LastPC()
								}
								fmt.Printf("MIR block-entry OOG: firstPC=%d lastPC=%d op=0x%x cnt=%d constGas=%d need=%d have=%d\n",
									fp, lp, byte(op), cnt, jt.constantGas, total, currentContract.Gas)
							}
							return ErrOutOfGas
						}
						currentContract.Gas -= total
						if mirGasChargeProbe != nil {
							mirGasChargeProbe(uint64(ctx.Block.FirstPC()), byte(op), total, true)
						}
						blockEntryTotalGas += total
					}
				}
				// Store block entry gas charges for this block (for GAS opcode to add back)
				if blockEntryTotalGas > 0 {
					adapter.blockEntryGasCharges[ctx.Block] = blockEntryTotalGas
				}
			}
		}
		// Determine originating EVM opcode for this MIR
		evmOp := OpCode(ctx.EvmOp)
		// Defensive mapping: some MIR ops may not carry the originating EVM opcode byte
		// (ctx.EvmOp==0). In that case, derive it from the MIR op so constant gas accounting
		// remains correct.
		if evmOp == 0 && ctx.M != nil {
			switch ctx.M.Op() {
			case compiler.MirSUB:
				evmOp = SUB
			}
		}
		// Emit tracer OnOpcode before charging to maintain step-count parity
		if adapter.evm != nil && adapter.evm.Config.Tracer != nil && adapter.evm.Config.Tracer.OnOpcode != nil {
			scope := &ScopeContext{Memory: adapter.memShadow, Stack: nil, Contract: contract}
			adapter.evm.Config.Tracer.OnOpcode(uint64(ctx.M.EvmPC()), byte(evmOp), contract.Gas, 0, scope, nil, adapter.evm.depth, nil)
		}
		// Constant gas:
		// - For opcodes with MIR instructions: charged per-instruction (except special cases below).
		// - For opcodes without MIR instructions (e.g. PUSH/DUP/SWAP optimized away): charged at block entry above.
		if ctx.M != nil && !ctx.IsBlockEntry {
			// EXP and GAS have special handling below; JUMPDEST is handled via dedicated logic.
			if evmOp != 0 && evmOp != EXP && evmOp != GAS && evmOp != JUMPDEST {
				if adapter.table != nil && (*adapter.table)[evmOp] != nil {
					cg := (*adapter.table)[evmOp].constantGas
					if shouldTraceBlock966Tx0(adapter.evm, contract) && ctx.M != nil && ctx.M.EvmPC() == 5304 && evmOp == LOG1 {
						// Print a pinpoint snapshot of what we're about to charge at LOG1 (block 966 tx0).
						// This helps determine whether we are OOG due to the jump-table constant gas,
						// or due to dynamic LOG gas (mem + topics + data).
						var off, sz uint64
						if len(ctx.Operands) >= 2 {
							off = ctx.Operands[0].Uint64()
							sz = ctx.Operands[1].Uint64()
						}
						needed := off + sz
						if needed == 0 && ctx.MemorySize > 0 {
							needed = ctx.MemorySize
						}
						memSize := (needed + 31) / 32 * 32
						var memGas uint64
						if adapter.memShadow != nil && memSize > uint64(adapter.memShadow.Len()) {
							if g, err := memoryGasCost(adapter.memShadow, memSize); err == nil {
								memGas = g
							}
						}
						dynNeed := memGas + params.LogGas + params.LogTopicGas + sz*params.LogDataGas
						log.Warn("MIR_TRACE_BLOCK966 LOG1 precharge",
							"addr", contract.Address(),
							"gas", contract.Gas,
							"jumpTableConstGas", cg,
							"memShadow", func() int {
								if adapter.memShadow == nil {
									return 0
								}
								return adapter.memShadow.Len()
							}(),
							"ctxMemSize", ctx.MemorySize,
							"off", off,
							"size", sz,
							"memSize", memSize,
							"memGas", memGas,
							"dynNeed", dynNeed,
						)
					}
					if cg > 0 {
						if contract.Gas < cg {
							if shouldTraceBlock966Tx0(adapter.evm, contract) && ctx.M != nil && ctx.M.EvmPC() == 5304 && evmOp == LOG1 {
								log.Warn("MIR_TRACE_BLOCK966 OOG at LOG1 constant gas",
									"addr", contract.Address(),
									"have", contract.Gas,
									"need", cg,
								)
							}
							return ErrOutOfGas
						}
						contract.Gas -= cg
					}
				}
			}
		}
		// JUMPDEST is charged at block entry of landing blocks.
		// Charge JUMPDEST exactly when executed (matches base EVM semantics).
		// For zero-size landing blocks, MIR synthesizes a JUMPDEST pre-op at block-entry:
		// in that case, charge at block-entry; for normal blocks, charge on instruction (IsBlockEntry=false).
		// Charge JUMPDEST on landing exactly once.
		// Prefer charging at the instruction itself; if first MIR instruction doesn't carry EvmOp=JUMPDEST,
		// charge at block entry when coming from a jump, based on bytecode and/or first MIR instr.
		if ctx.M != nil && (ctx.EvmOp == byte(JUMPDEST) || ctx.M.Op() == compiler.MirJUMPDEST) {
			lp := uint32(ctx.M.EvmPC())
			var bf uint32
			if ctx.Block != nil {
				bf = uint32(ctx.Block.FirstPC())
			}
			// Skip if we've already charged for this exact landing in this block
			if adapter.lastJdPC == lp && adapter.lastJdBlockFirstPC == bf {
				// no-op
			} else {
				jumpdestGas := params.JumpdestGas
				if contract.Gas < jumpdestGas {
					return ErrOutOfGas
				}
				contract.Gas -= jumpdestGas
				adapter.lastJdPC = lp
				adapter.lastJdBlockFirstPC = bf
			}
		} else if ctx.IsBlockEntry && ctx.Block != nil && adapter.currentContract != nil {
			firstPC := int(ctx.Block.FirstPC())
			isJD := false
			// Check bytecode at firstPC
			code := adapter.currentContract.Code
			if code != nil && firstPC >= 0 && firstPC < len(code) {
				if OpCode(code[firstPC]) == JUMPDEST {
					isJD = true
				}
			}
			// Also check first MIR instruction if available
			if !isJD {
				if instrs := ctx.Block.Instructions(); len(instrs) > 0 && instrs[0] != nil {
					if instrs[0].Op() == compiler.MirJUMPDEST || instrs[0].EvmOp() == byte(JUMPDEST) {
						isJD = true
					}
				}
			}
			if isJD {
				lp := uint32(ctx.Block.FirstPC())
				bf := lp
				// Dedup
				if !(adapter.lastJdPC == lp && adapter.lastJdBlockFirstPC == bf) {
					jumpdestGas := params.JumpdestGas
					if contract.Gas < jumpdestGas {
						return ErrOutOfGas
					}
					contract.Gas -= jumpdestGas
					adapter.lastJdPC = lp
					adapter.lastJdBlockFirstPC = bf
				}
			}
			// Clear jump flag at block entry regardless
			adapter.lastWasJump = false
		}
		// Exception: GAS opcode must read gas BEFORE its own constant gas is charged
		// GAS opcode constant gas is skipped at block entry, so we charge it when executed
		// But GAS opcode reads the gas value, so we need to charge it AFTER it reads
		// Actually, we charge it in the pre-op hook (before execution), but GAS reads in execution
		// So GAS will read the gas AFTER its constant gas is charged, which matches EVM behavior
		if ctx.M != nil && ctx.M.Op() == compiler.MirGAS && !ctx.IsBlockEntry {
			// GAS opcode charges constant gas when executed
			if adapter.table != nil && (*adapter.table)[GAS] != nil {
				gasOpGas := (*adapter.table)[GAS].constantGas
				if gasOpGas > 0 {
					if contract.Gas < gasOpGas {
						return ErrOutOfGas
					}
					contract.Gas -= gasOpGas
				}
			}
		}
		// Dynamic gas will still be charged per instruction in the switch statement below
		// Dynamic gas metering
		// Ensure shadow memory reflects prior expansions
		if adapter.memShadow == nil {
			adapter.memShadow = NewMemory()
		}
		// Helper: resize shadow memory after charging
		resizeShadow := func(sz uint64) {
			if sz > 0 {
				adapter.memShadow.Resize(sz)
			}
		}
		// Helper: toWordSize
		toWord := func(x uint64) uint64 { return (x + 31) / 32 }
		// Handle EXP gas (check MIR opcode, evmOp, and MIR instruction's evmOp field)
		// Following EVM logic: EXP gas is charged via dynamicGas function (constant + dynamic together)
		expHandledByMir := false
		// Check all possible ways EXP might be detected
		isEXP := false
		if ctx.M != nil {
			mirOp := ctx.M.Op()
			mirEvmOp := ctx.M.EvmOp()
			if mirOp == compiler.MirEXP {
				isEXP = true
			} else if mirEvmOp == byte(EXP) {
				// Check MIR instruction's evmOp field directly
				isEXP = true
			}
		}
		if !isEXP && (evmOp == EXP || ctx.EvmOp == byte(EXP)) {
			isEXP = true
		}

		// DEBUG: innerHook trace
		// if true {
		//      opsStr := ""
		//      for _, op := range ctx.Operands {
		//          if op != nil {
		//              opsStr += fmt.Sprintf("%x ", op.Bytes())
		//          }
		//      }
		//
		// }

		if isEXP {
			expHandledByMir = true
			// EXP has both constant and dynamic gas (charged together, following EVM logic)
			if len(ctx.Operands) >= 2 {
				exp := ctx.Operands[1]
				expBytes := uint64((exp.BitLen() + 7) / 8)
				perByte := params.ExpByteFrontier
				if adapter.evm.chainRules.IsEIP158 {
					perByte = params.ExpByteEIP158
				}
				// Charge both constant and dynamic gas for EXP (same as EVM dynamicGas function)
				totalGas := params.ExpGas + perByte*expBytes
				if contract.Gas < totalGas {
					return ErrOutOfGas
				}
				contract.Gas -= totalGas
			} else {
				// Fallback: charge minimum EXP gas if operands not available
				minGas := params.ExpGas
				if contract.Gas < minGas {
					return ErrOutOfGas
				}
				contract.Gas -= minGas
			}
		}
		// EXP gas will be handled in the switch statement below when evmOp == EXP, following EVM logic
		switch evmOp {
		case SLOAD:
			// EIP-2929 SLOAD dynamic gas
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					st := newstack()
					st.push(new(uint256.Int).Set(ctx.Operands[0])) // peek -> slot
					gas, err := gasSLoadEIP2929(adapter.evm, contract, st, adapter.memShadow, 0)
					if err != nil {
						if errors.Is(err, ErrGasUintOverflow) {
							// Mirror base interpreter behavior: do not surface overflow from dynamic calc here
							// Leave callGasTemp as-is; the call execution path will handle effective gas
							err = nil
						}
						return err
					}
					if contract.Gas < gas {
						return ErrOutOfGas
					}
					contract.Gas -= gas
				}
			}
		case BALANCE, EXTCODESIZE, EXTCODEHASH:
			// EIP-2929 account warm/cold surcharge
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					st := newstack()
					st.push(new(uint256.Int).Set(ctx.Operands[0])) // peek -> address
					gas, err := gasEip2929AccountCheck(adapter.evm, contract, st, adapter.memShadow, 0)
					if err != nil {
						if errors.Is(err, ErrGasUintOverflow) {
							err = nil
						}
						return err
					}
					if gas > 0 {
						if contract.Gas < gas {
							return ErrOutOfGas
						}
						contract.Gas -= gas
					}
				}
			}
		case EXP:
			// EXP has both constant and dynamic gas (charged together, following EVM logic)
			// Constant gas is NOT charged at block entry for EXP (already skipped above)
			// Only charge here if MirEXP wasn't already handled above (to avoid double-charging)
			if !expHandledByMir {
				if len(ctx.Operands) >= 2 {
					exp := ctx.Operands[1]
					expBytes := uint64((exp.BitLen() + 7) / 8)
					perByte := params.ExpByteFrontier
					if adapter.evm.chainRules.IsEIP158 {
						perByte = params.ExpByteEIP158
					}
					// Charge both constant and dynamic gas for EXP (same as EVM dynamicGas function)
					totalGas := params.ExpGas + perByte*expBytes
					if contract.Gas < totalGas {
						return ErrOutOfGas
					}
					contract.Gas -= totalGas
				} else {
					// Fallback: charge minimum EXP gas if operands not available
					minGas := params.ExpGas
					if contract.Gas < minGas {
						return ErrOutOfGas
					}
					contract.Gas -= minGas
				}
			}
		case MLOAD, MSTORE, MSTORE8, RETURN, REVERT, CREATE, CREATE2:
			// Calculate the required memory size for the operation
			var needed uint64
			switch evmOp {
			case MLOAD, MSTORE:
				if len(ctx.Operands) > 0 {
					off := ctx.Operands[0].Uint64()
					needed = off + 32
				}
			case MSTORE8:
				if len(ctx.Operands) > 0 {
					off := ctx.Operands[0].Uint64()
					needed = off + 1
				}
			case RETURN, REVERT:
				if len(ctx.Operands) >= 2 {
					off := ctx.Operands[0].Uint64()
					size := ctx.Operands[1].Uint64()
					needed = off + size
				}
			case CREATE, CREATE2:
				// CREATE: value, offset, size
				// CREATE2: value, offset, size, salt
				if len(ctx.Operands) >= 3 {
					off := ctx.Operands[1].Uint64()
					size := ctx.Operands[2].Uint64()
					needed = off + size
				}
			}

			// Round up to 32 bytes
			memSize := (needed + 31) / 32 * 32
			if memSize < needed { // overflow check
				return ErrGasUintOverflow
			}

			// Only charge gas if memory is expanding
			if memSize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					}
					return err
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}

			// Additional gas charges
			if evmOp == CREATE2 {
				if len(ctx.Operands) >= 3 {
					size := ctx.Operands[2].Uint64()
					keccak256Gas := toWord(size) * params.Keccak256WordGas
					if contract.Gas < keccak256Gas {
						return ErrOutOfGas
					}
					contract.Gas -= keccak256Gas
				}
			}
			// EIP-3860 initcode per-word gas for CREATE/CREATE2 (only if Shanghai is active)
			if (evmOp == CREATE || evmOp == CREATE2) && adapter.evm.chainRules.IsShanghai {
				if len(ctx.Operands) >= 3 {
					size := ctx.Operands[2].Uint64()
					if size > params.MaxInitCodeSize {
						return fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
					}
					more := params.InitCodeWordGas * toWord(size)
					if contract.Gas < more {
						return ErrOutOfGas
					}
					contract.Gas -= more
				}
			}
		case CALLDATACOPY, CODECOPY, RETURNDATACOPY:
			// Always charge copy gas per word
			var memOff, size uint64
			if len(ctx.Operands) >= 3 {
				memOff = ctx.Operands[0].Uint64()
				size = ctx.Operands[2].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas

			needed := memOff + size
			memSize := (needed + 31) / 32 * 32
			if memSize < needed {
				return ErrGasUintOverflow
			}

			// Memory expansion gas if destination grows memory
			var memGas uint64
			if memSize > uint64(adapter.memShadow.Len()) {
				g, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				memGas = g
			}
			add := memGas + copyGas
			if add > 0 {
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
			}
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case EXTCODECOPY:
			// Always charge copy gas per word; memory expansion if needed
			var memOff, size uint64
			if len(ctx.Operands) >= 4 {
				memOff = ctx.Operands[1].Uint64()
				size = ctx.Operands[3].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas

			needed := memOff + size
			memSize := (needed + 31) / 32 * 32
			if memSize < needed {
				return ErrGasUintOverflow
			}

			var memGas uint64
			if memSize > uint64(adapter.memShadow.Len()) {
				g, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				memGas = g
			}
			add := memGas + copyGas
			if add > 0 {
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
			}
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
			// EIP-2929 cold-warm surcharge for EXTCODECOPY
			if adapter.evm.chainRules.IsBerlin {
				if len(ctx.Operands) >= 1 {
					st := newstack()
					st.push(new(uint256.Int).Set(ctx.Operands[0])) // address
					gas, err := gasEip2929AccountCheck(adapter.evm, contract, st, adapter.memShadow, 0)
					if err != nil {
						if errors.Is(err, ErrGasUintOverflow) {
							err = nil
						} else {
							return err
						}
					}
					if gas > 0 {
						if contract.Gas < gas {
							return ErrOutOfGas
						}
						contract.Gas -= gas
					}
				}
			}
		case MCOPY:
			// Always charge copy gas; and memory gas if growing
			// Operands: dest, src, len
			var dest, src, size uint64
			if len(ctx.Operands) >= 3 {
				dest = ctx.Operands[0].Uint64()
				src = ctx.Operands[1].Uint64()
				size = ctx.Operands[2].Uint64()
			}
			copyGas := toWord(size) * params.CopyGas

			// Expansion for both read and write
			m1 := dest + size
			m2 := src + size
			needed := m1
			if m2 > m1 {
				needed = m2
			}
			memSize := (needed + 31) / 32 * 32
			if memSize < needed {
				return ErrGasUintOverflow
			}

			var memGas uint64
			if memSize > uint64(adapter.memShadow.Len()) {
				g, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				memGas = g
			}
			add := memGas + copyGas
			if add > 0 {
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
			}
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case KECCAK256:
			// KECCAK256 has dynamic gas = memory expansion + word gas.
			// NOTE: constant gas (params.Keccak256Gas) is charged via the generic
			// per-instruction constant-gas path above.
			var offset, size uint64
			if len(ctx.Operands) >= 2 {
				offset = ctx.Operands[0].Uint64()
				size = ctx.Operands[1].Uint64()
			}
			// Calculate memory size
			needed := offset + size
			memSize := (needed + 31) / 32 * 32
			if memSize < needed {
				return ErrGasUintOverflow
			}

			wordGas := toWord(size) * params.Keccak256WordGas
			totalGas := wordGas
			// Memory expansion gas (if any)
			if memSize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						// align with base interpreter: don't surface overflow from call gas calc here
					} else {
						return err
					}
				}
				totalGas += gas
			}
			if contract.Gas < totalGas {
				return ErrOutOfGas
			}
			contract.Gas -= totalGas
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case LOG0, LOG1, LOG2, LOG3, LOG4:
			var offset, size uint64
			if len(ctx.Operands) >= 2 {
				offset = ctx.Operands[0].Uint64()
				size = ctx.Operands[1].Uint64()
			}
			// Match native EVM memory-expansion semantics: if size==0, there is no memory expansion
			// regardless of offset (e.g. LOG1 with size=0).
			needed := uint64(0)
			if size != 0 {
				needed = offset + size
			}
			memSize := (needed + 31) / 32 * 32
			if memSize < needed {
				return ErrGasUintOverflow
			}

			var gas uint64
			if memSize > uint64(adapter.memShadow.Len()) {
				g, err := memoryGasCost(adapter.memShadow, memSize)
				if err != nil {
					return err
				}
				gas = g
			}
			// Topics and data costs
			n := int(evmOp - LOG0)
			add := gas + params.LogGas + uint64(n)*params.LogTopicGas
			// LogDataGas is per byte
			add += size * params.LogDataGas
			if contract.Gas < add {
				return ErrOutOfGas
			}
			contract.Gas -= add
			if memSize > uint64(adapter.memShadow.Len()) {
				resizeShadow(memSize)
				adapter.mirInterpreter.EnsureMemorySize(memSize)
			}
		case SELFDESTRUCT:
			// Charge dynamic gas according to fork rules
			var gas uint64
			var err error
			if len(ctx.Operands) < 1 {
				return fmt.Errorf("SELFDESTRUCT missing operand")
			}
			st := newstack()
			beneficiaryAddr := new(uint256.Int).Set(ctx.Operands[0])
			st.push(beneficiaryAddr) // Push beneficiary address onto stack for gas calculation
			if adapter.evm.chainRules.IsLondon {
				gas, err = gasSelfdestructEIP3529(adapter.evm, contract, st, adapter.memShadow, 0)
			} else if adapter.evm.chainRules.IsBerlin {
				gas, err = gasSelfdestructEIP2929(adapter.evm, contract, st, adapter.memShadow, 0)
			}
			if err != nil {
				return err
			}
			if gas > 0 {
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
			}
		case SSTORE:
			// Build a tiny stack where Back(0)=key, Back(1)=value per gasSStore contract
			if len(ctx.Operands) >= 2 {
				st := newstack()
				// push value then key so Back(0)=key, Back(1)=value
				st.push(new(uint256.Int).Set(ctx.Operands[1]))
				st.push(new(uint256.Int).Set(ctx.Operands[0]))
				// Use EIP-2929/3529 gas functions for Berlin/London
				var gas uint64
				var err error
				if adapter.evm.chainRules.IsLondon {
					gas, err = gasSStoreEIP3529(adapter.evm, contract, st, adapter.memShadow, 0)
				} else if adapter.evm.chainRules.IsBerlin {
					gas, err = gasSStoreEIP2929(adapter.evm, contract, st, adapter.memShadow, 0)
				} else {
					gas, err = gasSStore(adapter.evm, contract, st, adapter.memShadow, 0)
				}
				if err != nil {
					return err
				}
				if contract.Gas < gas {
					if shouldTraceBlock966Tx0(adapter.evm, contract) {
						// Replicate the gasSStore key/value decode for logging.
						key := st.Back(0).Bytes32()
						val := st.Back(1)
						cur := adapter.evm.StateDB.GetState(contract.Address(), key)
						committed := adapter.evm.StateDB.GetCommittedState(contract.Address(), key)
						log.Warn("MIR_TRACE_BLOCK966 OOG at SSTORE",
							"evmPC", ctx.M.EvmPC(),
							"need", gas,
							"have", contract.Gas,
							"key", common.Hash(key),
							"valSign", val.Sign(),
							"cur", cur,
							"committed", committed,
							"isPetersburg", adapter.evm.chainRules.IsPetersburg,
							"isConstantinople", adapter.evm.chainRules.IsConstantinople,
							"isBerlin", adapter.evm.chainRules.IsBerlin,
							"isLondon", adapter.evm.chainRules.IsLondon,
							"refund", adapter.evm.StateDB.GetRefund(),
						)
					}
					return ErrOutOfGas
				}
				contract.Gas -= gas
			}
		case CALL, CALLCODE, DELEGATECALL, STATICCALL:
			// Use vm gas calculators to set evm.callGasTemp and deduct dynamic gas
			// Build stack so Back(0)=requestedGas, Back(1)=addr, Back(2)=value (if present)
			st := newstack()
			// Ensure ctx.Operands length checks per variant
			switch evmOp {
			case CALL, CALLCODE:
				if len(ctx.Operands) < 7 {
					return nil
				}
				reqGas := new(uint256.Int).Set(ctx.Operands[0])
				addr := new(uint256.Int)
				// address at operands[1]
				addr.Set(ctx.Operands[1])
				val := new(uint256.Int).Set(ctx.Operands[2])
				st.push(val)    // Back(2)
				st.push(addr)   // Back(1)
				st.push(reqGas) // Back(0)
				var dyn uint64
				var err error
				if adapter.evm.chainRules.IsBerlin {
					if evmOp == CALL {
						dyn, err = gasCallEIP2929(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					} else {
						dyn, err = gasCallCodeEIP2929(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					}
				} else {
					if evmOp == CALL {
						dyn, err = gasCall(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					} else {
						dyn, err = gasCallCode(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					}
				}
				if err != nil {
					return err
				}
				if contract.Gas < dyn {
					return ErrOutOfGas
				}
				contract.Gas -= dyn
				resizeShadow(ctx.MemorySize)
			case DELEGATECALL, STATICCALL:
				if len(ctx.Operands) < 6 {
					return nil
				}
				st := newstack()
				reqGas := new(uint256.Int).Set(ctx.Operands[0])
				addr := new(uint256.Int).Set(ctx.Operands[1])
				st.push(addr)   // Back(1) - address
				st.push(reqGas) // Back(0) - requested gas
				var dyn uint64
				var err error
				if adapter.evm.chainRules.IsBerlin {
					if evmOp == DELEGATECALL {
						dyn, err = gasDelegateCallEIP2929(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					} else {
						dyn, err = gasStaticCallEIP2929(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					}
				} else {
					if evmOp == DELEGATECALL {
						dyn, err = gasDelegateCall(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					} else {
						dyn, err = gasStaticCall(adapter.evm, contract, st, adapter.memShadow, ctx.MemorySize)
					}
				}
				if err != nil {
					return err
				}
				if contract.Gas < dyn {
					return ErrOutOfGas
				}
				contract.Gas -= dyn
				resizeShadow(ctx.MemorySize)
			}
		}
		// Test probe: allow tests to observe gas left after each MIR step
		if mirGasProbe != nil {
			mirGasProbe(uint64(ctx.M.EvmPC()), ctx.EvmOp, contract.Gas)
		}
		if mirGasChargeProbe != nil && ctx.M != nil {
			charged := uint64(0)
			if gasBefore >= contract.Gas {
				charged = gasBefore - contract.Gas
			}
			mirGasChargeProbe(uint64(ctx.M.EvmPC()), ctx.EvmOp, charged, ctx.IsBlockEntry)
		}
		return nil
	}
	// Save current beforeOp hook to restore after this execution
	oldHook := adapter.mirInterpreter.GetBeforeOpHook()
	defer func() {
		// Restore previous hook after execution
		if oldHook != nil {
			adapter.mirInterpreter.SetBeforeOpHook(oldHook)
		}
	}()

	adapter.mirInterpreter.SetBeforeOpHook(func(ctx *compiler.MIRPreOpContext) error {
		err := innerHook(ctx)
		if err != nil && errors.Is(err, ErrGasUintOverflow) {
			return nil
		}
		return err
	})

	// Selector-based direct dispatch is disabled; always fall back to default entry.

	// No selector: execute the first basic block only
	bbs := cfg.GetBasicBlocks()
	// Allow blocks with Size=0 to execute if they have children (e.g., entry block with only PUSH)
	// PUSH operations don't create MIR instructions but are handled via block-level opcode counts
	if len(bbs) > 0 {
		bbByPC := cfg.BlockByPC(0)
		var bbByPCSize uint
		if bbByPC != nil {
			bbByPCSize = bbByPC.Size()
		}
		log.Warn("Adapter.Run checking entry block", "len(bbs)", len(bbs), "bb0.Size", bbs[0].Size(), "bb0.children", len(bbs[0].Children()), "BlockByPC(0)!=nil", bbByPC != nil, "BlockByPC(0).Size", bbByPCSize)
	} else {
		log.Warn("Adapter.Run checking entry block", "len(bbs)", 0)
	}
	entryBlockHasContent := len(bbs) > 0 && bbs[0] != nil && (bbs[0].Size() > 0 || len(bbs[0].Children()) > 0)
	hasCode := len(contract.Code) > 0
	if entryBlockHasContent || hasCode {
		result, err := adapter.mirInterpreter.RunCFGWithResolver(cfg, bbs[0])
		if err != nil {
			// High-signal OOG pinpointing for block 966 tx0: log the last MIR pc/op we saw.
			if err == ErrOutOfGas && shouldTraceBlock966Tx0(adapter.evm, contract) {
				var be uint64
				var firstPC uint
				if adapter.currentBlock != nil {
					firstPC = adapter.currentBlock.FirstPC()
					be = adapter.blockEntryGasCharges[adapter.currentBlock]
				}
				log.Warn("MIR_TRACE_BLOCK966 OOG",
					"addr", adapter.lastTraceAddr,
					"evmPC", adapter.lastTracePC,
					"op", fmt.Sprintf("0x%x", adapter.lastTraceOp),
					"gasLeftBeforeHook", adapter.lastTraceGasLeft,
					"blockFirstPC", firstPC,
					"blockEntryCharged", be,
					"origin", adapter.evm.TxContext.Origin,
				)
			}
			// Mirror canonical EVM invalid-jump semantics (do not surface MIR_FALLBACK here).
			if err == compiler.ErrInvalidJumpDestination {
				return result, ErrInvalidJump
			}
			// No fallback: surface MIR errors directly so MIR bugs are not masked.
			// Map compiler.errREVERT to vm.ErrExecutionReverted to preserve gas
			if errors.Is(err, compiler.GetErrREVERT()) {
				return result, ErrExecutionReverted
			}
			// Preserve returndata on error (e.g., REVERT) to match EVM semantics
			return result, err
		}
		// If MIR executed without error, return whatever returndata was produced.
		// An empty result (e.g., STOP) should not trigger fallback; mirror EVM semantics
		// where a STOP simply returns empty bytes.
		if compiler.DebugLogsEnabled {
			fmt.Printf("✅ MIR interpreter completed successfully: contract=%s resultLen=%d\n", contract.Address().Hex(), len(result))
		}
		return result, nil
	}
	// If nothing returned from the entry, check for implicit STOP
	if len(contract.Code) > 0 {
		return nil, nil // Implicit STOP for code with no MIR-executable instructions
	}
	if compiler.DebugLogsEnabled {
		fmt.Printf("❌ MIR entry block produced no result: contract=%s\n", contract.Address().Hex())
	}
	return nil, fmt.Errorf("MIR entry block produced no result")
}

// setupExecutionEnvironment configures the MIR interpreter with contract-specific data
func (adapter *MIRInterpreterAdapter) setupExecutionEnvironment(contract *Contract, input []byte) {
	env := adapter.mirInterpreter.GetEnv()

	// Set calldata (copy to avoid slice reuse issues)
	if input != nil {
		env.Calldata = append([]byte(nil), input...)
	} else {
		env.Calldata = nil
	}

	// Reset interpreter transient state to avoid per-call allocations
	// Reuse memory backing store by truncating length to zero
	if adapter.mirInterpreter != nil {
		// Reset memory view
		if adapter.mirInterpreter.MemoryCap() > 0 {
			adapter.mirInterpreter.TruncateMemory()
		}
		// Reset return data
		adapter.mirInterpreter.ResetReturnData()
		// Reset execution caches/results to avoid cross-call value leakage
		adapter.mirInterpreter.ResetExecutionState()
	}

	// Reset warm caches per top-level Run
	if adapter.warmAccounts == nil {
		adapter.warmAccounts = make(map[[20]byte]struct{})
	} else {
		for k := range adapter.warmAccounts {
			delete(adapter.warmAccounts, k)
		}
	}
	// Reset storage cache per run
	if adapter.storageCache == nil {
		adapter.storageCache = make(map[[32]byte][32]byte)
	} else {
		for k := range adapter.storageCache {
			delete(adapter.storageCache, k)
		}
	}

	// Set address context
	{
		addr := contract.Address()
		caller := contract.Caller()
		origin := adapter.evm.TxContext.Origin
		adapter.currentSelf = addr
		copy(env.Self[:], addr[:])
		copy(env.Caller[:], caller[:])
		copy(env.Origin[:], origin[:])

		// Debug: trace call context for ERC20 transfer(selector 0xa9059cbb).
		// This helps diagnose "transfer from the zero address" / balance divergence between repos.
		if os.Getenv("MIR_TRACE_CALL_CONTEXT") == "1" && len(input) >= 4 &&
			input[0] == 0xa9 && input[1] == 0x05 && input[2] == 0x9c && input[3] == 0xbb {
			// Use stdout to ensure visibility in `go test -v` output.
			cv := "nil"
			if contract.Value() != nil {
				cv = contract.Value().String()
			}
			fmt.Printf("MIR_CALLCTX transfer self=%s caller=%s origin=%s callValue=%s calldataLen=%d\n",
				addr.Hex(), caller.Hex(), origin.Hex(), cv, len(input))
		}
	}

	// Set gas price from transaction context
	if adapter.evm.TxContext.GasPrice != nil {
		env.GasPrice = adapter.evm.TxContext.GasPrice.Uint64()
	}
	// Set blob base fee from block context (for BLOBBASEFEE opcode)
	if adapter.evm.Context.BlobBaseFee != nil {
		env.BlobBaseFee = adapter.evm.Context.BlobBaseFee.Uint64()
	} else {
		env.BlobBaseFee = 0
	}

	// Set call value for CALLVALUE op
	if contract != nil && contract.Value() != nil {
		// MIR will clone when reading, but we also clone here to insulate from Contract mutation
		env.CallValue = new(uint256.Int).Set(contract.Value())
	} else {
		env.CallValue = uint256.NewInt(0)
	}

	// Provide code for CODE* ops
	env.Code = contract.Code

	// External code accessors
	if env.ExtCodeSize == nil {
		env.ExtCodeSize = func(addr [20]byte) uint64 {
			a := common.BytesToAddress(addr[:])
			code := adapter.evm.StateDB.GetCode(a)
			if code == nil {
				return 0
			}
			return uint64(len(code))
		}
	}
	if env.ExtCodeCopy == nil {
		env.ExtCodeCopy = func(addr [20]byte, codeOffset uint64, dest []byte) {
			a := common.BytesToAddress(addr[:])
			code := adapter.evm.StateDB.GetCode(a)
			if code == nil {
				for i := range dest {
					dest[i] = 0
				}
				return
			}
			for i := uint64(0); i < uint64(len(dest)); i++ {
				idx := codeOffset + i
				if idx < uint64(len(code)) {
					dest[i] = code[idx]
				} else {
					dest[i] = 0
				}
			}
		}
	}

	// EXTCODEHASH via StateDB (installed once)
	if env.ExtCodeHash == nil {
		env.ExtCodeHash = func(addr [20]byte) [32]byte {
			a := common.BytesToAddress(addr[:])
			h := adapter.evm.StateDB.GetCodeHash(a)
			var out [32]byte
			copy(out[:], h[:])
			return out
		}
	}
	// Log function to route logs back into EVM (installed once)
	if env.LogFunc == nil {
		env.LogFunc = func(addr [20]byte, topics [][32]byte, data []byte) {
			a := common.BytesToAddress(addr[:])
			hashes := make([]common.Hash, len(topics))
			for i := range topics {
				hashes[i] = common.BytesToHash(topics[i][:])
			}
			if adapter.evm.Context.BlobBaseFee != nil {
				env.BlobBaseFee = adapter.evm.Context.BlobBaseFee.Uint64()
			}
			env.BlobHashFunc = func(index uint64) [32]byte {
				if index < uint64(len(adapter.evm.TxContext.BlobHashes)) {
					h := adapter.evm.TxContext.BlobHashes[index]
					var out [32]byte
					copy(out[:], h[:])
					return out
				}
				return [32]byte{}
			}
			adapter.evm.StateDB.AddLog(&coretypes.Log{
				Address:     a,
				Topics:      hashes,
				Data:        append([]byte(nil), data...),
				BlockNumber: adapter.evm.Context.BlockNumber.Uint64(),
			})
		}
	}

	// Wire external execution to stock EVM for CALL-family ops
	env.ExternalCall = func(kind byte, addr20 [20]byte, value *uint256.Int, callInput []byte, requestedGas uint64) (ret []byte, success bool) {
		to := common.BytesToAddress(addr20[:])
		// Use callGasTemp set by beforeOp hook (gas calculation already done)
		gas := adapter.evm.callGasTemp
		if (kind == 0 || kind == 1) && value != nil && !value.IsZero() {
			gas += params.CallStipend
		}
		var (
			out      []byte
			leftover uint64
			err      error
		)
		switch kind {
		case 0: // CALL
			out, leftover, err = adapter.evm.Call(contract.Caller(), to, callInput, gas, value)
		case 1: // CALLCODE
			out, leftover, err = adapter.evm.CallCode(contract.Caller(), to, callInput, gas, value)
		case 2: // DELEGATECALL
			// DelegateCall signature: (originCaller, caller, addr, input, gas, value)
			// For delegatecall from MIR, the current contract's caller is the originCaller
			// and the current contract's address is the caller (for the nested call)
			out, leftover, err = adapter.evm.DelegateCall(contract.Caller(), contract.Address(), to, callInput, gas, contract.Value())
		case 3: // STATICCALL
			out, leftover, err = adapter.evm.StaticCall(contract.Caller(), to, callInput, gas)
		default:
			return nil, false
		}
		// Refund leftover like stock interpreter
		contract.RefundGas(leftover, adapter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)
		if err != nil {
			return out, false
		}
		return out, true
	}

	// Wire CREATE and CREATE2 to stock EVM
	env.CreateContract = func(kind byte, value *uint256.Int, init []byte, salt *[32]byte) (addr [20]byte, success bool, ret []byte) {
		gas := contract.Gas
		// Apply EIP-150: parent gas reduction by 1/64 before passing to child
		gas -= gas / 64
		// Deduct from parent before call, matching opCreate/opCreate2
		// Use correct tracing reason for CREATE vs CREATE2
		tracingReason := tracing.GasChangeCallContractCreation
		if kind == 5 { // CREATE2
			tracingReason = tracing.GasChangeCallContractCreation2
		}
		contract.UseGas(gas, adapter.evm.Config.Tracer, tracingReason)
		var (
			out      []byte
			newAddr  common.Address
			leftover uint64
			err      error
		)
		if kind == 4 { // CREATE
			// Use contract.Address() (the executing contract) not contract.Caller() (who called this contract)
			// This matches the behavior of opCreate in instructions.go
			out, newAddr, leftover, err = adapter.evm.Create(contract.Address(), init, gas, value)
		} else { // CREATE2
			var saltU *uint256.Int
			if salt != nil {
				saltU = new(uint256.Int).SetBytes(salt[:])
			} else {
				saltU = uint256.NewInt(0)
			}
			// Use contract.Address() to match opCreate2 in instructions.go
			out, newAddr, leftover, err = adapter.evm.Create2(contract.Address(), init, gas, value, saltU)
		}
		copy(addr[:], newAddr[:])
		// Refund leftover like stock interpreter
		contract.RefundGas(leftover, adapter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)
		if err != nil {
			return addr, false, out
		}
		return addr, true, out
	}

	// Do not override any tracer set by tests; leave as-is.

	// Block info
	env.GasLimit = adapter.evm.Context.GasLimit
	if adapter.evm.Context.Difficulty != nil {
		env.Difficulty = adapter.evm.Context.Difficulty.Uint64()
	}
	copy(env.Coinbase[:], adapter.evm.Context.Coinbase[:])
	env.BlockHashFunc = func(num uint64) [32]byte {
		// Use Context.GetHash if available; else return zero
		h := adapter.evm.Context.GetHash(num)
		var out [32]byte
		copy(out[:], h[:])
		return out
	}

	// Set fork flags from chain rules
	rules := adapter.evm.chainRules
	env.IsByzantium = rules.IsByzantium
	env.IsConstantinople = rules.IsConstantinople
	env.IsIstanbul = rules.IsIstanbul
	env.IsLondon = rules.IsLondon
	// Optionally extend with newer flags if MIR grows support for those ops
	// No-op if not referenced in interpreter.

	// Install jumpdest checker using EVM contract helpers
	env.CheckJumpdest = func(pc uint64) bool {

		// Must be within bounds and at a JUMPDEST and code segment
		if pc >= uint64(len(contract.Code)) {

			return false
		}
		if OpCode(contract.Code[pc]) != JUMPDEST {

			return false
		}
		isC := contract.isCode(pc)

		return isC
	}
}

// CanRun checks if this adapter can run the given contract
func (adapter *MIRInterpreterAdapter) CanRun(contract *Contract) bool {
	return contract.HasMIRCode()
}
