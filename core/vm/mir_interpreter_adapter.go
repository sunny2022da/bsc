package vm

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/tracing"
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// warmSlotKey identifies a warmed storage slot for the current contract address
type warmSlotKey struct {
	addr [20]byte
	slot [32]byte
}

// mirGasProbe is an optional test hook to observe MIR gas after each instruction
var mirGasProbe func(pc uint64, op byte, gasLeft uint64)

// mirGasTimingHook, when set (testing only), receives time spent inside the
// adapter's pre-op hook (i.e., gas accounting for the originating EVM opcode).
var mirGasTimingHook func(pc uint64, op byte, dur time.Duration)

// SetMIRGasTimingHook installs a callback to observe MIR gas calculation time per-op (testing only).
func SetMIRGasTimingHook(cb func(pc uint64, op byte, dur time.Duration)) { mirGasTimingHook = cb }

// SetMIRGasProbe installs a callback to observe MIR gas after each instruction (testing only)
func SetMIRGasProbe(cb func(pc uint64, op byte, gasLeft uint64)) {
	mirGasProbe = cb
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
	warmSlots    map[warmSlotKey]struct{}
	// storageCache caches SLOAD values within a single Run (key is 32-byte slot)
	storageCache map[[32]byte][32]byte
}

// NewMIRInterpreterAdapter creates a new MIR interpreter adapter for EVM
func NewMIRInterpreterAdapter(evm *EVM) *MIRInterpreterAdapter {
	// Create adapter early so closures can reference cached fields
	adapter := &MIRInterpreterAdapter{evm: evm}

	// Create MIR execution environment from EVM context
	env := &compiler.MIRExecutionEnv{
		Memory:      make([]byte, 0, 1024),
		Storage:     make(map[[32]byte][32]byte),
		BlockNumber: evm.Context.BlockNumber.Uint64(),
		Timestamp:   evm.Context.Time,
		ChainID:     evm.ChainConfig().ChainID.Uint64(),
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
		evm.StateDB.SetState(adapter.currentSelf, common.BytesToHash(key[:]), common.BytesToHash(value[:]))
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
		if adapter.evm != nil && adapter.evm.Config.Tracer != nil && adapter.evm.Config.Tracer.OnOpcode != nil && ctx.IsBlockEntry {
			scope := &ScopeContext{Memory: adapter.memShadow, Stack: nil, Contract: contract}
			adapter.evm.Config.Tracer.OnOpcode(uint64(ctx.M.EvmPC()), byte(evmOp), contract.Gas, 0, scope, nil, adapter.evm.depth, nil)
		}
		if ctx.M.Op() != compiler.MirPHI {
			jt := (*adapter.table)[evmOp]
			if jt != nil && jt.constantGas > 0 {
				if contract.Gas < jt.constantGas {
					return ErrOutOfGas
				}
				contract.Gas -= jt.constantGas
			}
		}
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
			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
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
				resizeShadow(ctx.MemorySize)
				// Pre-size MIR interpreter memory to move resize cost out of handler
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			}
		case CALLDATACOPY, CODECOPY, RETURNDATACOPY:
			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				var size uint64
				if len(ctx.Operands) >= 3 {
					size = ctx.Operands[2].Uint64()
				}
				copyGas := toWord(size) * params.CopyGas
				add := gas + copyGas
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
			}
		case EXTCODECOPY:
			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				var size uint64
				if len(ctx.Operands) >= 4 {
					size = ctx.Operands[3].Uint64()
				}
				copyGas := toWord(size) * params.CopyGas
				add := gas + copyGas
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
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
			if ctx.MemorySize > uint64(adapter.memShadow.Len()) {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
						err = nil
					} else {
						return err
					}
				}
				var size uint64
				if len(ctx.Operands) >= 3 {
					size = ctx.Operands[2].Uint64()
				}
				copyGas := toWord(size) * params.CopyGas
				add := gas + copyGas
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
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
			if ctx.MemorySize > 0 {
				gas, err := memoryGasCost(adapter.memShadow, ctx.MemorySize)
				if err != nil {
					if errors.Is(err, ErrGasUintOverflow) {
					} else {
						return err
					}
				}
				n := int(evmOp - LOG0)
				add := gas + uint64(n)*params.LogTopicGas
				var size uint64
				if len(ctx.Operands) >= 2 {
					size = ctx.Operands[1].Uint64()
				}
				add += size * params.LogDataGas
				if contract.Gas < add {
					return ErrOutOfGas
				}
				contract.Gas -= add
				resizeShadow(ctx.MemorySize)
				adapter.mirInterpreter.EnsureMemorySize(ctx.MemorySize)
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
					if errors.Is(err, ErrGasUintOverflow) {
					} else {
						return err
					}
				}
				if contract.Gas < gas {
					return ErrOutOfGas
				}
				contract.Gas -= gas
			}
		case CALL, CALLCODE, DELEGATECALL, STATICCALL:
			st := newstack()
			defer returnStack(st)
			switch evmOp {
			case CALL, CALLCODE:
				if len(ctx.Operands) < 7 {
					return nil
				}
				st.push(ctx.Operands[2])
				st.push(ctx.Operands[1])
				st.push(ctx.Operands[0])
				var dyn uint64
				var err error
				hadOverflow := false
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
				if !hadOverflow {
					resizeShadow(ctx.MemorySize)
				}
			case DELEGATECALL, STATICCALL:
				if len(ctx.Operands) < 6 {
					return nil
				}
				st := newstack()
				defer returnStack(st)
				st.push(ctx.Operands[0])
				var dyn uint64
				var err error
				hadOverflow := false
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
				if !hadOverflow {
					resizeShadow(ctx.MemorySize)
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
	adapter.warmSlots = make(map[warmSlotKey]struct{})
	adapter.storageCache = make(map[[32]byte][32]byte)
	return adapter
}

// Run executes the contract using MIR interpreter
// This method should match the signature of EVMInterpreter.Run
func (adapter *MIRInterpreterAdapter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// Check if we have MIR-optimized code
	if !contract.HasMIRCode() {
		// Fallback to regular EVM interpreter
		return adapter.evm.Interpreter().Run(contract, input, readOnly)
	}

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
		// Fallback if no valid MIR CFG available
		log.Error("MIR fallback: invalid CFG, using EVM interpreter", "addr", contract.Address(), "codehash", contract.CodeHash)
		return adapter.evm.Interpreter().Run(contract, input, readOnly)
	}

	// Set current contract for the pre-installed hook
	adapter.currentContract = contract
	// Set up MIR execution environment with contract-specific data
	adapter.setupExecutionEnvironment(contract, input)

	// Wire gas left getter so MirGAS can read it if needed
	if adapter.mirInterpreter != nil && adapter.mirInterpreter.GetEnv() != nil {
		env := adapter.mirInterpreter.GetEnv()
		env.GasLeft = func() uint64 {
			if adapter.currentContract != nil {
				return adapter.currentContract.Gas
			}
			return 0
		}
	}

	// Selector-based direct dispatch is disabled; always fall back to default entry.

	// No selector: execute the first basic block only
	bbs := cfg.GetBasicBlocks()
	if len(bbs) > 0 && bbs[0] != nil && bbs[0].Size() > 0 {
		result, err := adapter.mirInterpreter.RunCFGWithResolver(cfg, bbs[0])
		if err != nil {
			if err == compiler.ErrMIRFallback {
				if adapter.evm.Config.MIRStrictNoFallback {
					// Strict mode: do not fallback; surface the error for debugging.
					return nil, fmt.Errorf("MIR strict mode: no fallback (reason=%w)", err)
				}
				log.Error("MIR fallback requested by interpreter, using EVM interpreter", "addr", contract.Address(), "pc", 0)
				return adapter.evm.baseInterpreter.Run(contract, input, readOnly)
			}
			// Preserve returndata on error (e.g., REVERT) to match EVM semantics
			return result, err
		}
		// If MIR executed without error, return whatever returndata was produced.
		// An empty result (e.g., STOP) should not trigger fallback; mirror EVM semantics
		// where a STOP simply returns empty bytes.
		return result, nil
	}
	// If nothing returned from the entry, fallback to EVM to preserve semantics
	if adapter.evm.Config.MIRStrictNoFallback {
		return nil, fmt.Errorf("MIR strict mode: entry block produced no result")
	}
	log.Error("MIR fallback: entry block produced no result, using EVM interpreter", "addr", contract.Address())
	return adapter.evm.Interpreter().Run(contract, input, readOnly)
}

// setupExecutionEnvironment configures the MIR interpreter with contract-specific data
func (adapter *MIRInterpreterAdapter) setupExecutionEnvironment(contract *Contract, input []byte) {
	env := adapter.mirInterpreter.GetEnv()

	// Set calldata
	env.Calldata = input

	// Reset interpreter transient state to avoid per-call allocations
	// Reuse memory backing store by truncating length to zero
	if adapter.mirInterpreter != nil {
		// Reset memory view
		if adapter.mirInterpreter.MemoryCap() > 0 {
			adapter.mirInterpreter.TruncateMemory()
		}
		// Reset return data
		adapter.mirInterpreter.ResetReturnData()
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
	if adapter.warmSlots == nil {
		adapter.warmSlots = make(map[warmSlotKey]struct{})
	} else {
		for k := range adapter.warmSlots {
			delete(adapter.warmSlots, k)
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
	}

	// Set gas price from transaction context
	if adapter.evm.TxContext.GasPrice != nil {
		env.GasPrice = adapter.evm.TxContext.GasPrice.Uint64()
	}

	// Set call value for CALLVALUE op
	if contract != nil && contract.Value() != nil {
		// MIR will clone when reading
		env.CallValue = contract.Value()
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
	env.ExternalCall = func(kind byte, addr20 [20]byte, value *uint256.Int, callInput []byte) (ret []byte, success bool) {
		to := common.BytesToAddress(addr20[:])
		// Use computed callGasTemp (set during pre-op hook) and apply stipend if value transferred
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
			out, leftover, err = adapter.evm.Call(contract, to, callInput, gas, value)
		case 1: // CALLCODE
			out, leftover, err = adapter.evm.CallCode(contract, to, callInput, gas, value)
		case 2: // DELEGATECALL
			out, leftover, err = adapter.evm.DelegateCall(contract, to, callInput, gas)
		case 3: // STATICCALL
			out, leftover, err = adapter.evm.StaticCall(contract, to, callInput, gas)
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
		contract.UseGas(gas, adapter.evm.Config.Tracer, tracing.GasChangeCallContractCreation)
		var (
			out      []byte
			newAddr  common.Address
			leftover uint64
			err      error
		)
		if kind == 4 { // CREATE
			out, newAddr, leftover, err = adapter.evm.Create(contract, init, gas, value)
		} else { // CREATE2
			var saltU *uint256.Int
			if salt != nil {
				saltU = new(uint256.Int).SetBytes(salt[:])
			} else {
				saltU = uint256.NewInt(0)
			}
			out, newAddr, leftover, err = adapter.evm.Create2(contract, init, gas, value, saltU)
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
		return contract.isCode(pc)
	}
}

// CanRun checks if this adapter can run the given contract
func (adapter *MIRInterpreterAdapter) CanRun(contract *Contract) bool {
	return contract.HasMIRCode()
}
