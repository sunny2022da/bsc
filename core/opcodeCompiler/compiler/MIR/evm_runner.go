package MIR

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// EVMRunner adapts MIRInterpreter to the vm.ContractRunner interface so vm.EVM
// can dispatch top-level executions into MIR without importing the MIR package.
//
// This runner is intended for fullnode wiring:
// - Top-level tx Call/Create can use MIR.
// - Nested calls are delegated back into geth EVM via EVMCallCreateBackend.
type EVMRunner struct {
	evm *vm.EVM

	mu       sync.RWMutex
	cfgCache map[common.Hash]*CFG

	itPool sync.Pool

	stateBackend StateDBBackend
	callBackend  EVMCallCreateBackend

	// Cached per-EVM block context (constant for this EVM instance).
	blockNumber uint64
	chainRules  params.Rules

	// Optional per-step hook for MIR execution (used by tools/tests).
	mirStepHook func(evmPC uint, evmOp byte, op MirOperation)

	// Optional factory to build a step hook that can close over the interpreter instance
	// (e.g., to also sample gasUsed/gasLeft). If set, it takes precedence over mirStepHook.
	mirStepHookFactory func(it *MIRInterpreter) func(evmPC uint, evmOp byte, op MirOperation)
}

func NewEVMRunner(evm *vm.EVM) *EVMRunner {
	r := &EVMRunner{
		evm:      evm,
		cfgCache: make(map[common.Hash]*CFG),
	}
	// Pool interpreters to avoid per-call allocations (maps/slices). ResetForRun() clears state.
	r.itPool.New = func() any { return NewMIRInterpreter(nil) }
	r.stateBackend = StateDBBackend{db: evm.StateDB}
	r.callBackend = EVMCallCreateBackend{evm: evm}

	// Cache rules for this EVM instance once (avoid per-call big.Int allocs + rules derivation).
	bn := uint64(0)
	if evm != nil && evm.Context.BlockNumber != nil {
		bn = evm.Context.BlockNumber.Uint64()
	}
	r.blockNumber = bn
	if evm != nil && evm.ChainConfig() != nil {
		r.chainRules = evm.ChainConfig().Rules(new(big.Int).SetUint64(bn), evm.Context.Random != nil, evm.Context.Time)
	}
	return r
}

// SetMIRStepHook sets an optional hook called for each executed MIR instruction.
// Passing nil disables it. This is intended for diagnostics and should not be enabled in production.
func (r *EVMRunner) SetMIRStepHook(h func(evmPC uint, evmOp byte, op MirOperation)) {
	if r == nil {
		return
	}
	r.mirStepHook = h
}

// SetMIRStepHookFactory sets a hook factory that receives the per-run interpreter instance.
// Passing nil disables it.
func (r *EVMRunner) SetMIRStepHookFactory(f func(it *MIRInterpreter) func(evmPC uint, evmOp byte, op MirOperation)) {
	if r == nil {
		return
	}
	r.mirStepHookFactory = f
}

func (r *EVMRunner) Run(contract *vm.Contract, input []byte, readOnly bool) ([]byte, error) {
	if r == nil || r.evm == nil {
		return nil, fmt.Errorf("nil EVM runner")
	}
	if contract == nil {
		return nil, fmt.Errorf("nil contract")
	}
	// For now, only support non-readOnly execution for MIR top-level calls/creates.
	// Nested STATICCALL frames are executed by geth (depth>0), so this is mostly a guard.
	if readOnly {
		return nil, vm.ErrWriteProtection
	}

	codeHash := contract.CodeHash
	if (codeHash == common.Hash{}) {
		// Some call paths may not set CodeHash; derive it to make caching effective.
		codeHash = crypto.Keccak256Hash(contract.Code)
	}

	r.mu.RLock()
	cfg := r.cfgCache[codeHash]
	r.mu.RUnlock()

	if cfg == nil {
		built := NewCFG(codeHash, contract.Code)
		if err := built.Parse(); err != nil {
			return nil, err
		}
		r.mu.Lock()
		// Another goroutine may have populated it while we were building; keep the first.
		if existing := r.cfgCache[codeHash]; existing != nil {
			cfg = existing
		} else {
			r.cfgCache[codeHash] = built
			cfg = built
		}
		r.mu.Unlock()
	}

	it := r.itPool.Get().(*MIRInterpreter)
	it.ResetForRun(cfg)
	defer r.itPool.Put(it)
	it.SetGasLimit(contract.Gas)
	// IMPORTANT: Refund cap is applied by geth's state transition logic, not the runner.
	// If MIR applies it internally, it will incorrectly refund against post-intrinsic call gas.
	it.SetApplyRefundCapInFinish(false)
	// EVM.Call/Create already wraps execution in a StateDB snapshot; avoid duplicating that work here.
	it.SetManageStateSnapshots(false)
	// Ensure we don't leak a previous hook across pooled interpreter instances.
	if r.mirStepHookFactory != nil {
		it.SetStepHook(r.mirStepHookFactory(it))
	} else {
		it.SetStepHook(r.mirStepHook)
	}

	// Fork rules + block context (cached in runner)
	it.blockNumber = r.blockNumber
	it.SetChainRules(r.chainRules)
	// Block context for block-environment opcodes (NUMBER/TIMESTAMP/COINBASE/etc).
	if r.evm != nil {
		it.blockTime = r.evm.Context.Time
		it.blockCoinbase = r.evm.Context.Coinbase
		it.blockGasLimit = r.evm.Context.GasLimit
		it.blockDifficulty = r.evm.Context.Difficulty
		it.blockRandom = r.evm.Context.Random
		it.blockBaseFee = r.evm.Context.BaseFee
		it.blockBlobBaseFee = r.evm.Context.BlobBaseFee
		it.blockGetHash = r.evm.Context.GetHash
		it.txBlobHashes = r.evm.BlobHashes
	}

	// Call context
	it.SetContractAddress(contract.Address())
	it.SetCallerAddress(contract.Caller())
	it.SetOriginAddress(r.evm.Origin)
	it.SetCallValue(contract.Value())
	it.SetCallData(input)

	// Fullnode backends
	it.SetStateBackend(&r.stateBackend)
	it.SetCallCreateBackend(&r.callBackend)

	res := it.Run()
	contract.Gas = res.GasLeft
	return res.ReturnData, res.Err
}
