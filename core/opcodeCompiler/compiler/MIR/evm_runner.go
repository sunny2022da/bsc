package MIR

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
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
	return r
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

	// Fork rules + block context
	bn := uint64(0)
	if r.evm.Context.BlockNumber != nil {
		bn = r.evm.Context.BlockNumber.Uint64()
	}
	it.SetChainConfig(r.evm.ChainConfig(), bn, r.evm.Context.Random != nil, r.evm.Context.Time)

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
