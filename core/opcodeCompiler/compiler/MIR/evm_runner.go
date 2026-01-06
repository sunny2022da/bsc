package MIR

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/vm"
)

// EVMRunner adapts MIRInterpreter to the vm.ContractRunner interface so vm.EVM
// can dispatch top-level executions into MIR without importing the MIR package.
//
// This runner is intended for fullnode wiring:
// - Top-level tx Call/Create can use MIR.
// - Nested calls are delegated back into geth EVM via EVMCallCreateBackend.
type EVMRunner struct {
	evm *vm.EVM
}

func NewEVMRunner(evm *vm.EVM) *EVMRunner {
	return &EVMRunner{evm: evm}
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

	cfg := NewCFG(contract.CodeHash, contract.Code)
	if err := cfg.Parse(); err != nil {
		return nil, err
	}
	it := NewMIRInterpreter(cfg)
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
	it.SetStateBackend(NewStateDBBackend(r.evm.StateDB))
	it.SetCallCreateBackend(NewEVMCallCreateBackend(r.evm))

	res := it.Run()
	contract.Gas = res.GasLeft
	return res.ReturnData, res.Err
}
