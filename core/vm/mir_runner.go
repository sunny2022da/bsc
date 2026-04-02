package vm

// ContractRunner is an optional execution backend for running a Contract.
// It mirrors the signature of (*EVMInterpreter).Run so the EVM can dispatch
// to alternative engines (e.g. MIR) without importing them (avoids cycles).
//
// NOTE: The EVM is responsible for managing evm.depth when invoking a runner.
type ContractRunner interface {
	Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error)
}

// SetMIRRunner installs an optional MIR runner. When Config.EnableMIR is true,
// the EVM may dispatch top-level executions to this runner.
func (evm *EVM) SetMIRRunner(r ContractRunner) {
	if evm == nil {
		return
	}
	evm.mirRunner = r
}

// GetMIRRunner returns the installed MIR runner, or nil if none is set.
// Callers can type-assert the result to *mir.EVMRunner to access extended
// methods such as FellBack().
func (evm *EVM) GetMIRRunner() ContractRunner {
	if evm == nil {
		return nil
	}
	return evm.mirRunner
}
