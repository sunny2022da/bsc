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
