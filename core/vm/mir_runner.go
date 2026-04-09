package vm

import "sync/atomic"

// MIR fallback reason counters. Declared in core/vm (not MIR package) to avoid
// circular imports. MIR's evm_runner.go increments them via vm.MIRFallback*.
var (
	MIRFallbackGasZero        atomic.Uint64
	MIRFallbackCFGParseFailed atomic.Uint64
	MIRFallbackRuntimeEpoch   atomic.Uint64
	MIRFallbackUnresolvedJump atomic.Uint64
)

// ContractRunner is an optional execution backend for running a Contract.
// It mirrors the signature of (*EVMInterpreter).Run so the EVM can dispatch
// to alternative engines (e.g. MIR) without importing them (avoids cycles).
//
// NOTE: The EVM is responsible for managing evm.depth when invoking a runner.
type ContractRunner interface {
	Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error)
	// FellBack reports whether the most recent Run() call fell back to the
	// base interpreter instead of executing natively.
	FellBack() bool
}

// SetMIRRunner installs an optional MIR runner. When Config.EnableMIR is true,
// the EVM may dispatch top-level executions to this runner.
func (evm *EVM) SetMIRRunner(r ContractRunner) {
	if evm == nil {
		return
	}
	evm.mirRunner = r
}

// IncDepth increments the EVM call depth. Used by MIR runner to mirror
// EVMInterpreter.Run() depth management from an external package.
func (evm *EVM) IncDepth() {
	if evm != nil {
		evm.depth++
	}
}

// DecDepth decrements the EVM call depth.
func (evm *EVM) DecDepth() {
	if evm != nil {
		evm.depth--
	}
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
