package MIR

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// CallCreateBackend is the execution hook for CALL*/CREATE* opcodes.
// In a fullnode, this should delegate into the real EVM/state transition layer.
//
// Gas semantics:
// - The MIRInterpreter charges the caller-side costs and determines the gas passed to the callee.
// - The backend should execute with the provided gas and return `returnGas` (unused gas) back to caller.
// - `returnGas` MUST NOT exceed the provided gas.
type CallCreateBackend interface {
	Call(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
	CallCode(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
	DelegateCall(caller, addr, to common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, returnGas uint64, err error)
	StaticCall(caller, to common.Address, input []byte, gas uint64) (ret []byte, returnGas uint64, err error)

	Create(caller common.Address, initCode []byte, gas uint64, value *uint256.Int) (ret []byte, addr common.Address, returnGas uint64, err error)
	Create2(caller common.Address, initCode []byte, gas uint64, value *uint256.Int, salt *uint256.Int) (ret []byte, addr common.Address, returnGas uint64, err error)
}

// NoopCallCreateBackend is a minimal stub used by default in tools/tests.
// It always succeeds, returns empty returndata, and refunds all provided gas.
type NoopCallCreateBackend struct{}

func (NoopCallCreateBackend) Call(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return nil, gas, nil
}
func (NoopCallCreateBackend) CallCode(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return nil, gas, nil
}
func (NoopCallCreateBackend) DelegateCall(caller, addr, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return nil, gas, nil
}
func (NoopCallCreateBackend) StaticCall(caller, to common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	return nil, gas, nil
}
func (NoopCallCreateBackend) Create(caller common.Address, initCode []byte, gas uint64, value *uint256.Int) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, nil
}
func (NoopCallCreateBackend) Create2(caller common.Address, initCode []byte, gas uint64, value *uint256.Int, salt *uint256.Int) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, nil
}


