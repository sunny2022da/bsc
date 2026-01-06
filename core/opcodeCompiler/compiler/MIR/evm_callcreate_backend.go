package MIR

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// EVMCallCreateBackend delegates CALL*/CREATE* execution to the real geth EVM.
// This is intended for fullnode wiring: MIR handles the caller-side gas accounting,
// then the backend executes the callee and returns leftover gas.
type EVMCallCreateBackend struct {
	evm *vm.EVM
}

func NewEVMCallCreateBackend(evm *vm.EVM) *EVMCallCreateBackend {
	return &EVMCallCreateBackend{evm: evm}
}

func (b *EVMCallCreateBackend) Call(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return b.evm.Call(caller, to, input, gas, value)
}

func (b *EVMCallCreateBackend) CallCode(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return b.evm.CallCode(caller, to, input, gas, value)
}

func (b *EVMCallCreateBackend) DelegateCall(originCaller, caller, codeAddr common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	// Matches geth instruction semantics: DelegateCall(originCaller, caller, addr(code), ...)
	return b.evm.DelegateCall(originCaller, caller, codeAddr, input, gas, value)
}

func (b *EVMCallCreateBackend) StaticCall(caller, to common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	return b.evm.StaticCall(caller, to, input, gas)
}

func (b *EVMCallCreateBackend) Create(caller common.Address, initCode []byte, gas uint64, value *uint256.Int) ([]byte, common.Address, uint64, error) {
	return b.evm.Create(caller, initCode, gas, value)
}

func (b *EVMCallCreateBackend) Create2(caller common.Address, initCode []byte, gas uint64, value *uint256.Int, salt *uint256.Int) ([]byte, common.Address, uint64, error) {
	return b.evm.Create2(caller, initCode, gas, value, salt)
}
