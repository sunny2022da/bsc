//go:build mir_parity_legacy
// +build mir_parity_legacy

package evm_parity_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Simple arithmetic bytecode: PUSH1 1; PUSH1 2; ADD; PUSH1 3; MUL; STOP
var simpleAddMul = []byte{0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x03, 0x02, 0x00}

// Compute 1+2, then *3, then return the 32-byte value (9)
var addMulReturn = []byte{
	0x60, 0x01,
	0x60, 0x02,
	0x01,
	0x60, 0x03,
	0x02,
	// store at memory[0x00..0x20]
	0x60, 0x00,
	0x52,
	// return 32 bytes from 0x00
	0x60, 0x20,
	0x60, 0x00,
	0xf3,
}

// Storage write/read and return: SSTORE 0x00 <- 0x01; SLOAD 0x00; RETURN 32 bytes
var storageStoreLoadReturn = []byte{
	0x60, 0x00, // key
	0x60, 0x01, // value
	0x55,
	0x60, 0x00, // key
	0x54,
	0x60, 0x00, // offset
	0x52,
	0x60, 0x20, // size
	0x60, 0x00, // offset
	0xf3,
}

// Keccak over memory[0..32] with constant 0x2a; return the 32-byte hash
var keccakMemReturn = []byte{
	0x60, 0x2a, // value
	0x60, 0x00, // offset
	0x52,
	0x60, 0x20, // size
	0x60, 0x00, // offset
	0x20,
	0x60, 0x00, // store hash at 0
	0x52,
	0x60, 0x20,
	0x60, 0x00,
	0xf3,
}

// Copy calldata to memory, keccak it, return 32-byte hash
var calldataKeccakReturn = []byte{
	0x60, 0x00, // dest
	0x60, 0x00, // offset
	0x36,
	0x91, // SWAP2
	0x37,
	0x36,       // size
	0x60, 0x00, // offset
	0x20,
	0x60, 0x00, // store at 0
	0x52,
	0x60, 0x20,
	0x60, 0x00,
	0xf3,
}

func BenchmarkMIRVsEVM_AddMul(b *testing.B) {
	// Base EVM interpreter
	cfgBase := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
		},
	}

	// MIR path: enable opcode optimizations and MIR opcode parsing
	cfgMIR := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 true,
		},
	}

	b.Run("EVM_Base", func(b *testing.B) {
		// Fresh StateDB
		if cfgBase.State == nil {
			cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		// Build a proper env with State
		evm := runtime.NewEnv(cfgBase)
		address := common.BytesToAddress([]byte("contract"))
		sender := cfgBase.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, simpleAddMul)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Execute the contract
			_, _, err := evm.Call(sender, address, nil, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
			if err != nil {
				// ignore reverts; simple code should not revert
				continue
			}
		}
	})

	b.Run("MIR_Interpreter", func(b *testing.B) {
		// Ensure a fresh StateDB exists
		if cfgMIR.State == nil {
			cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		// Fresh env with optimizations enabled
		evm := runtime.NewEnv(cfgMIR)
		address := common.BytesToAddress([]byte("contract"))
		sender := cfgMIR.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, simpleAddMul)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
			if err != nil {
				continue
			}
		}
	})
}

func BenchmarkMIRVsEVM_AddMulReturn(b *testing.B) {
	// Base EVM interpreter
	cfgBase := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	// MIR path
	cfgMIR := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableMIR: true},
	}

	b.Run("EVM_Base_Return", func(b *testing.B) {
		if cfgBase.State == nil {
			cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgBase)
		address := common.BytesToAddress([]byte("contract"))
		sender := cfgBase.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, addMulReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
			if err != nil {
				b.Fatalf("base call err: %v", err)
			}
		}
	})

	b.Run("MIR_Interpreter_Return", func(b *testing.B) {
		if cfgMIR.State == nil {
			cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgMIR)
		address := common.BytesToAddress([]byte("contract"))
		sender := cfgMIR.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, addMulReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
			if err != nil {
				b.Fatalf("mir call err: %v", err)
			}
		}
	})
}

func BenchmarkMIRVsEVM_Storage(b *testing.B) {
	cfgBase := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{}}
	cfgMIR := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{EnableMIR: true}}

	b.Run("EVM_Base_Storage", func(b *testing.B) {
		if cfgBase.State == nil {
			cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgBase)
		address := common.BytesToAddress([]byte("contract_storage"))
		sender := cfgBase.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, storageStoreLoadReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
			if err != nil {
				b.Fatalf("base storage err: %v", err)
			}
		}
	})

	b.Run("MIR_Interpreter_Storage", func(b *testing.B) {
		if cfgMIR.State == nil {
			cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgMIR)
		address := common.BytesToAddress([]byte("contract_storage"))
		sender := cfgMIR.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, storageStoreLoadReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
			if err != nil {
				b.Fatalf("mir storage err: %v", err)
			}
		}
	})
}

func BenchmarkMIRVsEVM_Keccak(b *testing.B) {
	cfgBase := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{}}
	cfgMIR := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{EnableMIR: true}}

	b.Run("EVM_Base_Keccak", func(b *testing.B) {
		if cfgBase.State == nil {
			cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgBase)
		address := common.BytesToAddress([]byte("contract_keccak"))
		sender := cfgBase.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, keccakMemReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
			if err != nil {
				b.Fatalf("base keccak err: %v", err)
			}
		}
	})

	b.Run("MIR_Interpreter_Keccak", func(b *testing.B) {
		if cfgMIR.State == nil {
			cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgMIR)
		address := common.BytesToAddress([]byte("contract_keccak"))
		sender := cfgMIR.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, keccakMemReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, nil, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
			if err != nil {
				b.Fatalf("mir keccak err: %v", err)
			}
		}
	})
}

func BenchmarkMIRVsEVM_CalldataKeccak(b *testing.B) {
	cfgBase := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{}}
	cfgMIR := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{EnableMIR: true}}
	input := make([]byte, 96)
	for i := range input {
		input[i] = byte(i)
	}

	b.Run("EVM_Base_CalldataKeccak", func(b *testing.B) {
		if cfgBase.State == nil {
			cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgBase)
		address := common.BytesToAddress([]byte("contract_calldata"))
		sender := cfgBase.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, calldataKeccakReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, input, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
			if err != nil {
				b.Fatalf("base calldata err: %v", err)
			}
		}
	})

	b.Run("MIR_Interpreter_CalldataKeccak", func(b *testing.B) {
		if cfgMIR.State == nil {
			cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfgMIR)
		address := common.BytesToAddress([]byte("contract_calldata"))
		sender := cfgMIR.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, calldataKeccakReturn)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := evm.Call(sender, address, input, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
			if err != nil {
				b.Fatalf("mir calldata err: %v", err)
			}
		}
	})
}

func TestMIRVsEVM_Functional(t *testing.T) {
	// Base and MIR configs
	base := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{}}
	mir := &runtime.Config{ChainConfig: params.MainnetChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: big.NewInt(1), Value: big.NewInt(0), EVMConfig: vm.Config{EnableMIR: true}}

	// helper to run code and return output
	run := func(cfg *runtime.Config, code []byte, input []byte, addrLabel string) ([]byte, error) {
		if cfg.State == nil {
			cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		}
		evm := runtime.NewEnv(cfg)
		address := common.BytesToAddress([]byte(addrLabel))
		sender := cfg.Origin
		evm.StateDB.CreateAccount(address)
		evm.StateDB.SetCode(address, code)
		ret, _, err := evm.Call(sender, address, input, cfg.GasLimit, uint256.MustFromBig(cfg.Value))
		return ret, err
	}

	// cases: addMulReturn, storageStoreLoadReturn, keccakMemReturn, calldataKeccakReturn
	t.Run("addMulReturn", func(t *testing.T) {
		rb, err := run(base, addMulReturn, nil, "addr_am")
		if err != nil {
			t.Fatalf("base err: %v", err)
		}
		rm, err := run(mir, addMulReturn, nil, "addr_am")
		if err != nil {
			t.Fatalf("mir err: %v", err)
		}
		if string(rb) != string(rm) {
			t.Fatalf("mismatch: base %x mir %x", rb, rm)
		}
	})

	t.Run("storage", func(t *testing.T) {
		rb, err := run(base, storageStoreLoadReturn, nil, "addr_st")
		if err != nil {
			t.Fatalf("base err: %v", err)
		}
		rm, err := run(mir, storageStoreLoadReturn, nil, "addr_st")
		if err != nil {
			t.Fatalf("mir err: %v", err)
		}
		if string(rb) != string(rm) {
			t.Fatalf("mismatch: base %x mir %x", rb, rm)
		}
	})

	t.Run("keccak", func(t *testing.T) {
		rb, err := run(base, keccakMemReturn, nil, "addr_km")
		if err != nil {
			t.Fatalf("base err: %v", err)
		}
		rm, err := run(mir, keccakMemReturn, nil, "addr_km")
		if err != nil {
			t.Fatalf("mir err: %v", err)
		}
		if string(rb) != string(rm) {
			t.Fatalf("mismatch: base %x mir %x", rb, rm)
		}
	})

	t.Run("calldata_keccak", func(t *testing.T) {
		input := make([]byte, 96)
		for i := range input {
			input[i] = byte(i)
		}
		rb, err := run(base, calldataKeccakReturn, input, "addr_ck_b")
		if err != nil {
			t.Fatalf("base err: %v", err)
		}
		rm, err := run(mir, calldataKeccakReturn, input, "addr_ck_m")
		if err != nil {
			t.Fatalf("mir err: %v", err)
		}
		exp := crypto.Keccak256(input)
		if string(rb) != string(exp) || string(rm) != string(exp) {
			t.Fatalf("unexpected: base %x mir %x exp %x", rb, rm, exp)
		}
	})
}

func TestAddMulReturn_BaseAndMIR(t *testing.T) {
	// Base
	cfgBase := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	if cfgBase.State == nil {
		cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	evm := runtime.NewEnv(cfgBase)
	addr := common.BytesToAddress([]byte("contract"))
	sender := cfgBase.Origin
	evm.StateDB.CreateAccount(addr)
	evm.StateDB.SetCode(addr, addMulReturn)
	ret, _, err := evm.Call(sender, addr, nil, cfgBase.GasLimit, uint256.MustFromBig(cfgBase.Value))
	if err != nil {
		t.Fatalf("base call err: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("unexpected ret len %d", len(ret))
	}
	got := uint256.NewInt(0).SetBytes(ret)
	if !got.Eq(uint256.NewInt(9)) {
		t.Fatalf("base expected 9, got %s", got.String())
	}

	// MIR
	cfgMIR := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableMIR: true},
	}
	if cfgMIR.State == nil {
		cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	evm2 := runtime.NewEnv(cfgMIR)
	evm2.StateDB.CreateAccount(addr)
	evm2.StateDB.SetCode(addr, addMulReturn)
	ret2, _, err2 := evm2.Call(sender, addr, nil, cfgMIR.GasLimit, uint256.MustFromBig(cfgMIR.Value))
	if err2 != nil {
		t.Fatalf("mir call err: %v", err2)
	}
	if len(ret2) != 32 {
		t.Fatalf("unexpected ret len (mir) %d", len(ret2))
	}
	got2 := uint256.NewInt(0).SetBytes(ret2)
	if !got2.Eq(uint256.NewInt(9)) {
		t.Fatalf("mir expected 9, got %s", got2.String())
	}
}
