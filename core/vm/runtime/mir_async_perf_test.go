package runtime_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// BenchmarkMIRAsyncVsEVM_SimpleContract compares MIR (with async CFG) vs EVM
// for a simple contract. First call uses EVM, subsequent calls use MIR.
func BenchmarkMIRAsyncVsEVM_SimpleContract(b *testing.B) {
	code := []byte{
		byte(compiler.PUSH1), 0x01,
		byte(compiler.PUSH1), 0x02,
		byte(compiler.ADD),
		byte(compiler.PUSH1), 0x03,
		byte(compiler.MUL),
		byte(compiler.PUSH1), 0x00,
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.RETURN),
	}

	codeHash := crypto.Keccak256Hash(code)

	// EVM baseline (no optimization)
	evmCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	// MIR with async CFG generation
	mirCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("EVM_Base", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(evmCfg)
			addr := common.BytesToAddress([]byte("evm_base"))
			sender := vm.AccountRef(evmCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, evmCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_FirstCall_EVMFallback", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Delete CFG cache to force first call scenario
			compiler.DeleteMIRCFGCache(codeHash)

			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_first"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			// First call: CFG not cached, triggers async generation, uses EVM
			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_CachedCall_MIRInterpreter", func(b *testing.B) {
		// Pre-generate CFG once to simulate cached scenario
		_, err := compiler.TryGenerateMIRCFG(codeHash, code)
		if err != nil {
			b.Fatalf("failed to pre-generate CFG: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_cached"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			// Cached call: CFG ready, uses MIR interpreter
			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}

// BenchmarkMIRAsyncVsEVM_StorageContract compares MIR vs EVM for storage operations
func BenchmarkMIRAsyncVsEVM_StorageContract(b *testing.B) {
	// Storage store and load contract
	code := []byte{
		byte(compiler.PUSH1), 0x01, // value
		byte(compiler.PUSH1), 0x00, // key
		byte(compiler.SSTORE),
		byte(compiler.PUSH1), 0x00, // key
		byte(compiler.SLOAD),
		byte(compiler.PUSH1), 0x00,
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.RETURN),
	}

	codeHash := crypto.Keccak256Hash(code)

	evmCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	mirCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("EVM_Base", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(evmCfg)
			addr := common.BytesToAddress([]byte("evm_storage"))
			sender := vm.AccountRef(evmCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, evmCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_FirstCall_EVMFallback", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			compiler.DeleteMIRCFGCache(codeHash)

			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_storage_first"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_CachedCall_MIRInterpreter", func(b *testing.B) {
		_, err := compiler.TryGenerateMIRCFG(codeHash, code)
		if err != nil {
			b.Fatalf("failed to pre-generate CFG: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_storage_cached"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}

// BenchmarkMIRAsyncVsEVM_KeccakContract compares MIR vs EVM for keccak operations
func BenchmarkMIRAsyncVsEVM_KeccakContract(b *testing.B) {
	code := []byte{
		byte(compiler.PUSH1), 0x2a, // value
		byte(compiler.PUSH1), 0x00, // offset
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20, // size
		byte(compiler.PUSH1), 0x00, // offset
		byte(compiler.KECCAK256),
		byte(compiler.PUSH1), 0x00,
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.RETURN),
	}

	codeHash := crypto.Keccak256Hash(code)

	evmCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	mirCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("EVM_Base", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(evmCfg)
			addr := common.BytesToAddress([]byte("evm_keccak"))
			sender := vm.AccountRef(evmCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, evmCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_FirstCall_EVMFallback", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			compiler.DeleteMIRCFGCache(codeHash)

			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_keccak_first"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_CachedCall_MIRInterpreter", func(b *testing.B) {
		_, err := compiler.TryGenerateMIRCFG(codeHash, code)
		if err != nil {
			b.Fatalf("failed to pre-generate CFG: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_keccak_cached"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}

// BenchmarkMIRAsyncVsEVM_RealisticWorkload simulates realistic workload where
// first call uses EVM (async CFG generation), subsequent calls use MIR (cached)
func BenchmarkMIRAsyncVsEVM_RealisticWorkload(b *testing.B) {
	code := []byte{
		byte(compiler.PUSH1), 0x01,
		byte(compiler.PUSH1), 0x02,
		byte(compiler.ADD),
		byte(compiler.PUSH1), 0x03,
		byte(compiler.MUL),
		byte(compiler.PUSH1), 0x00,
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.RETURN),
	}

	codeHash := crypto.Keccak256Hash(code)

	evmCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	mirCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("EVM_AllCalls", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(evmCfg)
			addr := common.BytesToAddress([]byte("evm_all"))
			sender := vm.AccountRef(evmCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, evmCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("MIR_Realistic_FirstEVMThenMIR", func(b *testing.B) {
		// Delete cache to start fresh
		compiler.DeleteMIRCFGCache(codeHash)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(mirCfg)
			addr := common.BytesToAddress([]byte("mir_realistic"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			// First iteration: EVM fallback (CFG not cached)
			// Subsequent iterations: MIR interpreter (CFG cached from async generation)
			_, _, err := evm.Call(sender, addr, nil, mirCfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}
