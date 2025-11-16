package runtime_test

import (
	"encoding/hex"
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

// BenchmarkMIRAsyncVsEVM_USDT benchmarks USDT contract with async CFG generation
// First call uses EVM fallback, subsequent calls use MIR (cached CFG)
func BenchmarkMIRAsyncVsEVM_USDT(b *testing.B) {
	// Decode USDT bytecode
	realCode, err := hex.DecodeString(usdtHex[2:])
	if err != nil {
		b.Fatalf("decode USDT hex: %v", err)
	}

	codeHash := crypto.Keccak256Hash(realCode)

	zeroAddress := make([]byte, 32)
	oneUint := make([]byte, 32)
	oneUint[31] = 1
	anotherAddress := make([]byte, 32)
	anotherAddress[31] = 0x01

	methods := []struct {
		name     string
		selector []byte
		args     [][]byte
	}{
		{"name", []byte{0x06, 0xfd, 0xde, 0x03}, nil},
		{"symbol", []byte{0x95, 0xd8, 0x9b, 0x41}, nil},
		{"decimals", []byte{0x31, 0x3c, 0xe5, 0x67}, nil},
		{"totalSupply", []byte{0x18, 0x16, 0x0d, 0xdd}, nil},
		{"balanceOf", []byte{0x70, 0xa0, 0x82, 0x31}, [][]byte{zeroAddress}},
		{"allowance", []byte{0x39, 0x50, 0x93, 0x51}, [][]byte{zeroAddress, zeroAddress}},
		{"approve", []byte{0x09, 0x5e, 0xa7, 0xb3}, [][]byte{zeroAddress, oneUint}},
		{"transfer", []byte{0xa9, 0x05, 0x9c, 0xbb}, [][]byte{zeroAddress, oneUint}},
		{"transferFrom", []byte{0x23, 0xb8, 0x72, 0xdd}, [][]byte{zeroAddress, anotherAddress, oneUint}},
	}

	// Use BSC chain config at/after London to enable SHR/SHL/SAR and other opcodes
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)

	// EVM baseline (no optimization)
	evmCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	// MIR with async CFG generation
	mirCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true},
	}
	compiler.EnableOpcodeParse()

	for _, m := range methods {
		input := append([]byte{}, m.selector...)
		for _, arg := range m.args {
			input = append(input, arg...)
		}

		b.Run("EVM_Base_"+m.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(evmCfg)
				addr := common.BytesToAddress([]byte("usdt_evm_" + m.name))
				sender := vm.AccountRef(evmCfg.Origin)
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, realCode)

				_, _, err := evm.Call(sender, addr, input, evmCfg.GasLimit, uint256.MustFromBig(evmCfg.Value))
				if err != nil {
					b.Fatalf("call failed: %v", err)
				}
			}
		})

		b.Run("MIR_FirstCall_EVMFallback_"+m.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Delete CFG cache to force first call scenario (async generation)
				compiler.DeleteMIRCFGCache(codeHash)

				mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(mirCfg)
				addr := common.BytesToAddress([]byte("usdt_mir_first_" + m.name))
				sender := vm.AccountRef(mirCfg.Origin)
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, realCode)

				// First call: CFG not cached, triggers async generation, uses EVM
				_, _, err := evm.Call(sender, addr, input, mirCfg.GasLimit, uint256.MustFromBig(mirCfg.Value))
				if err != nil {
					b.Fatalf("call failed: %v", err)
				}
			}
		})

		b.Run("MIR_CachedCall_MIRInterpreter_"+m.name, func(b *testing.B) {
			// Pre-generate CFG once to simulate cached scenario
			_, err := compiler.TryGenerateMIRCFG(codeHash, realCode)
			if err != nil {
				b.Fatalf("failed to pre-generate CFG: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(mirCfg)
				addr := common.BytesToAddress([]byte("usdt_mir_cached_" + m.name))
				sender := vm.AccountRef(mirCfg.Origin)
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, realCode)

				// Cached call: CFG ready, uses MIR interpreter
				_, _, err := evm.Call(sender, addr, input, mirCfg.GasLimit, uint256.MustFromBig(mirCfg.Value))
				if err != nil {
					b.Fatalf("call failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkMIRAsyncVsEVM_RealisticWorkload_RealContract simulates realistic production workload
// with real USDT contract where first call uses EVM (async CFG generation), subsequent calls use MIR (cached)
func BenchmarkMIRAsyncVsEVM_RealisticWorkload_RealContract(b *testing.B) {
	// Use USDT as representative real contract
	realCode, err := hex.DecodeString(usdtHex[2:])
	if err != nil {
		b.Fatalf("decode USDT hex: %v", err)
	}

	codeHash := crypto.Keccak256Hash(realCode)
	zeroAddress := make([]byte, 32)
	input := append([]byte{0x70, 0xa0, 0x82, 0x31}, zeroAddress...) // balanceOf

	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)

	evmCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}

	mirCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("EVM_AllCalls", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			evmCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(evmCfg)
			addr := common.BytesToAddress([]byte("realistic_evm"))
			sender := vm.AccountRef(evmCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, realCode)

			_, _, err := evm.Call(sender, addr, input, evmCfg.GasLimit, uint256.MustFromBig(evmCfg.Value))
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
			addr := common.BytesToAddress([]byte("realistic_mir"))
			sender := vm.AccountRef(mirCfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, realCode)

			// First iteration: EVM fallback (CFG not cached, async generation triggered)
			// Subsequent iterations: MIR interpreter (CFG cached from async generation)
			_, _, err := evm.Call(sender, addr, input, mirCfg.GasLimit, uint256.MustFromBig(mirCfg.Value))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}
