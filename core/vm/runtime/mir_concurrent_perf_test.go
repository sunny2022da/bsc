package runtime_test

import (
	"math/big"
	"testing"
	"time"

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

// BenchmarkMIRConcurrent_FirstCall benchmarks the first call scenario where
// CFG is not cached, triggers async generation, and falls back to EVM
func BenchmarkMIRConcurrent_FirstCall(b *testing.B) {
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

	cfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Delete CFG cache to simulate first call
		codeHash := crypto.Keccak256Hash(code)
		compiler.DeleteMIRCFGCache(codeHash)

		// Create fresh state for each iteration
		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evm := runtime.NewEnv(cfg)
		addr := common.BytesToAddress([]byte("bench_first"))
		sender := vm.AccountRef(cfg.Origin)
		evm.StateDB.CreateAccount(addr)
		evm.StateDB.SetCode(addr, code)

		// First call: CFG not cached, triggers async generation, uses EVM
		start := time.Now()
		_, _, err := evm.Call(sender, addr, nil, cfg.GasLimit, uint256.NewInt(0))
		duration := time.Since(start)

		if err != nil {
			b.Fatalf("call failed: %v", err)
		}

		// Record timing (this simulates first call latency)
		b.ReportMetric(float64(duration.Nanoseconds())/float64(1), "ns/first_call")
	}
}

// BenchmarkMIRConcurrent_CachedCall benchmarks subsequent calls where
// CFG is already cached and MIR interpreter is used
func BenchmarkMIRConcurrent_CachedCall(b *testing.B) {
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

	cfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	// Pre-generate CFG to simulate cached scenario
	codeHash := crypto.Keccak256Hash(code)
	_, err := compiler.TryGenerateMIRCFG(codeHash, code)
	if err != nil {
		b.Fatalf("failed to pre-generate CFG: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create fresh state for each iteration
		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evm := runtime.NewEnv(cfg)
		addr := common.BytesToAddress([]byte("bench_cached"))
		sender := vm.AccountRef(cfg.Origin)
		evm.StateDB.CreateAccount(addr)
		evm.StateDB.SetCode(addr, code)

		// Cached call: CFG ready, uses MIR interpreter
		_, _, err := evm.Call(sender, addr, nil, cfg.GasLimit, uint256.NewInt(0))
		if err != nil {
			b.Fatalf("call failed: %v", err)
		}
	}
}

// BenchmarkMIRConcurrent_RealContract benchmarks with a real contract (USDT-like)
// First call vs cached call performance
func BenchmarkMIRConcurrent_RealContract(b *testing.B) {
	// Simple contract: return a value
	code := []byte{
		byte(compiler.PUSH1), 0x01,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.MSTORE),
		byte(compiler.PUSH1), 0x20,
		byte(compiler.PUSH1), 0x00,
		byte(compiler.RETURN),
	}

	cfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	b.Run("FirstCall_EVM", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Delete CFG cache to force EVM fallback
			codeHash := crypto.Keccak256Hash(code)
			compiler.DeleteMIRCFGCache(codeHash)

			cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(cfg)
			addr := common.BytesToAddress([]byte("bench_real_first"))
			sender := vm.AccountRef(cfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, cfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})

	b.Run("CachedCall_MIR", func(b *testing.B) {
		// Pre-generate CFG
		codeHash := crypto.Keccak256Hash(code)
		_, err := compiler.TryGenerateMIRCFG(codeHash, code)
		if err != nil {
			b.Fatalf("failed to pre-generate CFG: %v", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
			evm := runtime.NewEnv(cfg)
			addr := common.BytesToAddress([]byte("bench_real_cached"))
			sender := vm.AccountRef(cfg.Origin)
			evm.StateDB.CreateAccount(addr)
			evm.StateDB.SetCode(addr, code)

			_, _, err := evm.Call(sender, addr, nil, cfg.GasLimit, uint256.NewInt(0))
			if err != nil {
				b.Fatalf("call failed: %v", err)
			}
		}
	})
}

// BenchmarkMIRConcurrent_AsyncGeneration measures the time to trigger
// async CFG generation (non-blocking)
func BenchmarkMIRConcurrent_AsyncGeneration(b *testing.B) {
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

	compiler.EnableOpcodeParse()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		codeHash := crypto.Keccak256Hash(code)
		compiler.DeleteMIRCFGCache(codeHash)

		// Measure time to trigger async generation (should be very fast, non-blocking)
		start := time.Now()
		compiler.GenOrLoadMIRCFG(codeHash, code)
		duration := time.Since(start)

		b.ReportMetric(float64(duration.Nanoseconds())/float64(1), "ns/async_trigger")
	}
}

// BenchmarkMIRConcurrent_SyncGeneration measures synchronous CFG generation
// for comparison with async generation
func BenchmarkMIRConcurrent_SyncGeneration(b *testing.B) {
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

	compiler.EnableOpcodeParse()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		codeHash := crypto.Keccak256Hash(code)
		compiler.DeleteMIRCFGCache(codeHash)

		// Measure time for synchronous generation (blocking)
		start := time.Now()
		_, err := compiler.TryGenerateMIRCFG(codeHash, code)
		duration := time.Since(start)

		if err != nil {
			b.Fatalf("generation failed: %v", err)
		}

		b.ReportMetric(float64(duration.Nanoseconds())/float64(1), "ns/sync_gen")
	}
}

// BenchmarkMIRConcurrent_MixedWorkload simulates a mixed workload where
// some contracts have cached CFG and some don't
func BenchmarkMIRConcurrent_MixedWorkload(b *testing.B) {
	codes := [][]byte{
		{byte(compiler.PUSH1), 0x01, byte(compiler.PUSH1), 0x02, byte(compiler.ADD), byte(compiler.RETURN)},
		{byte(compiler.PUSH1), 0x03, byte(compiler.PUSH1), 0x04, byte(compiler.MUL), byte(compiler.RETURN)},
		{byte(compiler.PUSH1), 0x05, byte(compiler.PUSH1), 0x06, byte(compiler.ADD), byte(compiler.RETURN)},
	}

	cfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true},
	}
	compiler.EnableOpcodeParse()

	// Pre-generate CFG for first contract only
	codeHash0 := crypto.Keccak256Hash(codes[0])
	_, err := compiler.TryGenerateMIRCFG(codeHash0, codes[0])
	if err != nil {
		b.Fatalf("failed to pre-generate CFG: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		codeIdx := i % len(codes)
		code := codes[codeIdx]
		codeHash := crypto.Keccak256Hash(code)

		// First contract has cached CFG, others don't
		if codeIdx != 0 {
			compiler.DeleteMIRCFGCache(codeHash)
		}

		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evm := runtime.NewEnv(cfg)
		addr := common.BytesToAddress([]byte{byte(codeIdx)})
		sender := vm.AccountRef(cfg.Origin)
		evm.StateDB.CreateAccount(addr)
		evm.StateDB.SetCode(addr, code)

		_, _, err := evm.Call(sender, addr, nil, cfg.GasLimit, uint256.NewInt(0))
		if err != nil {
			b.Fatalf("call failed: %v", err)
		}
	}
}
