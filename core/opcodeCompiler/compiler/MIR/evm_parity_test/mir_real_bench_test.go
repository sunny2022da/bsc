package evm_parity_test

import (
	"math/big"
	"os"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var (
	benchSinkRet []byte
	benchSinkGas uint64
	benchSinkErr error
)

// Configure logger to emit warnings/errors to stdout during benchmarks so MIR fallback logs are visible.
func init() {
	lvl := ethlog.LevelCrit
	if os.Getenv("MIR_DEBUG") == "1" {
		lvl = ethlog.LevelWarn
	}
	h := ethlog.NewTerminalHandlerWithLevel(os.Stdout, lvl, false)
	ethlog.SetDefault(ethlog.NewLogger(h))
}

func BenchmarkMIRVsEVM_USDT(b *testing.B) {
	only := strings.ToUpper(os.Getenv("ONLY")) // "", "EVM", "MIR"
	code := loadHexFile(b, "../test_contact/usdt_runtime_code.hex")

	cfgBase := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	cfgMIR := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true},
	}

	zeroAddress := make([]byte, 32)
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
	}

	for _, m := range methods {
		input := append([]byte{}, m.selector...)
		for _, arg := range m.args {
			input = append(input, arg...)
		}

		if only != "MIR" {
			b.Run("EVM_Base_"+m.name, func(b *testing.B) {
				cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(cfgBase)
				addr := common.BytesToAddress([]byte("bench_usdt"))
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, code)
				// Warm-up to avoid counting one-time init work (e.g. jumpdest scanning) in the loop.
				benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, uint256.NewInt(0))
				goruntime.KeepAlive(benchSinkRet)
				goruntime.KeepAlive(benchSinkGas)
				goruntime.KeepAlive(benchSinkErr)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, uint256.NewInt(0))
				}
			})
		}

		if only != "EVM" {
			b.Run("MIR_"+m.name, func(b *testing.B) {
				cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(cfgMIR)
				addr := common.BytesToAddress([]byte("bench_usdt"))
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, code)
				// Warm-up to populate MIR CFG cache inside the runner (steady-state timing).
				benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, uint256.NewInt(0))
				goruntime.KeepAlive(benchSinkRet)
				goruntime.KeepAlive(benchSinkGas)
				goruntime.KeepAlive(benchSinkErr)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, uint256.NewInt(0))
				}
			})
		}
	}
}

func BenchmarkMIRVsEVM_WBNB(b *testing.B) {
	only := strings.ToUpper(os.Getenv("ONLY")) // "", "EVM", "MIR"

	// Derive runtime code from creation fixture.
	creation := loadHexFile(b, "../test_contact/wbnb_creation_code.txt")
	deployCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(15_000_000),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	code, _, _, err := runtime.Create(creation, deployCfg)
	if err != nil || len(code) == 0 {
		b.Fatalf("derive wbnb runtime via create: err=%v len=%d", err, len(code))
	}

	cfgBase := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	cfgMIR := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false, EnableMIR: true},
	}

	zeroAddress := make([]byte, 32)
	methods := []struct {
		name       string
		selector   []byte
		args       [][]byte
		callValue  *uint256.Int
		fundOrigin *uint256.Int
	}{
		{"name", []byte{0x06, 0xfd, 0xde, 0x03}, nil, uint256.NewInt(0), uint256.NewInt(0)},
		{"symbol", []byte{0x95, 0xd8, 0x9b, 0x41}, nil, uint256.NewInt(0), uint256.NewInt(0)},
		{"decimals", []byte{0x31, 0x3c, 0xe5, 0x67}, nil, uint256.NewInt(0), uint256.NewInt(0)},
		{"totalSupply", []byte{0x18, 0x16, 0x0d, 0xdd}, nil, uint256.NewInt(0), uint256.NewInt(0)},
		{"balanceOf", []byte{0x70, 0xa0, 0x82, 0x31}, [][]byte{zeroAddress}, uint256.NewInt(0), uint256.NewInt(0)},
		// Include one stateful path in the benchmark corpus (deposit) with a fixed msg.value.
		// IMPORTANT: fund the origin with a very large balance so the call doesn't fail-fast
		// on the CanTransfer check after the first iteration.
		{"deposit_1e18", []byte{0xd0, 0xe3, 0x0d, 0xb0}, nil,
			uint256.MustFromBig(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)), // msg.value = 1e18
			uint256.MustFromBig(new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)), // fundOrigin = 1e30
		},
	}

	for _, m := range methods {
		input := append([]byte{}, m.selector...)
		for _, arg := range m.args {
			input = append(input, arg...)
		}

		if only != "MIR" {
			b.Run("EVM_Base_"+m.name, func(b *testing.B) {
				cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(cfgBase)
				addr := common.BytesToAddress([]byte("bench_wbnb"))
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, code)
				if m.fundOrigin != nil && !m.fundOrigin.IsZero() {
					evm.StateDB.AddBalance(cfgBase.Origin, m.fundOrigin, tracing.BalanceIncreaseGenesisBalance)
				}
				benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, m.callValue)
				goruntime.KeepAlive(benchSinkRet)
				goruntime.KeepAlive(benchSinkGas)
				goruntime.KeepAlive(benchSinkErr)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, m.callValue)
				}
			})
		}

		if only != "EVM" {
			b.Run("MIR_"+m.name, func(b *testing.B) {
				cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
				evm := runtime.NewEnv(cfgMIR)
				addr := common.BytesToAddress([]byte("bench_wbnb"))
				evm.StateDB.CreateAccount(addr)
				evm.StateDB.SetCode(addr, code)
				if m.fundOrigin != nil && !m.fundOrigin.IsZero() {
					evm.StateDB.AddBalance(cfgMIR.Origin, m.fundOrigin, tracing.BalanceIncreaseGenesisBalance)
				}
				benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, m.callValue)
				goruntime.KeepAlive(benchSinkRet)
				goruntime.KeepAlive(benchSinkGas)
				goruntime.KeepAlive(benchSinkErr)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchSinkRet, benchSinkGas, benchSinkErr = evm.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, m.callValue)
				}
			})
		}
	}
}
