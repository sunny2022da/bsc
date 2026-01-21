package evm_parity_test

import (
	"math"
	"math/big"
	goruntime "runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	evmruntime "github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

const (
	// perfGateIters is the number of iterations used for each measurement sample.
	// This is a compromise between noise reduction and test runtime.
	perfGateIters = 5_000
	// perfGateMaxSlowdown is the allowed slowdown fraction for MIR vs base EVM.
	// User requirement: MIR must not be slower than native EVM => 0.
	perfGateMaxSlowdown = 0.0
)

func measureNsPerOp(iters int, fn func()) float64 {
	// Try to reduce run-to-run noise.
	goruntime.GC()
	oldGC := debug.SetGCPercent(-1)
	start := time.Now()
	for i := 0; i < iters; i++ {
		fn()
	}
	d := time.Since(start)
	debug.SetGCPercent(oldGC)
	return float64(d.Nanoseconds()) / float64(iters)
}

func gateCompareT(t *testing.T, label string, baseNs, mirNs float64, maxSlowdown float64) {
	if baseNs <= 0 || mirNs <= 0 {
		t.Fatalf("perf gate %s: invalid measurements base=%.2fns/op mir=%.2fns/op", label, baseNs, mirNs)
	}
	limit := baseNs * (1.0 + maxSlowdown)
	if mirNs > limit {
		t.Fatalf("perf gate %s FAILED: MIR slower than base EVM (mir=%.2fns/op base=%.2fns/op maxSlowdown=%.2f%%)",
			label, mirNs, baseNs, maxSlowdown*100.0)
	}
}

// TestPerfGate_MIRNotSlowerThanEVM_USDT fails if MIR is slower than base EVM for the USDT corpus.
func TestPerfGate_MIRNotSlowerThanEVM_USDT(t *testing.T) {
	code := loadHexFile(t, "../test_contact/usdt_runtime_code.hex")

	cfgBase := &evmruntime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	cfgMIR := &evmruntime.Config{
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

	var sumBase, sumMIR float64
	for _, m := range methods {
		input := append([]byte{}, m.selector...)
		for _, arg := range m.args {
			input = append(input, arg...)
		}

		// Base env
		cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evmBase := evmruntime.NewEnv(cfgBase)
		addr := common.BytesToAddress([]byte("gate_usdt"))
		evmBase.StateDB.CreateAccount(addr)
		evmBase.StateDB.SetCode(addr, code)
		callBase := func() {
			benchSinkRet, benchSinkGas, benchSinkErr = evmBase.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, uint256.NewInt(0))
		}
		// Warm-up
		callBase()

		// MIR env
		cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evmMIR := evmruntime.NewEnv(cfgMIR)
		evmMIR.StateDB.CreateAccount(addr)
		evmMIR.StateDB.SetCode(addr, code)
		callMIR := func() {
			benchSinkRet, benchSinkGas, benchSinkErr = evmMIR.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, uint256.NewInt(0))
		}
		// Warm-up (CFG/cache population)
		callMIR()

		goruntime.KeepAlive(benchSinkRet)
		goruntime.KeepAlive(benchSinkGas)
		goruntime.KeepAlive(benchSinkErr)

		// Measure (take best-of-3 to reduce noise)
		bestBase := math.Inf(1)
		bestMIR := math.Inf(1)
		for k := 0; k < 3; k++ {
			bestBase = math.Min(bestBase, measureNsPerOp(perfGateIters, callBase))
			bestMIR = math.Min(bestMIR, measureNsPerOp(perfGateIters, callMIR))
		}
		t.Logf("USDT/%s base=%.2fns/op mir=%.2fns/op", m.name, bestBase, bestMIR)
		sumBase += bestBase
		sumMIR += bestMIR
	}
	// User requirement: average perf for MIR can't be slower than native EVM.
	gateCompareT(t, "USDT/avg", sumBase, sumMIR, perfGateMaxSlowdown)
}

// TestPerfGate_MIRNotSlowerThanEVM_WBNB fails if MIR is slower than base EVM for the WBNB corpus.
func TestPerfGate_MIRNotSlowerThanEVM_WBNB(t *testing.T) {
	creation := loadHexFile(t, "../test_contact/wbnb_creation_code.txt")
	deployCfg := &evmruntime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(15_000_000),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	code, _, _, err := evmruntime.Create(creation, deployCfg)
	if err != nil || len(code) == 0 {
		t.Fatalf("derive wbnb runtime via create: err=%v len=%d", err, len(code))
	}

	cfgBase := &evmruntime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	cfgMIR := &evmruntime.Config{
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
		{"deposit_1e18", []byte{0xd0, 0xe3, 0x0d, 0xb0}, nil,
			uint256.MustFromBig(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)),
			uint256.MustFromBig(new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)),
		},
	}

	var sumBase, sumMIR float64
	for _, m := range methods {
		input := append([]byte{}, m.selector...)
		for _, arg := range m.args {
			input = append(input, arg...)
		}

		cfgBase.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evmBase := evmruntime.NewEnv(cfgBase)
		addr := common.BytesToAddress([]byte("gate_wbnb"))
		evmBase.StateDB.CreateAccount(addr)
		evmBase.StateDB.SetCode(addr, code)
		if m.fundOrigin != nil && !m.fundOrigin.IsZero() {
			evmBase.StateDB.AddBalance(cfgBase.Origin, m.fundOrigin, tracing.BalanceIncreaseGenesisBalance)
		}
		callBase := func() {
			benchSinkRet, benchSinkGas, benchSinkErr = evmBase.Call(cfgBase.Origin, addr, input, cfgBase.GasLimit, m.callValue)
		}
		callBase()

		cfgMIR.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		evmMIR := evmruntime.NewEnv(cfgMIR)
		evmMIR.StateDB.CreateAccount(addr)
		evmMIR.StateDB.SetCode(addr, code)
		if m.fundOrigin != nil && !m.fundOrigin.IsZero() {
			evmMIR.StateDB.AddBalance(cfgMIR.Origin, m.fundOrigin, tracing.BalanceIncreaseGenesisBalance)
		}
		callMIR := func() {
			benchSinkRet, benchSinkGas, benchSinkErr = evmMIR.Call(cfgMIR.Origin, addr, input, cfgMIR.GasLimit, m.callValue)
		}
		callMIR()

		goruntime.KeepAlive(benchSinkRet)
		goruntime.KeepAlive(benchSinkGas)
		goruntime.KeepAlive(benchSinkErr)

		bestBase := math.Inf(1)
		bestMIR := math.Inf(1)
		for k := 0; k < 3; k++ {
			bestBase = math.Min(bestBase, measureNsPerOp(perfGateIters, callBase))
			bestMIR = math.Min(bestMIR, measureNsPerOp(perfGateIters, callMIR))
		}
		t.Logf("WBNB/%s base=%.2fns/op mir=%.2fns/op", m.name, bestBase, bestMIR)
		sumBase += bestBase
		sumMIR += bestMIR
	}
	gateCompareT(t, "WBNB/avg", sumBase, sumMIR, perfGateMaxSlowdown)
}
