package evm_parity_test

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func loadHexFile(t testing.TB, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %s: %v", path, err)
	}
	return b
}

func newRuntimeCfg(t testing.TB, chainCfg *params.ChainConfig, blockNumber *big.Int, gasLimit uint64, enableMIR bool) *runtime.Config {
	t.Helper()
	cfg := &runtime.Config{
		ChainConfig: chainCfg,
		GasLimit:    gasLimit,
		Origin:      common.Address{},
		BlockNumber: blockNumber,
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 enableMIR,
		},
	}
	cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	return cfg
}

func installAndCall(t testing.TB, cfg *runtime.Config, addr common.Address, code []byte, input []byte, gas uint64, value *uint256.Int) (ret []byte, gasLeft uint64, err error) {
	t.Helper()
	env := runtime.NewEnv(cfg)
	env.StateDB.CreateAccount(addr)
	env.StateDB.SetCode(addr, code)
	if value == nil {
		value = uint256.NewInt(0)
	}
	return env.Call(cfg.Origin, addr, input, gas, value)
}
