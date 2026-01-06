package evm_parity_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	MIR "github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler/MIR"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestDebug_USDT_Name_DirectMIR(t *testing.T) {
	code := loadHexFile(t, "../test_contact/usdt_runtime_code.hex")
	input := []byte{0x06, 0xfd, 0xde, 0x03}

	// Baseline geth EVM run (for comparison)
	var baseLastPC uint64
	var baseRetOffset, baseRetSize string
	baseCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			Tracer: &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, _ []byte, _ int, _ error) {
				baseLastPC = pc
				if pc == 429 && op == byte(vm.RETURN) {
					sd := scope.StackData()
					if len(sd) >= 2 {
						baseRetOffset = sd[len(sd)-1].String()
						baseRetSize = sd[len(sd)-2].String()
					}
				}
			}},
		},
	}
	baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	baseEnv := runtime.NewEnv(baseCfg)
	contractAddr := common.HexToAddress("0xc0de")
	baseEnv.StateDB.CreateAccount(contractAddr)
	baseEnv.StateDB.SetCode(contractAddr, code)
	baseRet, baseLeft, baseErr := baseEnv.Call(baseCfg.Origin, contractAddr, input, baseCfg.GasLimit, uint256.NewInt(0))
	t.Logf("BASE: err=%v lastPC=%d gasLeft=%d retLen=%d ret=%x (RETURN offset=%s size=%s)", baseErr, baseLastPC, baseLeft, len(baseRet), baseRet, baseRetOffset, baseRetSize)

	cfg := MIR.NewCFG(common.Hash{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("cfg parse: %v", err)
	}

	it := MIR.NewMIRInterpreter(cfg)
	it.SetGasLimit(10_000_000)
	it.SetChainConfig(params.BSCChainConfig, 1, false, 0)
	it.SetContractAddress(common.Address{})
	it.SetCallerAddress(common.Address{})
	it.SetOriginAddress(common.Address{})
	it.SetCallValue(uint256.NewInt(0))
	it.SetCallData(input)

	res := it.Run()
	t.Logf("halt=%s lastPC=%d err=%v gasUsed=%d gasLeft=%d retLen=%d ret=%x (RETURN offset=%d size=%d)", res.HaltOp.String(), res.LastEVMPC, res.Err, res.GasUsed, res.GasLeft, len(res.ReturnData), res.ReturnData, res.ReturnOffset, res.ReturnSize)
}
