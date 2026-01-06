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

func TestDebug_WBNB_Decimals_OpcodeCounts(t *testing.T) {
	creation := loadHexFile(t, "../test_contact/wbnb_creation_code.txt")
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
		t.Fatalf("derive wbnb runtime via create: err=%v len=%d", err, len(code))
	}

	input := []byte{0x31, 0x3c, 0xe5, 0x67} // decimals()
	addr := common.HexToAddress("0xc0de")

	// Base opcode counts
	baseCounts := map[byte]uint64{}
	baseCfg := &runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(15_000_000),
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			Tracer: &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, _ tracing.OpContext, _ []byte, _ int, _ error) {
				_ = pc
				baseCounts[op]++
			}},
		},
	}
	baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	baseEnv := runtime.NewEnv(baseCfg)
	baseEnv.StateDB.CreateAccount(addr)
	baseEnv.StateDB.SetCode(addr, code)
	_, baseLeft, baseErr := baseEnv.Call(baseCfg.Origin, addr, input, baseCfg.GasLimit, uint256.NewInt(0))
	if baseErr != nil {
		t.Fatalf("base err: %v", baseErr)
	}

	// MIR opcode counts (MIR-executed MIR instructions only; stack ops are charged via block counts)
	cfg := MIR.NewCFG(common.Hash{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("cfg parse: %v", err)
	}
	it := MIR.NewMIRInterpreter(cfg)
	it.SetGasLimit(10_000_000)
	it.SetChainConfig(params.MainnetChainConfig, 15_000_000, false, 0)
	it.SetContractAddress(addr)
	it.SetCallerAddress(baseCfg.Origin)
	it.SetOriginAddress(baseCfg.Origin)
	it.SetCallValue(uint256.NewInt(0))
	it.SetCallData(input)

	mirStepCounts := map[byte]uint64{}
	it.SetStepHook(func(evmPC uint, evmOp byte, op MIR.MirOperation) {
		_ = evmPC
		_ = op
		if evmOp != 0 {
			mirStepCounts[evmOp]++
		}
	})
	res := it.Run()
	if res.Err != nil {
		t.Fatalf("mir err: %v", res.Err)
	}
	mirLeft := res.GasLeft

	t.Logf("gasLeft base=%d mir=%d delta(mir-base)=%d", baseLeft, mirLeft, int64(mirLeft)-int64(baseLeft))
	t.Logf("base JUMPI(0x57) count=%d", baseCounts[0x57])
	t.Logf("mir  JUMPI(0x57) count=%d", mirStepCounts[0x57])
	t.Logf("base EXP(0x0a) count=%d", baseCounts[0x0a])
}

func TestDebug_WBNB_Deposit_SloadCount(t *testing.T) {
	creation := loadHexFile(t, "../test_contact/wbnb_creation_code.txt")
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
		t.Fatalf("derive wbnb runtime via create: err=%v len=%d", err, len(code))
	}

	// Match TestMIRParity_WBNB address choice for the base env
	addr := common.BytesToAddress([]byte("contract_wbnb_base"))
	depositSel := []byte{0xd0, 0xe3, 0x0d, 0xb0}
	val := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	baseCounts := map[byte]uint64{}
	baseCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: new(big.Int).Set(params.BSCChainConfig.LondonBlock),
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			Tracer: &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, _ tracing.OpContext, _ []byte, _ int, _ error) {
				_ = pc
				baseCounts[op]++
			}},
		},
	}
	baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	baseEnv := runtime.NewEnv(baseCfg)
	baseEnv.StateDB.CreateAccount(addr)
	baseEnv.StateDB.SetCode(addr, code)
	baseEnv.StateDB.AddBalance(baseCfg.Origin, uint256.MustFromBig(val), tracing.BalanceIncreaseGenesisBalance)
	_, baseLeft, baseErr := baseEnv.Call(baseCfg.Origin, addr, depositSel, baseCfg.GasLimit, uint256.MustFromBig(val))
	if baseErr != nil {
		t.Fatalf("base err: %v", baseErr)
	}

	// Also print the jump-table constant gas for SLOAD under these rules.
	rules := params.BSCChainConfig.Rules(new(big.Int).Set(params.BSCChainConfig.LondonBlock), false, 0)
	sloadConst, ok := vm.ConstantGasForOp(rules, vm.SLOAD)
	if !ok {
		t.Fatalf("no constant gas for SLOAD")
	}
	expConst, ok := vm.ConstantGasForOp(rules, vm.EXP)
	if !ok {
		t.Fatalf("no constant gas for EXP")
	}

	t.Logf("base gasLeft=%d SLOAD(0x54) count=%d constantGas(SLOAD)=%d constantGas(EXP)=%d", baseLeft, baseCounts[0x54], sloadConst, expConst)
}
