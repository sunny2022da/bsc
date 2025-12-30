package MIR

import (
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func runGethEVMCall(t *testing.T, code []byte, gasLimit uint64) (gasUsed uint64, ret []byte, err error) {
	t.Helper()
	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, code)
	statedb.Finalise(true)

	vmctx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(0),
		Time:        0,
		GasLimit:    math.MaxUint64,
	}
	evm := vm.NewEVM(vmctx, statedb, params.TestChainConfig, vm.Config{})
	ret, left, err := evm.Call(common.Address{}, contractAddr, nil, gasLimit, new(uint256.Int))
	return gasLimit - left, ret, err
}

func runMIR(t *testing.T, code []byte, gasLimit uint64) (gasUsed uint64, ret []byte, err error) {
	t.Helper()
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		return 0, nil, err
	}
	it := NewMIRInterpreter(cfg)
	it.SetGasLimit(gasLimit)
	it.SetChainConfig(params.TestChainConfig, 0, false, 0)
	res := it.Run()
	return res.GasUsed, res.ReturnData, res.Err
}

func TestParity_GasUsed_SimplePrograms(t *testing.T) {
	cases := []struct {
		name    string
		codeHex string
		gas     uint64
	}{
		// PUSH1 1; PUSH1 2; ADD; STOP
		{"add_stop", "600160020100", 100000},
		// PUSH1 1; PUSH1 0x40; MSTORE; STOP
		{"mstore_memexp", "600160405200", 100000},
		// PUSH1 0; PUSH1 0x20; KECCAK256; STOP
		{"keccak_memexp", "600060202000", 100000},
		// PUSH1 0xbb (topic2); PUSH1 0xaa (topic1); PUSH1 0 (size); PUSH1 0 (offset); LOG2; STOP
		// Regression: LOG base/topic gas must come ONLY from constant gas tables (no double-charge in MIR dynamic gas).
		{"log2_size0_topics_only", "60bb60aa60006000a200", 100000},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			code, err := hex.DecodeString(tt.codeHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			gGas, gRet, gErr := runGethEVMCall(t, code, tt.gas)
			mGas, mRet, mErr := runMIR(t, code, tt.gas)
			if (gErr == nil) != (mErr == nil) {
				t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
			}
			// For these programs, returndata should be empty.
			if len(gRet) != len(mRet) {
				t.Fatalf("ret mismatch: geth=%x mir=%x", gRet, mRet)
			}
			if gGas != mGas {
				t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
			}
		})
	}
}


