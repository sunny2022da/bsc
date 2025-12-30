package vm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type stubRunner struct {
	ret []byte
	err error
}

func (s *stubRunner) Run(contract *Contract, input []byte, readOnly bool) ([]byte, error) {
	return s.ret, s.err
}

func newTestEVMWithCode(t *testing.T, addr common.Address, code []byte, cfg Config) (*EVM, *state.StateDB) {
	t.Helper()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(addr)
	statedb.SetCode(addr, code)
	statedb.Finalise(true)

	ctx := BlockContext{
		CanTransfer: func(StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(0),
		Time:        0,
		GasLimit:    30_000_000,
	}
	evm := NewEVM(ctx, statedb, params.TestChainConfig, cfg)
	return evm, statedb
}

func TestEVM_MIRRunner_DispatchesOnlyAtTopLevel(t *testing.T) {
	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000cc")

	// Contract code that returns 32 bytes [0x42, 0x00..] so we can detect base interpreter execution:
	// PUSH1 0x42; PUSH1 0; MSTORE8; PUSH1 0x20; PUSH1 0; RETURN
	baseReturnCode := []byte{
		0x60, 0x42,
		0x60, 0x00,
		0x53, // MSTORE8
		0x60, 0x20,
		0x60, 0x00,
		0xF3, // RETURN
	}

	evm, _ := newTestEVMWithCode(t, contractAddr, baseReturnCode, Config{EnableMIR: true})
	sr := &stubRunner{ret: []byte{0x99}}
	evm.SetMIRRunner(sr)

	// depth==0 => should dispatch to runner
	ret, left, err := evm.Call(common.Address{}, contractAddr, nil, 100000, new(uint256.Int))
	if err != nil {
		t.Fatalf("Call error: %v", err)
	}
	if left == 0 {
		t.Fatalf("expected non-zero leftover gas")
	}
	if len(ret) != 1 || ret[0] != 0x99 {
		t.Fatalf("expected runner returndata 0x99, got %x", ret)
	}

	// depth>0 => should NOT dispatch to runner; should run base interpreter instead.
	evm.depth = 1
	ret2, _, err2 := evm.Call(common.Address{}, contractAddr, nil, 100000, new(uint256.Int))
	if err2 != nil {
		t.Fatalf("Call(depth=1) error: %v", err2)
	}
	if len(ret2) != 32 || ret2[0] != 0x42 {
		t.Fatalf("expected base interpreter returndata starting with 0x42, got %x", ret2)
	}
}


