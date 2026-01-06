package MIR

import (
	"encoding/hex"
	"errors"
	"fmt"
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

func newStateDBWithContract(t *testing.T, code []byte) (*state.StateDB, common.Address) {
	t.Helper()
	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, code)
	statedb.Finalise(true)
	return statedb, contractAddr
}

func runGethEVMCallWithState(t *testing.T, statedb *state.StateDB, contractAddr common.Address, code []byte, gasLimit uint64) (gasUsed uint64, ret []byte, err error) {
	t.Helper()
	vmctx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(0),
		Time:        0,
		GasLimit:    math.MaxUint64,
	}
	evm := vm.NewEVM(vmctx, statedb, params.TestChainConfig, vm.Config{})
	_ = code // code is already installed in statedb at contractAddr
	ret, left, err := evm.Call(common.Address{}, contractAddr, nil, gasLimit, new(uint256.Int))
	return gasLimit - left, ret, err
}

func runMIRWithStateDB(t *testing.T, statedb *state.StateDB, contractAddr common.Address, code []byte, gasLimit uint64) (gasUsed uint64, ret []byte, err error) {
	t.Helper()
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		return 0, nil, err
	}
	it := NewMIRInterpreter(cfg)
	it.SetGasLimit(gasLimit)
	it.SetChainConfig(params.TestChainConfig, 0, false, 0)
	if !it.chainRules.IsEIP2929 {
		return 0, nil, fmt.Errorf("test expects EIP-2929 active under TestChainConfig, got rules=%+v", it.chainRules)
	}
	it.SetContractAddress(contractAddr)
	it.SetStateBackend(NewStateDBBackend(statedb))
	res := it.Run()
	return res.GasUsed, res.ReturnData, res.Err
}

func runMIRTopLevelViaEVMCallWithState(t *testing.T, statedb *state.StateDB, contractAddr common.Address, gasLimit uint64) (gasUsed uint64, ret []byte, err error) {
	t.Helper()
	vmctx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(0),
		Time:        0,
		GasLimit:    math.MaxUint64,
	}
	evm := vm.NewEVM(vmctx, statedb, params.TestChainConfig, vm.Config{EnableMIR: true})
	evm.SetMIRRunner(NewEVMRunner(evm))
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

func TestParity_Stateful_SStoreThenSLoad_ReturnsValue(t *testing.T) {
	// Program:
	// PUSH1 0x01; PUSH1 0x00; SSTORE
	// PUSH1 0x00; SLOAD
	// PUSH1 0x00; MSTORE
	// PUSH1 0x20; PUSH1 0x00; RETURN
	code := []byte{
		0x60, 0x01, 0x60, 0x00, 0x55,
		0x60, 0x00, 0x54,
		0x60, 0x00, 0x52,
		0x60, 0x20, 0x60, 0x00, 0xF3,
	}
	const gasLimit = 5_000_000

	stG, addr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	gGas, gRet, gErr := runGethEVMCallWithState(t, stG, addr, code, gasLimit)
	mGas, mRet, mErr := runMIRWithStateDB(t, stM, addr, code, gasLimit)

	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gErr != nil || mErr != nil {
		t.Fatalf("expected success, geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}
	if len(gRet) != 32 || len(mRet) != 32 {
		t.Fatalf("expected 32-byte returndata, geth=%d mir=%d", len(gRet), len(mRet))
	}
	if gRet[31] != 0x01 || mRet[31] != 0x01 {
		t.Fatalf("expected return value 1, geth=%x mir=%x", gRet, mRet)
	}
}

func TestParity_Stateful_RevertRevertsSStore(t *testing.T) {
	// Program:
	// PUSH1 0x01; PUSH1 0x00; SSTORE
	// PUSH1 0x00; PUSH1 0x00; REVERT
	code := []byte{
		0x60, 0x01, 0x60, 0x00, 0x55,
		0x60, 0x00, 0x60, 0x00, 0xFD,
	}
	const gasLimit = 5_000_000

	stG, addr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	gGas, _, gErr := runGethEVMCallWithState(t, stG, addr, code, gasLimit)
	mGas, _, mErr := runMIRWithStateDB(t, stM, addr, code, gasLimit)

	if gErr == nil || mErr == nil {
		t.Fatalf("expected revert error, geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}

	// Verify state reverted: slot0 should be zero after REVERT.
	var slot common.Hash
	gotG := stG.GetState(addr, slot)
	gotM := stM.GetState(addr, slot)
	if gotG != (common.Hash{}) {
		t.Fatalf("geth state not reverted, slot0=%x", gotG)
	}
	if gotM != (common.Hash{}) {
		t.Fatalf("mir state not reverted, slot0=%x", gotM)
	}
}

func TestParity_Stateful_SLoad_WarmCold_SameSlotTwice(t *testing.T) {
	// Program (Berlin+):
	// PUSH1 0x00; SLOAD; POP
	// PUSH1 0x00; SLOAD; STOP
	//
	// Expected: first SLOAD cold, second warm. Compare total gas used with geth.
	code := []byte{
		0x60, 0x00, 0x54, 0x50,
		0x60, 0x00, 0x54, 0x00,
	}
	const gasLimit = 5_000_000

	stG, addr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	gGas, _, gErr := runGethEVMCallWithState(t, stG, addr, code, gasLimit)
	mGas, _, mErr := runMIRWithStateDB(t, stM, addr, code, gasLimit)
	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}
}

func TestParity_Stateful_Balance_WarmCold_SameAddrTwice(t *testing.T) {
	// Program (Berlin+):
	// BALANCE(0x11..11); POP
	// BALANCE(0x11..11); STOP
	//
	// Expected: first BALANCE cold (constant warm + dynamic cold-warm), second warm (constant warm only).
	addr20 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	code := []byte{
		0x73, // PUSH20
	}
	code = append(code, addr20.Bytes()...)
	code = append(code,
		0x31, // BALANCE
		0x50, // POP
		0x73, // PUSH20
	)
	code = append(code, addr20.Bytes()...)
	code = append(code,
		0x31, // BALANCE
		0x00, // STOP
	)
	const gasLimit = 5_000_000

	stG, caddr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	// Make the target account exist with some balance (not strictly needed for BALANCE gas, but keeps semantics realistic)
	stG.CreateAccount(addr20)
	stM.CreateAccount(addr20)
	stG.SetBalance(addr20, uint256.NewInt(7), 0)
	stM.SetBalance(addr20, uint256.NewInt(7), 0)

	gGas, _, gErr := runGethEVMCallWithState(t, stG, caddr, code, gasLimit)
	mGas, _, mErr := runMIRWithStateDB(t, stM, caddr, code, gasLimit)
	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}
}

func TestParity_Stateful_LOG2_RecordsLogAndMatchesGas(t *testing.T) {
	// Program:
	// MSTORE8(0, 0x42)
	// LOG2(0, 1, topic1=0xaa, topic2=0xbb)
	// STOP
	//
	// Encoded:
	// PUSH1 0x42 PUSH1 0x00 MSTORE8
	// PUSH1 0xbb PUSH1 0xaa PUSH1 0x01 PUSH1 0x00 LOG2
	// STOP
	code := []byte{
		0x60, 0x42, 0x60, 0x00, 0x53,
		0x60, 0xbb, 0x60, 0xaa, 0x60, 0x01, 0x60, 0x00, 0xa2,
		0x00,
	}
	const gasLimit = 5_000_000

	stG, addr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	gGas, _, gErr := runGethEVMCallWithState(t, stG, addr, code, gasLimit)
	mGas, _, mErr := runMIRWithStateDB(t, stM, addr, code, gasLimit)
	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gErr != nil || mErr != nil {
		t.Fatalf("expected success, geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}
	// Semantics: both should have recorded exactly one log.
	if len(stG.Logs()) != 1 {
		t.Fatalf("geth expected 1 log, got %d", len(stG.Logs()))
	}
	if len(stM.Logs()) != 1 {
		t.Fatalf("mir expected 1 log, got %d", len(stM.Logs()))
	}
}

func TestParity_Stateful_EXTCODE_WarmCold_SameAddrTwice(t *testing.T) {
	// Program (Berlin+):
	// EXTCODESIZE(addr); POP
	// EXTCODEHASH(addr); POP
	// EXTCODESIZE(addr); POP
	// EXTCODEHASH(addr); STOP
	//
	// Expected: first access cold, subsequent warm; compare total gas with geth.
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	code := []byte{0x73}
	code = append(code, target.Bytes()...)
	code = append(code, 0x3b, 0x50) // EXTCODESIZE; POP
	code = append(code, 0x73)
	code = append(code, target.Bytes()...)
	code = append(code, 0x3f, 0x50) // EXTCODEHASH; POP
	code = append(code, 0x73)
	code = append(code, target.Bytes()...)
	code = append(code, 0x3b, 0x50) // EXTCODESIZE; POP
	code = append(code, 0x73)
	code = append(code, target.Bytes()...)
	code = append(code, 0x3f, 0x00) // EXTCODEHASH; STOP

	const gasLimit = 5_000_000
	stG, caddr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)
	// Install some code at target so EXTCODE* has something to read.
	stG.CreateAccount(target)
	stM.CreateAccount(target)
	stG.SetCode(target, []byte{0x60, 0x00, 0x00}) // PUSH1 0; STOP
	stM.SetCode(target, []byte{0x60, 0x00, 0x00})

	gGas, _, gErr := runGethEVMCallWithState(t, stG, caddr, code, gasLimit)
	mGas, _, mErr := runMIRWithStateDB(t, stM, caddr, code, gasLimit)
	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}
}

func TestParity_Stateful_RETURNDATACOPY_OutOfBoundsErrors(t *testing.T) {
	// Contract B: returns 1 byte (0x99).
	codeB := []byte{
		0x60, 0x99, 0x60, 0x00, 0x53, // MSTORE8(0,0x99)
		0x60, 0x01, 0x60, 0x00, 0xF3, // RETURN(0,1)
	}
	addrB := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	// Contract A (top-level, will run in MIR via EVM runner):
	// CALL(addrB) with outSize=0 so returnData is kept only in buffer, then:
	// RETURNDATACOPY(dest=0, off=0, size=2) -> out of bounds => ErrReturnDataOutOfBounds
	//
	// PUSH1 outSize=0
	// PUSH1 outOff=0
	// PUSH1 inSize=0
	// PUSH1 inOff=0
	// PUSH1 value=0
	// PUSH20 addrB
	// PUSH1 gas=0x64
	// CALL
	// POP (success flag)
	// PUSH1 size=2
	// PUSH1 off=0
	// PUSH1 dest=0
	// RETURNDATACOPY
	// STOP
	codeA := []byte{
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x73,
	}
	codeA = append(codeA, addrB.Bytes()...)
	codeA = append(codeA,
		0x60, 0x64,
		0xF1, // CALL
		0x50, // POP
		0x60, 0x02,
		0x60, 0x00,
		0x60, 0x00,
		0x3e, // RETURNDATACOPY
		0x00,
	)

	const gasLimit = 5_000_000
	stG, addrA := newStateDBWithContract(t, codeA)
	stM, _ := newStateDBWithContract(t, codeA)
	// Install callee B in both states
	stG.CreateAccount(addrB)
	stM.CreateAccount(addrB)
	stG.SetCode(addrB, codeB)
	stM.SetCode(addrB, codeB)

	// geth baseline: run A in geth interpreter
	gGas, _, gErr := runGethEVMCallWithState(t, stG, addrA, codeA, gasLimit)
	// MIR path: run A through vm.EVM with MIR enabled at depth 0 (nested CALL stays in geth)
	mGas, _, mErr := runMIRTopLevelViaEVMCallWithState(t, stM, addrA, gasLimit)

	if !errors.Is(gErr, vm.ErrReturnDataOutOfBounds) {
		t.Fatalf("geth expected ErrReturnDataOutOfBounds, got %v (mir=%v)", gErr, mErr)
	}
	if !errors.Is(mErr, vm.ErrReturnDataOutOfBounds) {
		t.Fatalf("mir expected ErrReturnDataOutOfBounds, got %v (geth=%v)", mErr, gErr)
	}
	// Both should be fatal and consume all gas
	if gGas != gasLimit || mGas != gasLimit {
		t.Fatalf("expected gasUsed==gasLimit, geth=%d mir=%d limit=%d", gGas, mGas, gasLimit)
	}
}

func TestParity_Stateful_SELFDESTRUCT_TransfersBalanceAndMatchesGas(t *testing.T) {
	// Program:
	// PUSH20 beneficiary; SELFDESTRUCT
	beneficiary := common.HexToAddress("0x9999999999999999999999999999999999999999")
	code := []byte{0x73}
	code = append(code, beneficiary.Bytes()...)
	code = append(code, 0xff) // SELFDESTRUCT

	const gasLimit = 5_000_000
	stG, addr := newStateDBWithContract(t, code)
	stM, _ := newStateDBWithContract(t, code)

	// Seed balance on the contract so transfer happens.
	stG.SetBalance(addr, uint256.NewInt(12345), 0)
	stM.SetBalance(addr, uint256.NewInt(12345), 0)
	stG.CreateAccount(beneficiary)
	stM.CreateAccount(beneficiary)

	gGas, _, gErr := runGethEVMCallWithState(t, stG, addr, code, gasLimit)
	mGas, _, mErr := runMIRTopLevelViaEVMCallWithState(t, stM, addr, gasLimit)
	if (gErr == nil) != (mErr == nil) {
		t.Fatalf("err mismatch: geth=%v mir=%v", gErr, mErr)
	}
	if gErr != nil || mErr != nil {
		t.Fatalf("expected success, geth=%v mir=%v", gErr, mErr)
	}
	if gGas != mGas {
		t.Fatalf("gas used mismatch: geth=%d mir=%d", gGas, mGas)
	}

	// Semantics: balances transferred and contract marked selfdestructed.
	if stG.HasSelfDestructed(addr) != stM.HasSelfDestructed(addr) {
		t.Fatalf("selfdestruct flag mismatch: geth=%v mir=%v", stG.HasSelfDestructed(addr), stM.HasSelfDestructed(addr))
	}
	if !stM.HasSelfDestructed(addr) {
		t.Fatalf("expected mir HasSelfDestructed=true")
	}
	if stG.GetBalance(addr).IsZero() != stM.GetBalance(addr).IsZero() {
		t.Fatalf("contract balance zero mismatch")
	}
	if !stM.GetBalance(addr).IsZero() {
		t.Fatalf("expected contract balance zero, got %s", stM.GetBalance(addr).String())
	}
	if stG.GetBalance(beneficiary).Cmp(stM.GetBalance(beneficiary)) != 0 {
		t.Fatalf("beneficiary balance mismatch: geth=%s mir=%s", stG.GetBalance(beneficiary).String(), stM.GetBalance(beneficiary).String())
	}
}
