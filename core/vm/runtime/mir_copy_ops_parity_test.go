package runtime_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// makeCodeCalldatacopy generates bytecode that:
// - optionally expands memory to 32 bytes via MSTORE
// - copies 'ln' bytes from calldata (offset 0) into memory at dst=0 via CALLDATACOPY
// - returns 32 bytes from memory at offset 0
func makeCodeCalldatacopy(ln int, preExpand bool) []byte {
	// Opcodes:
	// if preExpand: PUSH32 <0> PUSH1 0 MSTORE
	// PUSH <ln> PUSH1 0 PUSH1 0 CALLDATACOPY
	// PUSH1 0x20 PUSH1 0 RETURN
	code := []byte{}
	if preExpand {
		// PUSH32 0
		code = append(code, 0x7f)
		code = append(code, make([]byte, 32)...)
		// PUSH1 0
		code = append(code, 0x60, 0x00)
		// MSTORE
		code = append(code, 0x52)
	}
	// PUSH ln
	if ln <= 0xff {
		code = append(code, 0x60, byte(ln))
	} else {
		// support up to PUSH2 for convenience
		code = append(code, 0x61, byte(ln>>8), byte(ln))
	}
	// PUSH1 0 (data offset)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (dst)
	code = append(code, 0x60, 0x00)
	// CALLDATACOPY
	code = append(code, 0x37)
	// PUSH1 0x20, PUSH1 0, RETURN
	code = append(code, 0x60, 0x20, 0x60, 0x00, 0xf3)
	return code
}

// makeCalleeReturn32 returns a tiny callee that writes a 32-byte constant to memory and returns it.
func makeCalleeReturn32() []byte {
	// PUSH1 0xaa ; PUSH1 0x00 ; MSTORE ; PUSH1 0x20 ; PUSH1 0x00 ; RETURN
	return []byte{0x60, 0xaa, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
}

// makeCodeCodecopy generates bytecode that:
// - optionally expands memory to 32 bytes via MSTORE
// - CODECOPY dst=0, codeOffset=0, len=ln
// - RETURN 32 bytes from memory starting at 0
func makeCodeCodecopy(ln int, preExpand bool) []byte {
	code := []byte{}
	if preExpand {
		// PUSH32 0 ; PUSH1 0 ; MSTORE
		code = append(code, 0x7f)
		code = append(code, make([]byte, 32)...)
		code = append(code, 0x60, 0x00, 0x52)
	}
	// PUSH ln
	if ln <= 0xff {
		code = append(code, 0x60, byte(ln))
	} else {
		code = append(code, 0x61, byte(ln>>8), byte(ln))
	}
	// PUSH1 0 (code offset)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (dst)
	code = append(code, 0x60, 0x00)
	// CODECOPY
	code = append(code, 0x39)
	// RETURN 32
	code = append(code, 0x60, 0x20, 0x60, 0x00, 0xf3)
	return code
}

// makeCodeReturndatacopy generates bytecode that:
// - CALLs a preloaded callee at 'toAddr' that returns 32 bytes (no out buffer)
// - optionally pre-expands memory to 32 via MSTORE
// - RETURNDATACOPY dst=0, offset=0, len=ln
// - RETURN 32 bytes from memory
func makeCodeReturndatacopy(toAddr common.Address, ln int, preExpand bool) []byte {
	code := []byte{}
	// Prepare CALL (gas, to, value, inOff, inSz, outOff, outSz)
	// PUSH1 0 (outSz)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (outOff)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (inSz)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (inOff)
	code = append(code, 0x60, 0x00)
	// PUSH1 0 (value)
	code = append(code, 0x60, 0x00)
	// PUSH20 <toAddr>
	code = append(code, 0x73)
	code = append(code, toAddr.Bytes()...)
	// PUSH3 0x0186a0 (gas 100000)
	code = append(code, 0x62, 0x01, 0x86, 0xa0)
	// CALL
	code = append(code, 0xf1)
	if preExpand {
		// PUSH32 0 ; PUSH1 0 ; MSTORE
		code = append(code, 0x7f)
		code = append(code, make([]byte, 32)...)
		code = append(code, 0x60, 0x00, 0x52)
	}
	// RETURNDATACOPY: PUSH len ; PUSH1 0 ; PUSH1 0 ; 0x3e
	if ln <= 0xff {
		code = append(code, 0x60, byte(ln))
	} else {
		code = append(code, 0x61, byte(ln>>8), byte(ln))
	}
	code = append(code, 0x60, 0x00, 0x60, 0x00, 0x3e)
	// RETURN 32
	code = append(code, 0x60, 0x20, 0x60, 0x00, 0xf3)
	return code
}

// makeCodeMCopyOverlap generates bytecode that:
// - optionally pre-expands memory
// - MCOPY dst, src, len
// - RETURN 32 bytes from memory at 0
func makeCodeMCopyOverlap(dst, src, ln int, preExpand bool) []byte {
	code := []byte{}
	if preExpand {
		// Pre-expand to at least max(dst+ln, src+ln) via MSTORE at offset 32
		code = append(code, 0x7f)
		code = append(code, make([]byte, 32)...)
		code = append(code, 0x60, 0x20, 0x52) // PUSH1 0x20 ; MSTORE
	}
	// PUSH len
	if ln <= 0xff {
		code = append(code, 0x60, byte(ln))
	} else {
		code = append(code, 0x61, byte(ln>>8), byte(ln))
	}
	// PUSH src
	if src <= 0xff {
		code = append(code, 0x60, byte(src))
	} else {
		code = append(code, 0x61, byte(src>>8), byte(src))
	}
	// PUSH dst
	if dst <= 0xff {
		code = append(code, 0x60, byte(dst))
	} else {
		code = append(code, 0x61, byte(dst>>8), byte(dst))
	}
	// MCOPY (0x5e)
	code = append(code, 0x5e)
	// RETURN 32
	code = append(code, 0x60, 0x20, 0x60, 0x00, 0xf3)
	return code
}

func runCodeBaseVsMIR(t *testing.T, code []byte, input []byte) {
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)
	base := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	mir := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true, MIRStrictNoFallback: true},
	}
	// Init states
	if base.State == nil {
		base.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mir.State == nil {
		mir.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	addr := common.BytesToAddress([]byte("copy_ops_parity"))
	evmB := runtime.NewEnv(base)
	evmM := runtime.NewEnv(mir)
	evmB.StateDB.CreateAccount(addr)
	evmM.StateDB.CreateAccount(addr)
	evmB.StateDB.SetCode(addr, code)
	evmM.StateDB.SetCode(addr, code)
	senderB := vm.AccountRef(base.Origin)
	senderM := vm.AccountRef(mir.Origin)
	retB, leftB, errB := evmB.Call(senderB, addr, input, base.GasLimit, uint256.NewInt(0))
	retM, leftM, errM := evmM.Call(senderM, addr, input, mir.GasLimit, uint256.NewInt(0))
	if errB != nil || errM != nil {
		if (errB == nil) != (errM == nil) || (errB != nil && errM != nil && errB.Error() != errM.Error()) {
			t.Fatalf("error mismatch base=%v mir=%v", errB, errM)
		}
		return
	}
	if leftB != leftM {
		t.Fatalf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
	if hex.EncodeToString(retB) != hex.EncodeToString(retM) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retB, retM)
	}
}

func TestParity_MCOPY_Overlap_Prague(t *testing.T) {
	// Use Prague-active timestamp from BSC config
	var pragueTs uint64 = 0
	if params.BSCChainConfig.PragueTime != nil {
		pragueTs = *params.BSCChainConfig.PragueTime
	} else {
		// Fallback to a non-zero time to ensure post-London
		pragueTs = 1
	}
	code := makeCodeMCopyOverlap(4, 0, 16, true)
	// Run with Time set to Prague (activates MCOPY)
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)
	base := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Time:        pragueTs,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	mir := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    10_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Time:        pragueTs,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true, MIRStrictNoFallback: true},
	}
	if base.State == nil {
		base.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mir.State == nil {
		mir.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	addr := common.BytesToAddress([]byte("mcopy_overlap"))
	evmB := runtime.NewEnv(base)
	evmM := runtime.NewEnv(mir)
	evmB.StateDB.CreateAccount(addr)
	evmM.StateDB.CreateAccount(addr)
	evmB.StateDB.SetCode(addr, code)
	evmM.StateDB.SetCode(addr, code)
	senderB := vm.AccountRef(base.Origin)
	senderM := vm.AccountRef(mir.Origin)
	retB, leftB, errB := evmB.Call(senderB, addr, nil, base.GasLimit, uint256.NewInt(0))
	retM, leftM, errM := evmM.Call(senderM, addr, nil, mir.GasLimit, uint256.NewInt(0))
	if errB != nil || errM != nil {
		if (errB == nil) != (errM == nil) || (errB != nil && errM != nil && errB.Error() != errM.Error()) {
			t.Fatalf("error mismatch base=%v mir=%v", errB, errM)
		}
		return
	}
	if leftB != leftM {
		t.Fatalf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
	if hex.EncodeToString(retB) != hex.EncodeToString(retM) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retB, retM)
	}
}

func TestParity_CALLDATACOPY_NoGrowth_Partial(t *testing.T) {
	// Pre-expand, then copy 1 byte from calldata into memory
	code := makeCodeCalldatacopy(1, true)
	// Provide at least 1-byte calldata
	input := []byte{0xff}
	runCodeBaseVsMIR(t, code, input)
}

func TestParity_CODECOPY_NoGrowth_Partial(t *testing.T) {
	// Pre-expand memory, then copy 1 byte from code at offset 0
	code := makeCodeCodecopy(1, true)
	runCodeBaseVsMIR(t, code, nil)
}

func TestParity_CALLDATACOPY_Growth_Long(t *testing.T) {
	// No pre-expand, copy 33 bytes to trigger growth and multiword copy
	code := makeCodeCalldatacopy(33, false)
	input := make([]byte, 33)
	for i := range input {
		input[i] = byte(i)
	}
	runCodeBaseVsMIR(t, code, input)
}

func TestParity_RETURNDATACOPY_NoGrowth_Partial(t *testing.T) {
	// Setup callee at fixed address
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)
	base := &runtime.Config{ChainConfig: params.BSCChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: compatBlock, Value: big.NewInt(0), EVMConfig: vm.Config{EnableOpcodeOptimizations: false}}
	mir := &runtime.Config{ChainConfig: params.BSCChainConfig, GasLimit: 10_000_000, Origin: common.Address{}, BlockNumber: compatBlock, Value: big.NewInt(0), EVMConfig: vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true, MIRStrictNoFallback: true}}
	if base.State == nil {
		base.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mir.State == nil {
		mir.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	main := common.BytesToAddress([]byte("returndatacopy_main"))
	callee := common.HexToAddress("0x1000000000000000000000000000000000000001")
	// Install callee code that returns 32 bytes
	evmB := runtime.NewEnv(base)
	evmM := runtime.NewEnv(mir)
	evmB.StateDB.CreateAccount(callee)
	evmM.StateDB.CreateAccount(callee)
	evmB.StateDB.SetCode(callee, makeCalleeReturn32())
	evmM.StateDB.SetCode(callee, makeCalleeReturn32())
	// Main code: CALL callee, pre-expand, RETURNDATACOPY len=1, RETURN 32
	code := makeCodeReturndatacopy(callee, 1, true)
	evmB.StateDB.CreateAccount(main)
	evmM.StateDB.CreateAccount(main)
	evmB.StateDB.SetCode(main, code)
	evmM.StateDB.SetCode(main, code)
	senderB := vm.AccountRef(base.Origin)
	senderM := vm.AccountRef(mir.Origin)
	input := []byte{}
	retB, leftB, errB := evmB.Call(senderB, main, input, base.GasLimit, uint256.NewInt(0))
	retM, leftM, errM := evmM.Call(senderM, main, input, mir.GasLimit, uint256.NewInt(0))
	if errB != nil || errM != nil {
		if (errB == nil) != (errM == nil) || (errB != nil && errM != nil && errB.Error() != errM.Error()) {
			t.Fatalf("error mismatch base=%v mir=%v", errB, errM)
		}
		return
	}
	if leftB != leftM {
		t.Fatalf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
	if hex.EncodeToString(retB) != hex.EncodeToString(retM) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retB, retM)
	}
}
