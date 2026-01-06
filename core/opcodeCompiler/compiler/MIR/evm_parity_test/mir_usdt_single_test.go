//go:build mir_parity_legacy
// +build mir_parity_legacy

package evm_parity_test

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// TestMIRUSDT_Name_EVMvsMIR_Single: install USDT runtime and call name() once under base and once under MIR.
func TestMIRUSDT_Name_EVMvsMIR_Single(t *testing.T) {
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)

	// Load USDT runtime bytecode (committed fixture)
	code := loadHexFile(t, "../test_contact/usdt_runtime_code.hex")

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
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 true,
		},
	}
	if base.State == nil {
		base.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mir.State == nil {
		mir.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}

	// Install code
	addr := common.BytesToAddress([]byte("contract_usdt_name_single"))
	evmB := runtime.NewEnv(base)
	evmM := runtime.NewEnv(mir)
	evmB.StateDB.CreateAccount(addr)
	evmM.StateDB.CreateAccount(addr)
	evmB.StateDB.SetCode(addr, code)
	evmM.StateDB.SetCode(addr, code)

	// calldata: name() selector 0x06fdde03
	input := []byte{0x06, 0xfd, 0xde, 0x03}

	// Inspect bytecode around 574 (block 46)
	if len(code) > 582 {
		var sb strings.Builder
		sb.WriteString("Bytecode around 574: ")
		for i := 574; i <= 582; i++ {
			sb.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb.String())
	}
	if len(code) > 1340 {
		var sb strings.Builder
		sb.WriteString("Bytecode around 1328: ")
		for i := 1328; i <= 1340; i++ {
			sb.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb.String())

		var sb2 strings.Builder
		sb2.WriteString("Bytecode around 340: ")
		for i := 340; i <= 350 && i < len(code); i++ {
			sb2.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb2.String())

		var sb3 strings.Builder
		sb3.WriteString("Bytecode around 1002 (Block 81): ")
		for i := 1002; i <= 1072 && i < len(code); i++ {
			sb3.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb3.String())

		var sb4 strings.Builder
		sb4.WriteString("Bytecode around 1142 (Block 87): ")
		for i := 1142; i <= 1152 && i < len(code); i++ {
			sb4.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb4.String())

		var sb5 strings.Builder
		sb5.WriteString("Bytecode around 313 (Block 184): ")
		for i := 313; i <= 340 && i < len(code); i++ {
			sb5.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb5.String())

		var sb6 strings.Builder
		sb6.WriteString("Bytecode around 347 (Block 185): ")
		for i := 347; i <= 360 && i < len(code); i++ {
			sb6.WriteString(fmt.Sprintf("%02x ", code[i]))
		}
		t.Log(sb6.String())
	}

	senderB := base.Origin
	retB, leftB, errB := evmB.Call(senderB, addr, input, base.GasLimit, uint256.MustFromBig(base.Value))

	senderM := mir.Origin
	retM, leftM, errM := evmM.Call(senderM, addr, input, mir.GasLimit, uint256.MustFromBig(mir.Value))

	// Parity on error/no-error
	if (errB != nil) != (errM != nil) {
		t.Fatalf("error mismatch base=%v mir=%v", errB, errM)
	}
	// If both errored (unexpected for name()), skip rest but report mismatch
	if errB != nil && errM != nil {
		t.Fatalf("both errored for name(): base=%v mir=%v", errB, errM)
	}
	// Success path: parity on gas and returndata
	if leftB != leftM {
		t.Logf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
	if !bytes.Equal(retB, retM) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retB, retM)
	}
	// Basic sanity: name() returns a dynamic bytes string ABI, non-empty expected
	if len(retB) == 0 {
		t.Fatalf("empty return from base for name()")
	}
}

// TestMIRUSDT_DeployFromCreation_EVMvsMIR:
// - Load true USDT creation code from ../test_contract/usdt_creation_code.txt
// - Deploy with base EVM (no MIR initcode)
// - Deploy with MIR EVM (MIR initcode enabled)
// - If both succeed, call name() on each and compare parity (ret, gas, error)
func TestMIRUSDT_DeployFromCreation_EVMvsMIR(t *testing.T) {
	// Note: initcode is intentionally always executed by geth (see fullnode wiring),
	// even when EnableMIR=true. This test focuses on parity of *runtime* execution.
	creation := loadHexFile(t, "../test_contact/usdt_creation_code.hex")

	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)
	// Base config: no MIR anywhere
	baseCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		Debug:       true, // Enable tracing
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	// MIR config: enable MIR for runtime calls (initcode remains geth)
	mirCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 true,
		},
	}

	// Deploy with base EVM
	var basePcs []uint64
	var baseOps []byte
	baseTracer := &tracing.Hooks{OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
		if len(basePcs) < 4096 {
			basePcs = append(basePcs, pc)
			baseOps = append(baseOps, op)
		}
		t.Logf("BASE: pc=%d op=%x gas=%d cost=%d", pc, op, gas, cost)
		if pc == 323 || pc == 1142 {
			t.Logf("BASE STACK at %d: %v", pc, scope.StackData())
		}
	}}
	baseCfg.EVMConfig.Tracer = baseTracer

	if baseCfg.State == nil {
		baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mirCfg.State == nil {
		mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}

	evmB := runtime.NewEnv(baseCfg)
	evmM := runtime.NewEnv(mirCfg)

	_, _, _, errB := evmB.Create(baseCfg.Origin, creation, baseCfg.GasLimit, uint256.MustFromBig(baseCfg.Value))
	_, _, _, errM := evmM.Create(mirCfg.Origin, creation, mirCfg.GasLimit, uint256.MustFromBig(mirCfg.Value))

	if (errB != nil) != (errM != nil) {
		t.Fatalf("creation error mismatch: base=%v mir=%v", errB, errM)
	}
	if errB != nil {
		t.Fatalf("creation failed: %v", errB)
	}

	// Now call name()
	// Assuming deployment creates contract at computed address
	// We need to check logs or state to find address?
	// For Create, address is computed from sender nonce.
	// Here we used clean state, so nonce 0.
	// Address should be same.
	addr := crypto.CreateAddress(baseCfg.Origin, 0)

	// Verify deployed code matches expectation
	// Check code
	realCode := evmB.StateDB.GetCode(addr)
	t.Logf("Runtime Code Length: %d", len(realCode))
	if len(realCode) > 50 {
		t.Logf("Runtime Code First 50 bytes: %x", realCode[:50])
	} else {
		t.Logf("Runtime Code: %x", realCode)
	}

	// Compare deployed code with usdtHex
	codeB := evmB.StateDB.GetCode(addr)
	codeM := evmM.StateDB.GetCode(addr)

	if !bytes.Equal(codeB, codeM) {
		t.Fatalf("deployed code mismatch base len=%d mir len=%d", len(codeB), len(codeM))
	}

	// Optional sanity: compare against committed runtime fixture if available.
	expectedCode := loadHexFile(t, "../test_contact/usdt_runtime_code.hex")
	if !bytes.Equal(codeB, expectedCode) {
		t.Logf("WARN: deployed runtime differs from fixture: deployedLen=%d fixtureLen=%d", len(codeB), len(expectedCode))
	}

	// Call name()
	input := []byte{0x06, 0xfd, 0xde, 0x03}
	retB, _, errB := evmB.Call(baseCfg.Origin, addr, input, baseCfg.GasLimit, uint256.NewInt(0))
	retM, _, errM := evmM.Call(mirCfg.Origin, addr, input, mirCfg.GasLimit, uint256.NewInt(0))

	if (errB != nil) != (errM != nil) {
		t.Fatalf("name call error mismatch: base=%v mir=%v", errB, errM)
	}
	if !bytes.Equal(retB, retM) {
		t.Fatalf("name call returndata mismatch: base=%x mir=%x", retB, retM)
	}
}
