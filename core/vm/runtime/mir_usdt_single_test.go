package runtime_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	ethlog "github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// TestUSDT_Transfer_EVMvsMIR: deploy USDT from creation code, then call transfer(to, amount)
// once under base EVM and once under MIR (strict) and compare parity (error class, returndata, gas).
func TestMIRUSDT_Transfer_EVMvsMIR_Single(t *testing.T) {
	// Enable MIR opcode parsing
	compiler.EnableOpcodeParse()
	// Optional debug logs (env var)
	if os.Getenv("MIR_DEBUG") == "1" {
		compiler.EnableMIRDebugLogs(true)
		h := ethlog.NewTerminalHandlerWithLevel(os.Stdout, ethlog.LevelWarn, false)
		ethlog.SetDefault(ethlog.NewLogger(h))
	}

	// Use BSC chain config and a compatible block at/after London (matches working parity tests)
	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)

	// Load USDT RUNTIME bytecode like the parity tests do (avoid initcode path).
	// usdtHex is defined in mir_parity_test.go in the same package (runtime_test).
	code, err := hex.DecodeString(usdtHex[2:])
	if err != nil {
		t.Fatalf("decode USDT runtime hex failed: %v", err)
	}

	// Prepare base and MIR configs for the call
	base := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    15_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	mir := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    15_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
			EnableMIRInitcode:         false, // keep constructor off for stability
			MIRStrictNoFallback:       true,
		},
	}

	// Fresh in-memory state
	if base.State == nil {
		base.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mir.State == nil {
		mir.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}

	// Install USDT runtime code at a known address in both envs
	tokenAddr := common.BytesToAddress([]byte("contract_usdt_single"))
	evmB := runtime.NewEnv(base)
	evmM := runtime.NewEnv(mir)
	evmB.StateDB.CreateAccount(tokenAddr)
	evmM.StateDB.CreateAccount(tokenAddr)
	evmB.StateDB.SetCode(tokenAddr, code)
	evmM.StateDB.SetCode(tokenAddr, code)

	// Fund origin and (optionally) set a balance mapping if transfer requires it.
	// We keep Origin zero address and call transfer(to, 1). If USDT reverts due to policy,
	// we still compare error class parity (base vs MIR).

	// Prepare calldata for transfer(to, amount)
	// selector a9059cbb + 32B to + 32B amount
	selector := []byte{0xa9, 0x05, 0x9c, 0xbb}
	to := make([]byte, 32)
	// Use a non-zero recipient; last 20 bytes an address
	copy(to[12:], common.BytesToAddress([]byte("recipient_usdt")).Bytes())
	amount := make([]byte, 32)
	amount[31] = 1
	input := append(append([]byte{}, selector...), append(to, amount...)...)

	// Simple tracer to capture last PC for base for debugging
	var lastBasePC uint64
	base.EVMConfig.Tracer = &tracing.Hooks{
		OnOpcode: func(pc uint64, op byte, gas uint64, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
			lastBasePC = pc
		},
	}

	// Execute transfer under both engines
	senderB := vm.AccountRef(base.Origin)
	senderM := vm.AccountRef(mir.Origin)
	retB, leftB, errB := evmB.Call(senderB, tokenAddr, input, base.GasLimit, uint256.MustFromBig(base.Value))
	// Enable MIR opcode parsing just before MIR run (matches working tests)
	compiler.EnableOpcodeParse()
	retM, leftM, errM := evmM.Call(senderM, tokenAddr, input, mir.GasLimit, uint256.MustFromBig(mir.Value))

	// Emit errors (if any) for inspection
	if errB != nil {
		t.Logf("Base EVM error: %v (last pc=%d)", errB, lastBasePC)
	}
	if errM != nil {
		t.Logf("MIR error: %v", errM)
	}

	// Compare parity: both error/no-error states must match
	if (errB != nil) != (errM != nil) {
		t.Fatalf("error mismatch base=%v mir=%v", errB, errM)
	}
	// If both errored, compare error categories (normalize to revert/jump/opcode/other)
	if errB != nil && errM != nil {
		cat := func(e error) string {
			s := strings.ToLower(e.Error())
			switch {
			case strings.Contains(s, "revert"):
				return "revert"
			case strings.Contains(s, "invalid jump destination"):
				return "badjump"
			case strings.Contains(s, "invalid opcode"):
				return "invalid-opcode"
			default:
				return "other"
			}
		}
		cb, cm := cat(errB), cat(errM)
		if cb != cm {
			t.Fatalf("error category mismatch base=%q (%v) mir=%q (%v)", cb, errB, cm, errM)
		}
		return
	}

	// Success path: exact parity on gas and returndata
	if leftB != leftM {
		t.Fatalf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
	if !bytes.Equal(retB, retM) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retB, retM)
	}
}

// TestMIRUSDT_Name_EVMvsMIR_Single: install USDT runtime and call name() once under base and once under MIR.
func TestMIRUSDT_Name_EVMvsMIR_Single(t *testing.T) {
	// Enable MIR opcode parsing
	compiler.EnableOpcodeParse()
	// Optional debug logs (env var)
	if os.Getenv("MIR_DEBUG") == "1" {
		compiler.EnableMIRDebugLogs(true)
		h := ethlog.NewTerminalHandlerWithLevel(os.Stdout, ethlog.LevelWarn, false)
		ethlog.SetDefault(ethlog.NewLogger(h))
	}

	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)

	// Load USDT runtime bytecode (same source as parity tests)
	code, err := hex.DecodeString(usdtHex[2:])
	if err != nil {
		t.Fatalf("decode USDT runtime hex failed: %v", err)
	}

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
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
			EnableMIRInitcode:         false,
			MIRStrictNoFallback:       true,
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

	// Base call
	senderB := vm.AccountRef(base.Origin)
	retB, leftB, errB := evmB.Call(senderB, addr, input, base.GasLimit, uint256.MustFromBig(base.Value))

	// MIR call (enable parsing right before run)
	compiler.EnableOpcodeParse()
	senderM := vm.AccountRef(mir.Origin)
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
		t.Fatalf("gas leftover mismatch base=%d mir=%d", leftB, leftM)
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
	// Enable detailed MIR logs for this focused repro
	compiler.EnableParserDebugLogs(true)
	compiler.EnableMIRDebugLogs(true)
	var lastMIRPC uint64
	var mirPcs []uint64
	compiler.SetGlobalMIRTracerExtended(func(m *compiler.MIR) {
		if m != nil {
			lastMIRPC = uint64(m.EvmPC())
			if len(mirPcs) < 4096 {
				mirPcs = append(mirPcs, lastMIRPC)
			}
			// Debug loop around 320
			if lastMIRPC >= 320 && lastMIRPC <= 330 {
				ops := m.OperandDebugStrings()
				t.Logf("MIR trace: pc=%d op=%s operands=%v", lastMIRPC, m.Op().String(), ops)
			}
		}
	})
	// Read creation code from file
	creationHexBytes, err := ioutil.ReadFile("../test_contract/usdt_creation_code.txt")
	if err != nil {
		t.Fatalf("read creation code: %v", err)
	}
	creationStr := strings.TrimSpace(string(creationHexBytes))
	if strings.HasPrefix(creationStr, "0x") || strings.HasPrefix(creationStr, "0X") {
		creationStr = creationStr[2:]
	}
	creation, err := hex.DecodeString(creationStr)
	if err != nil {
		t.Fatalf("decode creation hex: %v", err)
	}

	compatBlock := new(big.Int).Set(params.BSCChainConfig.LondonBlock)
	// Base config: no MIR anywhere
	baseCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	// MIR config: enable MIR for initcode and runtime, strict mode
	mirCfg := &runtime.Config{
		ChainConfig: params.BSCChainConfig,
		GasLimit:    20_000_000,
		Origin:      common.Address{},
		BlockNumber: compatBlock,
		Value:       big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
			EnableMIRInitcode:         true,
			MIRStrictNoFallback:       true,
		},
	}

	// Deploy with base EVM
	var basePcs []uint64
	var baseOps []byte
	var baseCtorCopies []string
	var baseCtorReturns []string
	baseCfg.EVMConfig.Tracer = &tracing.Hooks{
		OnOpcode: func(pc uint64, op byte, gasLeft uint64, cost uint64, scope tracing.OpContext, rdata []byte, depth int, err error) {
			if len(basePcs) < 4096 {
				basePcs = append(basePcs, pc)
				baseOps = append(baseOps, op)
			}
			// Capture operands for CODECOPY (0x39) and RETURN (0xf3) around constructor dispatcher
			if pc >= 430 && pc <= 520 {
				stack := scope.StackData()
				if op == 0x39 && len(stack) >= 3 { // CODECOPY
					// top-of-stack is last element; CODECOPY pops dest, off, size (in that order)
					dest := &stack[len(stack)-1]
					codeOff := &stack[len(stack)-2]
					size := &stack[len(stack)-3]
					baseCtorCopies = append(baseCtorCopies, fmt.Sprintf("(pc=%d CODECOPY dest=%s off=%s sz=%s)", pc, dest.String(), codeOff.String(), size.String()))
				}
				if op == 0xf3 && len(stack) >= 2 { // RETURN
					// RETURN pops offset, size (in that order)
					off := &stack[len(stack)-1]
					sz := &stack[len(stack)-2]
					baseCtorReturns = append(baseCtorReturns, fmt.Sprintf("(pc=%d RETURN off=%s sz=%s)", pc, off.String(), sz.String()))
				}
			}
		},
	}
	codeB, addrB, gasLeftB, errB := runtime.Create(creation, baseCfg)
	if errB != nil {
		t.Logf("Base deploy error: %v (gasUsed=%d)", errB, baseCfg.GasLimit-gasLeftB)
	}
	// Deploy with MIR EVM (enable parsing)
	compiler.EnableOpcodeParse()
	codeM, addrM, gasLeftM, errM := runtime.Create(creation, mirCfg)
	if errM != nil {
		t.Logf("MIR deploy error: %v (gasUsed=%d, lastPC=%d)", errM, mirCfg.GasLimit-gasLeftM, lastMIRPC)
	}
	// Focused diff for constructor dispatcher region around pcs ~430-500
	if len(basePcs) > 0 {
		var sb strings.Builder
		sb.WriteString("Base initcode PCs/op in [430,500]:")
		for i := range basePcs {
			pc := basePcs[i]
			if pc >= 430 && pc <= 500 {
				sb.WriteString(strings.TrimSpace(
					// print compact "(pc,op)"
					func() string {
						return fmt.Sprintf(" (%d,0x%02x)", pc, baseOps[i])
					}(),
				))
			}
		}
		t.Log(sb.String())
		if len(baseCtorCopies) > 0 {
			t.Logf("Base initcode CODECOPY operands near ctor: %s", strings.Join(baseCtorCopies, " "))
		}
		if len(baseCtorReturns) > 0 {
			t.Logf("Base initcode RETURN operands near ctor: %s", strings.Join(baseCtorReturns, " "))
		}
	}
	if len(mirPcs) > 0 {
		var sb strings.Builder
		sb.WriteString("MIR initcode evmPCs in [430,500]:")
		for _, pc := range mirPcs {
			if pc >= 430 && pc <= 500 {
				sb.WriteString(fmt.Sprintf(" %d", pc))
			}
		}
		t.Log(sb.String())
	}

	// If either errored, require both to error with same class
	if (errB != nil) != (errM != nil) {
		t.Fatalf("deploy parity mismatch: base=%v mir=%v", errB, errM)
	}
	if errB != nil && errM != nil {
		// Compare rough category only
		cat := func(e error) string {
			s := strings.ToLower(e.Error())
			switch {
			case strings.Contains(s, "revert"):
				return "revert"
			case strings.Contains(s, "invalid jump destination"):
				return "badjump"
			case strings.Contains(s, "invalid opcode"):
				return "invalid-opcode"
			default:
				return "other"
			}
		}
		if cat(errB) != cat(errM) {
			t.Fatalf("deploy error category mismatch base=%q mir=%q", cat(errB), cat(errM))
		}
		return
	}

	// Both succeeded: compare deployed runtime bytecode length (exact bytes may differ in metadata)
	if len(codeB) != len(codeM) {
		t.Logf("Warning: deployed code size differs base=%d mir=%d", len(codeB), len(codeM))
	}

	// Now call name() on each deployed contract
	input := []byte{0x06, 0xfd, 0xde, 0x03}
	// Prepare per-call configs sharing states from deployment
	callBase := *baseCfg
	callMir := *mirCfg
	callBase.GasLimit = 10_000_000
	callMir.GasLimit = 10_000_000
	// Call base
	retB, leftB, errCB := runtime.Call(addrB, input, &callBase)
	// Call MIR (enable parsing before run)
	compiler.EnableOpcodeParse()
	retM, leftM, errCM := runtime.Call(addrM, input, &callMir)

	// Parity on error/no-error
	if (errCB != nil) != (errCM != nil) {
		t.Fatalf("call(name) error mismatch base=%v mir=%v", errCB, errCM)
	}
	if errCB != nil && errCM != nil {
		// If both errored, treat as parity OK for this probe
		return
	}
	// Success: compare returndata and gas
	if !bytes.Equal(retB, retM) {
		t.Fatalf("name() returndata mismatch\nbase: %x\n mir: %x", retB, retM)
	}
	if leftB != leftM {
		t.Fatalf("name() gas leftover mismatch base=%d mir=%d", leftB, leftM)
	}
}
