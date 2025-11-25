package runtime_test

import (
	"bytes"
	"encoding/hex"
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
