package runtime_test

import (
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
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type gasStep966 struct {
	pc   uint64
	op   byte
	gas  uint64
	cost uint64
}

func dumpFirstGasDiff966(t *testing.T, a, b []gasStep966) {
	t.Helper()
	normalizeMIR := func(steps []gasStep966) []gasStep966 {
		if len(steps) < 2 {
			return steps
		}
		out := make([]gasStep966, 0, len(steps))
		i := 0
		for i < len(steps) {
			if i+1 < len(steps) && steps[i].pc == steps[i+1].pc && steps[i].op == steps[i+1].op && steps[i].gas >= steps[i+1].gas {
				out = append(out, steps[i+1])
				i += 2
				continue
			}
			out = append(out, steps[i])
			i++
		}
		return out
	}
	b = normalizeMIR(b)
	derive := func(steps []gasStep966) []gasStep966 {
		out := make([]gasStep966, len(steps))
		var prev uint64
		for i := range steps {
			out[i] = steps[i]
			if i == 0 {
				prev = steps[i].gas
				out[i].cost = 0
				continue
			}
			if prev >= steps[i].gas {
				out[i].cost = prev - steps[i].gas
			} else {
				out[i].cost = 0
			}
			prev = steps[i].gas
		}
		return out
	}
	a = derive(a)
	b = derive(b)

	ai := 0
	for bi := 0; bi < len(b); bi++ {
		for ai < len(a) && (a[ai].pc != b[bi].pc || a[ai].op != b[bi].op) {
			ai++
		}
		if ai >= len(a) {
			t.Logf("unable to align MIR step bi=%d (pc=%d op=0x%x) in base stream (baseLen=%d)", bi, b[bi].pc, b[bi].op, len(a))
			return
		}
		if a[ai].cost != b[bi].cost {
			t.Logf("first aligned cost mismatch at pc=%d op=0x%x baseCost=%d mirCost=%d baseGas=%d mirGas=%d",
				b[bi].pc, b[bi].op, a[ai].cost, b[bi].cost, a[ai].gas, b[bi].gas)
			return
		}
		ai++
	}
	t.Logf("no aligned per-op cost diff found (lenBase=%d lenMIR=%d)", len(a), len(b))
}

// Regression test for Chapel block 966 tx0 execution gas (post-intrinsic).
//
// On-chain tx0 has gasLimit=29800 and intrinsic=21064, leaving 8736 gas for execution.
// Native EVM succeeds with exactly 0 gas left; MIR historically OOGs at LOG1 (pc=5304).
func TestMIR_Block966_Tx0_ExecGasParity(t *testing.T) {
	compiler.EnableOpcodeParse()

	codeHex, err := os.ReadFile("testdata_block966_code.hex")
	if err != nil {
		t.Fatalf("read testdata_block966_code.hex failed: %v", err)
	}
	codeStr := strings.TrimSpace(string(codeHex))
	codeStr = strings.TrimPrefix(codeStr, "0x")
	code, err := hex.DecodeString(codeStr)
	if err != nil {
		t.Fatalf("decode runtime bytecode failed: %v", err)
	}

	blockNumber := big.NewInt(966)
	contractAddr := common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")
	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	blockTime := uint64(0x5f06d951)
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16) // 27 gwei

	// Execution gas available after intrinsic (29800 - 21064).
	gasExec := uint64(8736)
	value := big.NewInt(0)
	input := common.Hex2Bytes("3f4ba83a")

	baseCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    gasExec,
		Origin:      sender,
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		Time:        blockTime,
		GasPrice:    gasPrice,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true},
	}
	mirCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    gasExec,
		Origin:      sender,
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		Time:        blockTime,
		GasPrice:    gasPrice,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
		},
	}
	// Build committed prestate (so GetCommittedState matches on-chain prestate).
	buildCommittedState := func() *state.StateDB {
		db := state.NewDatabaseForTesting()
		st, _ := state.New(types.EmptyRootHash, db)
		st.CreateAccount(sender)
		st.SetNonce(sender, 20, tracing.NonceChangeUnspecified)
		// balance = 0x1030d9a9661396fe00 (copied from tracer output)
		bal := new(big.Int)
		bal.SetString("1030d9a9661396fe00", 16)
		st.SetBalance(sender, uint256.MustFromBig(bal), tracing.BalanceChangeTouchAccount)

		st.CreateAccount(contractAddr)
		st.SetNonce(contractAddr, 1, tracing.NonceChangeUnspecified)
		st.SetCode(contractAddr, code)
		st.SetState(contractAddr,
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"),
			common.HexToHash("0x000000000000000000000000fa5e36a04eef3152092099f352ddbe88953bb540"),
		)
		st.SetState(contractAddr,
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),
			common.HexToHash("0x0000000000000000000000010000000000000000000000000000000000000000"),
		)
		root, err := st.Commit(0, false, false)
		if err != nil {
			t.Fatalf("commit prestate failed: %v", err)
		}
		st2, _ := state.New(root, db)
		return st2
	}
	baseCfg.State = buildCommittedState()
	mirCfg.State = buildCommittedState()

	evmBase := runtime.NewEnv(baseCfg)
	evmMIR := runtime.NewEnv(mirCfg)

	var baseSteps, mirSteps []gasStep966
	if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
		baseCfg.EVMConfig.Tracer = &tracing.Hooks{
			OnOpcode: func(pc uint64, op byte, gas uint64, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
				after := gas
				if gas >= cost {
					after = gas - cost
				}
				baseSteps = append(baseSteps, gasStep966{pc: pc, op: op, gas: after})
			},
		}
		vm.SetMIRGasProbe(func(pc uint64, op byte, gasLeft uint64) {
			mirSteps = append(mirSteps, gasStep966{pc: pc, op: op, gas: gasLeft})
		})
		defer vm.SetMIRGasProbe(nil)
		// recreate envs so tracer is installed
		evmBase = runtime.NewEnv(baseCfg)
		evmMIR = runtime.NewEnv(mirCfg)
	}

	retBase, leftBase, errBase := evmBase.Call(sender, contractAddr, input, gasExec, uint256.MustFromBig(value))
	retMIR, leftMIR, errMIR := evmMIR.Call(sender, contractAddr, input, gasExec, uint256.MustFromBig(value))

	if errBase != nil {
		t.Fatalf("base unexpected error=%v", errBase)
	}
	if errMIR != nil {
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			dumpFirstGasDiff966(t, baseSteps, mirSteps)
		}
		t.Fatalf("mir unexpected error=%v (leftMIR=%d leftBase=%d)", errMIR, leftMIR, leftBase)
	}

	if leftBase != leftMIR {
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			dumpFirstGasDiff966(t, baseSteps, mirSteps)
		}
		t.Fatalf("gasLeft mismatch base=%d mir=%d", leftBase, leftMIR)
	}
	if leftBase != 0 {
		t.Fatalf("expected 0 gas left (on-chain tx uses all exec gas): got=%d", leftBase)
	}
	if !strings.EqualFold(hex.EncodeToString(retBase), hex.EncodeToString(retMIR)) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retBase, retMIR)
	}
	// Must emit the Pause event (topic0 only, data empty) once.
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")
	logsBase := baseCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	logsMIR := mirCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	if len(logsBase) != 1 || len(logsMIR) != 1 {
		t.Fatalf("logs len mismatch base=%d mir=%d want=1", len(logsBase), len(logsMIR))
	}
	if logsBase[0].Topics[0] != wantTopic0 || logsMIR[0].Topics[0] != wantTopic0 {
		t.Fatalf("topic0 mismatch base=%s mir=%s want=%s", logsBase[0].Topics[0], logsMIR[0].Topics[0], wantTopic0)
	}
}


