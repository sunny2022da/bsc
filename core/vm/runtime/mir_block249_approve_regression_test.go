package runtime_test

import (
	"encoding/hex"
	"fmt"
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

type gasStep struct {
	pc   uint64
	op   byte
	gas  uint64
	cost uint64
}

func dumpFirstGasDiff(t *testing.T, label string, a, b []gasStep) {
	t.Helper()
	// MIR probe records an extra step at block-entry for the first MIR instruction of a block
	// (same pc/op repeated), before the actual per-instruction charging happens. Collapse those
	// duplicates so we compare "per-instruction" costs.
	normalizeMIR := func(steps []gasStep) []gasStep {
		if len(steps) < 2 {
			return steps
		}
		out := make([]gasStep, 0, len(steps))
		i := 0
		for i < len(steps) {
			if i+1 < len(steps) && steps[i].pc == steps[i+1].pc && steps[i].op == steps[i+1].op && steps[i].gas >= steps[i+1].gas {
				// Drop the block-entry snapshot (higher gas), keep the per-instruction one.
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
	// Derive per-step cost from gas deltas (tracer-reported cost is unreliable for MIR).
	derive := func(steps []gasStep) []gasStep {
		out := make([]gasStep, len(steps))
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

	// MIR tracer only emits steps for opcodes that have MIR-level hooks; base tracer emits all.
	// Align by advancing the base cursor until we find the matching (pc,op) for each MIR step.
	ai := 0
	for bi := 0; bi < len(b); bi++ {
		// find match in base stream
		for ai < len(a) && (a[ai].pc != b[bi].pc || a[ai].op != b[bi].op) {
			ai++
		}
		if ai >= len(a) {
			t.Logf("[%s] unable to align MIR step bi=%d (pc=%d op=0x%x) in base stream (baseLen=%d)",
				label, bi, b[bi].pc, b[bi].op, len(a))
			return
		}
		// Compare derived per-step cost (gas delta) for the aligned opcode.
		if a[ai].cost != b[bi].cost {
			t.Logf("[%s] first aligned cost mismatch at bi=%d pc=%d op=0x%x baseCost=%d mirCost=%d baseGas=%d mirGas=%d",
				label, bi, b[bi].pc, b[bi].op, a[ai].cost, b[bi].cost, a[ai].gas, b[bi].gas)
			// print a small window in MIR space, with aligned base indices
			start := bi - 5
			if start < 0 {
				start = 0
			}
			end := bi + 5
			if end > len(b)-1 {
				end = len(b) - 1
			}
			aj := ai
			for bj := start; bj <= end; bj++ {
				for aj < len(a) && (a[aj].pc != b[bj].pc || a[aj].op != b[bj].op) {
					aj++
				}
				if aj >= len(a) {
					t.Logf("  [%s] bi=%d pc=%d op=0x%x base=<no match> mirGas=%d mirCost=%d",
						label, bj, b[bj].pc, b[bj].op, b[bj].gas, b[bj].cost)
					continue
				}
				t.Logf("  [%s] bi=%d pc=%d op=0x%x baseGas=%d mirGas=%d baseCost=%d mirCost=%d",
					label, bj, b[bj].pc, b[bj].op, a[aj].gas, b[bj].gas, a[aj].cost, b[bj].cost)
			}
			return
		}
		ai++ // continue searching from the next base step
	}
	t.Logf("[%s] no aligned per-op cost diff found (lenBase=%d lenMIR=%d)", label, len(a), len(b))
}

// Regression test for Chapel block 249 tx0:
// 0x869c005a891aa95218c9d51a34ad2594924c3cc257536a20935aa84e35a44841
//
// Historically MIR diverged here with invalid bloom/receipts root due to an OOG in tx0,
// which removed the Approval log and changed receiptsRoot/logsBloom.
func TestMIR_Block249_Approve_GasAndLogsParity(t *testing.T) {
	compiler.EnableOpcodeParse()

	// Load the real on-chain runtime bytecode at block 249 (captured via eth_getCode).
	codeHex, err := os.ReadFile("testdata_block249_code.hex")
	if err != nil {
		t.Fatalf("read testdata_block249_code.hex failed: %v", err)
	}
	codeStr := strings.TrimSpace(string(codeHex))
	codeStr = strings.TrimPrefix(codeStr, "0x")
	code, err := hex.DecodeString(codeStr)
	if err != nil {
		t.Fatalf("decode runtime bytecode failed: %v", err)
	}

	// Chapel block 249 tx0 parameters.
	blockNumber := big.NewInt(249)
	contractAddr := common.HexToAddress("0xc3c3fcad82c7658cc821f21bcb4e5372339db953")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")
	gasLimit := uint64(0xab68) // 43880
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16)
	value := big.NewInt(0)

	// calldata: approve(0x1008, 0x2116545850052128000000)
	input := common.Hex2Bytes("095ea7b300000000000000000000000000000000000000000000000000000000000010080000000000000000000000000000000000000000002116545850052128000000")

	// Build base/native EVM env.
	baseCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    gasLimit,
		Origin:      sender,
		GasPrice:    gasPrice,
		BlockNumber: blockNumber,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: false},
	}
	mirCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    gasLimit,
		Origin:      sender,
		GasPrice:    gasPrice,
		BlockNumber: blockNumber,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 true,
		},
	}
	if baseCfg.State == nil {
		baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mirCfg.State == nil {
		mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}

	// Install identical code and fund the sender (needed since gasPrice != 0).
	for _, st := range []*state.StateDB{baseCfg.State, mirCfg.State} {
		st.CreateAccount(sender)
		st.CreateAccount(contractAddr)
		st.SetCode(contractAddr, code)
		st.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeTouchAccount)
	}

	evmBase := runtime.NewEnv(baseCfg)
	evmMIR := runtime.NewEnv(mirCfg)

	var baseSteps, mirSteps []gasStep
	var mirBlockEntryCounts []struct {
		firstPC uint
		counts  map[byte]uint32
	}
	baseCostByOp := make(map[byte]uint64)
	mirCostByOp := make(map[byte]uint64)
	if os.Getenv("MIR_DEBUG_GASDIFF") == "1" || os.Getenv("MIR_DEBUG_COSTTRACE") == "1" {
		baseCfg.EVMConfig.Tracer = &tracing.Hooks{
			OnOpcode: func(pc uint64, op byte, gas uint64, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
				// Record "gas after charging" to be comparable with MIR gas probe output.
				after := gas
				if gas >= cost {
					after = gas - cost
				}
				baseSteps = append(baseSteps, gasStep{pc: pc, op: op, gas: after})
				baseCostByOp[op] += cost
			},
		}
		// For MIR, use adapter probe which reports gas after MIR charging hooks.
		vm.SetMIRGasProbe(func(pc uint64, op byte, gasLeft uint64) {
			mirSteps = append(mirSteps, gasStep{pc: pc, op: op, gas: gasLeft})
		})
		vm.SetMIRGasChargeProbe(func(pc uint64, op byte, charged uint64, isBlockEntry bool) {
			_ = pc
			_ = isBlockEntry
			mirCostByOp[op] += charged
			if os.Getenv("MIR_DEBUG_COSTTRACE") == "1" && !isBlockEntry && op == 0x03 && charged != 3 {
				t.Logf("MIR_SUB_CHARGE pc=%d charged=%d", pc, charged)
			}
		})
		vm.SetMIRBlockEntryCountsProbe(func(firstPC uint, counts map[byte]uint32) {
			mirBlockEntryCounts = append(mirBlockEntryCounts, struct {
				firstPC uint
				counts  map[byte]uint32
			}{firstPC: firstPC, counts: counts})
		})
		defer vm.SetMIRGasProbe(nil)
		defer vm.SetMIRBlockEntryCountsProbe(nil)
		defer vm.SetMIRGasChargeProbe(nil)
		// Recreate envs so tracer is installed.
		evmBase = runtime.NewEnv(baseCfg)
		evmMIR = runtime.NewEnv(mirCfg)
	}

	if os.Getenv("MIR_DEBUG") == "1" {
		// Only install the printing probe if no other probe is already used for gas diff/cost trace.
		if os.Getenv("MIR_DEBUG_GASDIFF") != "1" && os.Getenv("MIR_DEBUG_COSTTRACE") != "1" {
			vm.SetMIRGasProbe(func(pc uint64, op byte, gasLeft uint64) {
				fmt.Printf("MIR GAS: pc=%d op=0x%x gasLeft=%d\n", pc, op, gasLeft)
			})
			defer vm.SetMIRGasProbe(nil)
		}
	}

	retBase, leftBase, errBase := evmBase.Call(sender, contractAddr, input, gasLimit, uint256.MustFromBig(value))
	var lastMIRPC uint64
	compiler.SetGlobalMIRTracerExtended(func(m *compiler.MIR) {
		// Clean up global tracer to prevent test pollution
		defer compiler.SetGlobalMIRTracerExtended(nil)
		if m != nil {
			lastMIRPC = uint64(m.EvmPC())
		}
	})
	retMIR, leftMIR, errMIR := evmMIR.Call(sender, contractAddr, input, gasLimit, uint256.MustFromBig(value))
	compiler.SetGlobalMIRTracerExtended(nil)

	if (errBase != nil) != (errMIR != nil) {
		t.Fatalf("error mismatch base=%v mir=%v (lastMIRPC=%d)", errBase, errMIR, lastMIRPC)
	}
	if errBase != nil {
		// If both errored, at least ensure they error the same way.
		if errBase.Error() != errMIR.Error() {
			t.Fatalf("error message mismatch base=%q mir=%q (lastMIRPC=%d)", errBase.Error(), errMIR.Error(), lastMIRPC)
		}
		return
	}

	if leftBase != leftMIR {
		if os.Getenv("MIR_DEBUG_GASDIFF") == "1" {
			dumpFirstGasDiff(t, "block249", baseSteps, mirSteps)
		}
		if os.Getenv("MIR_DEBUG_COSTTRACE") == "1" {
			// Summarize stack-only opcode counts (base executed vs MIR charged-at-block-entry).
			var basePush, baseDup, baseSwap uint32
			for _, s := range baseSteps {
				op := vm.OpCode(s.op)
				switch {
				case op == vm.PUSH0 || (op >= vm.PUSH1 && op <= vm.PUSH32):
					basePush++
				case op >= vm.DUP1 && op <= vm.DUP16:
					baseDup++
				case op >= vm.SWAP1 && op <= vm.SWAP16:
					baseSwap++
				}
			}
			var mirPush, mirDup, mirSwap uint32
			for _, be := range mirBlockEntryCounts {
				for opb, c := range be.counts {
					op := vm.OpCode(opb)
					switch {
					case op == vm.PUSH0 || (op >= vm.PUSH1 && op <= vm.PUSH32):
						mirPush += c
					case op >= vm.DUP1 && op <= vm.DUP16:
						mirDup += c
					case op >= vm.SWAP1 && op <= vm.SWAP16:
						mirSwap += c
					}
				}
			}
			t.Logf("STACK_OP_COUNTS base(push=%d dup=%d swap=%d) mirBlockEntry(push=%d dup=%d swap=%d) blocks=%d",
				basePush, baseDup, baseSwap, mirPush, mirDup, mirSwap, len(mirBlockEntryCounts))
			// Find opcodes where total charged differs.
			type diff struct {
				op   byte
				base uint64
				mir  uint64
			}
			var diffs []diff
			for op, bc := range baseCostByOp {
				mc := mirCostByOp[op]
				if bc != mc {
					diffs = append(diffs, diff{op: op, base: bc, mir: mc})
				}
			}
			// Log a few diffs.
			for i := 0; i < len(diffs) && i < 12; i++ {
				d := diffs[i]
				t.Logf("OP_COST_DIFF op=0x%x base=%d mir=%d delta=%d", d.op, d.base, d.mir, int64(d.mir)-int64(d.base))
			}
		}
		t.Fatalf("gasLeft mismatch base=%d mir=%d (gasUsed base=%d mir=%d)", leftBase, leftMIR, gasLimit-leftBase, gasLimit-leftMIR)
	}
	if !strings.EqualFold(hex.EncodeToString(retBase), hex.EncodeToString(retMIR)) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retBase, retMIR)
	}

	// The critical consensus signal: Approval log must be present.
	wantTopic0 := common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925") // Approval(address,address,uint256)

	logsBase := baseCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	logsMIR := mirCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)

	if len(logsBase) == 0 {
		t.Fatalf("base emitted no logs; expected Approval")
	}
	if len(logsMIR) == 0 {
		t.Fatalf("mir emitted no logs; expected Approval")
	}
	if logsBase[0].Topics[0] != wantTopic0 {
		t.Fatalf("base topic0 mismatch have=%s want=%s", logsBase[0].Topics[0], wantTopic0)
	}
	if logsMIR[0].Topics[0] != wantTopic0 {
		t.Fatalf("mir topic0 mismatch have=%s want=%s", logsMIR[0].Topics[0], wantTopic0)
	}
	// Ensure the log address is the contract itself.
	if logsMIR[0].Address != contractAddr {
		t.Fatalf("mir log address mismatch have=%s want=%s", logsMIR[0].Address, contractAddr)
	}
}
