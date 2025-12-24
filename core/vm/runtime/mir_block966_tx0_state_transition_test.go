package runtime_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func dumpFirstGasLeftDiff966(t *testing.T, baseSteps, mirSteps []gasStep) {
	t.Helper()
	// Normalize MIR: drop the extra block-entry snapshot for the first instruction of each block
	// (same pc/op repeated), keeping the post-instruction gas value.
	normalizeMIR := func(steps []gasStep) []gasStep {
		if len(steps) < 2 {
			return steps
		}
		out := make([]gasStep, 0, len(steps))
		i := 0
		for i < len(steps) {
			if i+1 < len(steps) &&
				steps[i].pc == steps[i+1].pc &&
				steps[i].op == steps[i+1].op &&
				steps[i].gas >= steps[i+1].gas {
				out = append(out, steps[i+1])
				i += 2
				continue
			}
			out = append(out, steps[i])
			i++
		}
		return out
	}
	mirSteps = normalizeMIR(mirSteps)

	ai := 0
	for bi := 0; bi < len(mirSteps); bi++ {
		for ai < len(baseSteps) && (baseSteps[ai].pc != mirSteps[bi].pc || baseSteps[ai].op != mirSteps[bi].op) {
			ai++
		}
		if ai >= len(baseSteps) {
			t.Logf("[block966] unable to align MIR step bi=%d (pc=%d op=0x%x) in base stream (baseLen=%d)",
				bi, mirSteps[bi].pc, mirSteps[bi].op, len(baseSteps))
			return
		}
		if baseSteps[ai].gas != mirSteps[bi].gas {
			t.Logf("[block966] first aligned gasLeft mismatch at pc=%d op=0x%x baseGas=%d mirGas=%d delta=%d",
				mirSteps[bi].pc, mirSteps[bi].op, baseSteps[ai].gas, mirSteps[bi].gas, int64(mirSteps[bi].gas)-int64(baseSteps[ai].gas))
			return
		}
		ai++
	}
	t.Logf("[block966] no aligned gasLeft diff found (lenBase=%d lenMIR=%d)", len(baseSteps), len(mirSteps))
}

func dumpFirstPreGasDrift966(t *testing.T, baseSteps []gasStep, mirPreSteps []gasStep) {
	t.Helper()
	// baseSteps: gasAfter + cost. Convert to "gas before opcode".
	basePre := make([]gasStep, 0, len(baseSteps))
	for _, s := range baseSteps {
		basePre = append(basePre, gasStep{pc: s.pc, op: s.op, gas: s.gas + s.cost})
	}
	// Normalize MIR-pre: for the first instruction of a basic block, MIR can emit two pre-snapshots
	// with the same pc/op (block-entry and instruction). We want the instruction-pre snapshot (later),
	// since it reflects post block-entry charges.
	normalizeMIRPre := func(steps []gasStep) []gasStep {
		if len(steps) < 2 {
			return steps
		}
		out := make([]gasStep, 0, len(steps))
		i := 0
		for i < len(steps) {
			if i+1 < len(steps) &&
				steps[i].pc == steps[i+1].pc &&
				steps[i].op == steps[i+1].op &&
				steps[i].gas >= steps[i+1].gas {
				out = append(out, steps[i+1])
				i += 2
				continue
			}
			out = append(out, steps[i])
			i++
		}
		return out
	}
	mirPre := normalizeMIRPre(mirPreSteps)

	if len(mirPre) == 0 || len(basePre) == 0 {
		t.Logf("[block966] drift: empty streams base=%d mir=%d", len(basePre), len(mirPre))
		return
	}

	// MIR-pre omits many stack-only ops (PUSH/DUP/SWAP/POP) because they're charged at block-entry.
	// So we align by scanning the base stream forward to find each MIR opcode.
	bi := 0
	var prevDelta int64
	var havePrev bool
	for mi := 0; mi < len(mirPre); mi++ {
		m := mirPre[mi]
		// Focus on the region that leads into the LOG1 OOG (pc~5k+).
		// Earlier parts can show large "drifts" purely from block-entry charging shifting stack-op
		// constants earlier than the native stream.
		if m.pc < 5000 {
			continue
		}
		for bi < len(basePre) && (basePre[bi].pc != m.pc || basePre[bi].op != m.op) {
			bi++
		}
		if bi >= len(basePre) {
			t.Logf("[block966] drift: unable to align mirI=%d pc=%d op=0x%x in base stream (baseLen=%d)",
				mi, m.pc, m.op, len(basePre))
			return
		}
		delta := int64(m.gas) - int64(basePre[bi].gas)
		if havePrev {
			deltaChange := delta - prevDelta
			if deltaChange >= 40 || deltaChange <= -40 {
				// Print a small window around the first large drift step.
				t.Logf("[block966] first large preGas drift at baseBi=%d mirI=%d pc=%d op=0x%x basePre=%d mirPre=%d delta=%d deltaChange=%d",
					bi, mi, m.pc, m.op, basePre[bi].gas, m.gas, delta, deltaChange)
				startB := bi - 6
				if startB < 0 {
					startB = 0
				}
				endB := bi + 6
				if endB > len(basePre)-1 {
					endB = len(basePre) - 1
				}
				t.Logf("[block966] basePre window:")
				for i := startB; i <= endB; i++ {
					t.Logf("  basePre bi=%d pc=%d op=0x%x gas=%d", i, basePre[i].pc, basePre[i].op, basePre[i].gas)
				}
				startM := mi - 6
				if startM < 0 {
					startM = 0
				}
				endM := mi + 6
				if endM > len(mirPre)-1 {
					endM = len(mirPre) - 1
				}
				t.Logf("[block966] mirPre window:")
				for i := startM; i <= endM; i++ {
					t.Logf("  mirPre  i=%d pc=%d op=0x%x gas=%d", i, mirPre[i].pc, mirPre[i].op, mirPre[i].gas)
				}
				return
			}
		}
		prevDelta = delta
		havePrev = true
		// keep base index monotonic
		bi++
	}
	t.Logf("[block966] drift: no large preGas drift found (lenBase=%d lenMIR=%d)", len(basePre), len(mirPre))
}

// Tx-level reproducer harness for Chapel block 966 tx0.
// This executes the full state transition (intrinsic gas + EVM.Call with gasRemaining=8736)
// and is intended to reproduce MIR's LOG1 OOG locally.
//
// Run:
//   MIR_RUN_BLOCK966_TX0=1 MIR_DEBUG_GASDIFF_966=1 go test ./core/vm/runtime -run '^TestMIR_Block966_Tx0_StateTransition_Repro$' -count=1
func TestMIR_Block966_Tx0_StateTransition_Repro(t *testing.T) {
	if os.Getenv("MIR_RUN_BLOCK966_TX0") != "1" {
		t.Skip("set MIR_RUN_BLOCK966_TX0=1 to run")
	}

	compiler.EnableOpcodeParse()

	blockNumber := big.NewInt(966)
	blockTime := uint64(0x5f06d951)
	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	// Needed for BLOCKHASH opcode. Block 966 parentHash is block 965 hash.
	block965Hash := common.HexToHash("0x2ac635eb3de76e0d23b51e1b2196cc320cc6f30d05a6a2878002424a91b32651")

	txHash := common.HexToHash("0x51a2684dff1919c2dc9401b24d907cacdb35087acc16fcde95e9a1351509a25b")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")
	to := common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	gasLimit := uint64(0x7468) // 29800
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16) // 27gwei

	// On-chain signature (EIP-155 legacy, chainId=97 => v=0xe5).
	v := new(big.Int).SetUint64(0xe5)
	r, _ := new(big.Int).SetString("a2442ecaa716d164f7a09a68a520b93e7898f737f1ea1b22feb871716c5abd4d", 16)
	s, _ := new(big.Int).SetString("24691a3482ee9fa3aec735ac37eb0ef8d001d234a902d80cf76ae892cca2e31a", 16)

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    20,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     common.Hex2Bytes("3f4ba83a"),
		V:        v,
		R:        r,
		S:        s,
	})
	if got := tx.Hash(); got != txHash {
		t.Fatalf("tx hash mismatch in test setup got=%s want=%s", got, txHash)
	}

	// Load prestate + code from the prestate tracer dump JSON (source of truth).
	// NOTE: We intentionally do NOT rely on a separately-copied hex file here because
	// a stale/incorrect copy can lead to invalid jump destinations and false negatives.
	type preAccount struct {
		Balance string            `json:"balance"`
		Nonce   uint64            `json:"nonce"`
		Code    string            `json:"code"`
		Storage map[string]string `json:"storage"`
	}
	type prestateDump struct {
		Result map[string]preAccount `json:"result"`
	}
	var dump prestateDump
	prestatePath := "../../../tmp_files/debug_traceTx_0x51a2684dff1919c2dc9401b24d907cacdb35087acc16fcde95e9a1351509a25b.json"
	raw, err := os.ReadFile(prestatePath)
	if err != nil {
		t.Fatalf("read prestate dump failed path=%s err=%v", prestatePath, err)
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatalf("decode prestate dump failed: %v", err)
	}
	toKey := strings.ToLower(to.Hex())
	toAcc, ok := dump.Result[toKey]
	if !ok {
		t.Fatalf("prestate missing to=%s (key=%s)", to.Hex(), toKey)
	}
	codeStr := strings.TrimSpace(toAcc.Code)
	codeStr = strings.TrimPrefix(codeStr, "0x")
	code, err := hex.DecodeString(codeStr)
	if err != nil {
		t.Fatalf("decode runtime bytecode failed: %v", err)
	}
	if len(code) == 0 {
		t.Fatalf("empty runtime code")
	}

	// Build committed prestate (so GetCommittedState matches on-chain).
	buildCommittedState := func() *state.StateDB {
		db := state.NewDatabaseForTesting()
		st, _ := state.New(types.EmptyRootHash, db)

		// Populate accounts from prestate dump (balances/nonces/code/storage).
		for addrHex, acc := range dump.Result {
			addr := common.HexToAddress(addrHex)
			st.CreateAccount(addr)
			st.SetNonce(addr, acc.Nonce, tracing.NonceChangeUnspecified)
			if acc.Balance != "" {
				b, ok := new(big.Int).SetString(strings.TrimPrefix(acc.Balance, "0x"), 16)
				if !ok {
					t.Fatalf("bad balance in prestate addr=%s balance=%q", addrHex, acc.Balance)
				}
				st.SetBalance(addr, uint256.MustFromBig(b), tracing.BalanceChangeTouchAccount)
			}
			if acc.Code != "" {
				c := strings.TrimPrefix(acc.Code, "0x")
				b, err := hex.DecodeString(c)
				if err != nil {
					t.Fatalf("bad code hex in prestate addr=%s: %v", addrHex, err)
				}
				if len(b) > 0 {
					st.SetCode(addr, b)
				}
			}
			for k, v := range acc.Storage {
				key := common.HexToHash(k)
				val := common.HexToHash(v)
				st.SetState(addr, key, val)
			}
		}

		// Ensure `to` is set to the code we are testing (paranoia).
		st.SetCode(to, code)

		// Accounts touched by fee accounting on BSC/Parlia.
		st.CreateAccount(coinbase)
		// coinbase is included in the dump but ensure it exists even if the dump changes
		// (don't overwrite nonce/balance set from dump).

		st.CreateAccount(consensus.SystemAddress)
		st.SetBalance(consensus.SystemAddress, uint256.NewInt(0), tracing.BalanceChangeTouchAccount)

		// Commit pre-block state (so GetCommittedState matches on-chain).
		root, err := st.Commit(blockNumber.Uint64()-1, false, false)
		if err != nil {
			t.Fatalf("commit prestate failed: %v", err)
		}
		st2, _ := state.New(root, db)
		return st2
	}

	runOnce := func(enableMIR bool) (receipt *types.Receipt, applyErr error, vmErr error, baseSteps []gasStep, mirSteps []gasStep) {
		st := buildCommittedState()
		st.SetTxContext(txHash, 0)

		var hashNs []uint64
		blockCtx := vm.BlockContext{
			CanTransfer: core.CanTransfer,
			Transfer:    core.Transfer,
			Coinbase:    coinbase,
			GetHash: func(n uint64) common.Hash {
				if len(hashNs) < 32 {
					hashNs = append(hashNs, n)
				}
				// Provide the only hash we know we may need (block.number-1).
				// If the contract needs deeper history, extend this map.
				if n == 965 {
					return block965Hash
				}
				return common.Hash{}
			},
			BlockNumber: blockNumber,
			Time:        blockTime,
			Difficulty:  big.NewInt(0),
			GasLimit:    30_000_000,
			BaseFee:     big.NewInt(0),
		}
		var localBaseSteps []gasStep
		var localMirSteps []gasStep
		var localMirPreSteps []gasStep
		// IMPORTANT: Keep the native baseline as close to upstream EVM as possible.
		// In this repo, some MIR-related hooks are gated by EnableOpcodeOptimizations, so we
		// only enable it for MIR runs.
		vmCfg := vm.Config{
			EnableOpcodeOptimizations: enableMIR,
			EnableMIR:                 enableMIR,
		}
		// Optional gas diff tracing (native stream vs MIR stream).
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			// Base: record "gas after charging" to match MIR probe.
			vmCfg.Tracer = &tracing.Hooks{
				OnOpcode: func(pc uint64, op byte, gas uint64, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
					after := gas
					if gas >= cost {
						after = gas - cost
					}
					localBaseSteps = append(localBaseSteps, gasStep{pc: pc, op: op, gas: after, cost: cost})
					// Focused debug for the observed invalid jump path.
					if pc == 1515 && op == 0x34 { // CALLVALUE
						if cv := scope.CallValue(); cv != nil {
							t.Logf("[block966] base CALLVALUE at pc=1515: callValue=%s depth=%d caller=%s addr=%s",
								cv.String(), depth, scope.Caller().Hex(), scope.Address().Hex())
						} else {
							t.Logf("[block966] base CALLVALUE at pc=1515: callValue=nil depth=%d caller=%s addr=%s",
								depth, scope.Caller().Hex(), scope.Address().Hex())
						}
					}
					if pc == 1521 && op == 0x57 { // JUMPI
						stk := scope.StackData()
						if len(stk) >= 2 {
							// Top: dest, Next: cond
							t.Logf("[block966] base JUMPI at pc=1521: dest=%s cond=%s depth=%d",
								stk[len(stk)-1].String(), stk[len(stk)-2].String(), depth)
						} else {
							t.Logf("[block966] base JUMPI at pc=1521: stackTooSmall=%d depth=%d", len(stk), depth)
						}
					}
					if pc == 5304 && op == 0xa1 { // LOG1
						stk := scope.StackData()
						memLen := 0
						if md := scope.MemoryData(); md != nil {
							memLen = len(md)
						}
						// LOG1 pops: mstart, msize, topic1 (topic is top-most at execution time).
						tail := func(n int) string {
							if len(stk) < n {
								return "<short>"
							}
							out := make([]string, 0, n)
							for i := len(stk) - n; i < len(stk); i++ {
								out = append(out, stk[i].String())
							}
							return strings.Join(out, ",")
						}
						t.Logf("[block966] base LOG1 pc=5304 memLen=%d stackTail3=[%s]", memLen, tail(3))
					}
				},
			}
			// MIR: record gasLeft after MIR charging hooks.
			if enableMIR {
				vm.SetMIRGasProbe(func(pc uint64, op byte, gasLeft uint64) {
					localMirSteps = append(localMirSteps, gasStep{pc: pc, op: op, gas: gasLeft})
				})
				vm.SetMIRGasPreProbe(func(pc uint64, op byte, gasLeft uint64, isBlockEntry bool) {
					// We only care about actual EVM op gas before charging; this always runs even if we OOG during charging.
					localMirPreSteps = append(localMirPreSteps, gasStep{pc: pc, op: op, gas: gasLeft})
				})
				// Also record block-entry opcode counts and gas charges to diagnose block-entry over/under-charging.
				var seenBlocks int
				vm.SetMIRBlockEntryCountsProbe(func(firstPC uint, counts map[byte]uint32) {
					if seenBlocks < 5 { // keep logs small
						seenBlocks++
						// focus on stack-only ops which are charged at block-entry if optimized away
						var push, dup, swap, pop uint32
						for opb, c := range counts {
							op := vm.OpCode(opb)
							switch {
							case op == vm.POP:
								pop += c
							case op == vm.PUSH0 || (op >= vm.PUSH1 && op <= vm.PUSH32):
								push += c
							case op >= vm.DUP1 && op <= vm.DUP16:
								dup += c
							case op >= vm.SWAP1 && op <= vm.SWAP16:
								swap += c
							}
						}
						t.Logf("[block966] MIR block-entry counts firstPC=%d push=%d dup=%d swap=%d pop=%d totalOps=%d",
							firstPC, push, dup, swap, pop, len(counts))
					}
				})
			}
		}
		evm := vm.NewEVM(blockCtx, st, params.ChapelChainConfig, vmCfg)
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" && enableMIR {
			defer vm.SetMIRGasProbe(nil)
			defer vm.SetMIRGasPreProbe(nil)
			defer vm.SetMIRBlockEntryCountsProbe(nil)
		}

		header := &types.Header{
			Number:   blockNumber,
			Time:     blockTime,
			Coinbase: coinbase,
			GasLimit: 30_000_000,
			BaseFee:  big.NewInt(0),
		}
		signer := types.MakeSigner(params.ChapelChainConfig, blockNumber, blockTime)
		msg, err := core.TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, err, nil, localBaseSteps, localMirSteps
		}
		// sanity: sender recovered
		if msg.From != sender {
			t.Fatalf("sender mismatch: got=%s want=%s", msg.From, sender)
		}

		gp := new(core.GasPool).AddGas(header.GasLimit)
		// Inline ApplyTransactionWithEVM so we can access ExecutionResult.Err (vm-level error).
		res, err := core.ApplyMessage(evm, msg, gp)
		if err != nil {
			return nil, err, nil, localBaseSteps, localMirSteps
		}
		vmErr = res.Err
		var root []byte
		if evm.ChainConfig().IsByzantium(header.Number) {
			evm.StateDB.Finalise(true)
		} else {
			root = st.IntermediateRoot(evm.ChainConfig().IsEIP158(header.Number)).Bytes()
		}
		receipt = core.MakeReceipt(evm, res, st, header.Number, header.Hash(), header.Time, tx, res.UsedGas, root)
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			if len(hashNs) > 0 {
				t.Logf("[block966] enableMIR=%v BLOCKHASH queries: %v", enableMIR, hashNs)
			} else {
				t.Logf("[block966] enableMIR=%v no BLOCKHASH queries observed", enableMIR)
			}
		}
		// For MIR runs, prefer returning the pre-charge stream (it includes the failing opcode).
		if enableMIR && os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" && len(localMirPreSteps) > 0 {
			return receipt, nil, vmErr, localBaseSteps, localMirPreSteps
		}
		return receipt, nil, vmErr, localBaseSteps, localMirSteps
	}

	// Regression expectation (canonical chain behavior): tx0 succeeds and emits the Pause event.
	//
	// NOTE: MIR currently FAILS (OOG at LOG1 pc=5304 on fullnode). This test is opt-in via
	// MIR_RUN_BLOCK966_TX0=1 so we can iterate without breaking CI.
	baseReceipt, baseApplyErr, baseVMErr, baseSteps, _ := runOnce(false)
	if baseApplyErr != nil {
		t.Fatalf("base ApplyMessage returned error: %v", baseApplyErr)
	}
	if baseReceipt == nil {
		t.Fatalf("nil base receipt (GetHash may be insufficient)")
	}
	if baseReceipt.Status != types.ReceiptStatusSuccessful {
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			t.Logf("[block966] base vmErr=%v gasUsed=%d logCount=%d", baseVMErr, baseReceipt.GasUsed, len(baseReceipt.Logs))
			if n := len(baseSteps); n > 0 {
				start := n - 20
				if start < 0 {
					start = 0
				}
				t.Logf("[block966] base last %d opcodes:", n-start)
				for i := start; i < n; i++ {
					t.Logf("  base i=%d pc=%d op=0x%x gasAfter=%d cost=%d", i, baseSteps[i].pc, baseSteps[i].op, baseSteps[i].gas, baseSteps[i].cost)
				}
			}
		}
		t.Fatalf("base tx failed: status=%d gasUsed=%d logs=%d", baseReceipt.Status, baseReceipt.GasUsed, len(baseReceipt.Logs))
	}

	mirReceipt, mirApplyErr, mirVMErr, _, mirSteps := runOnce(true)
	if mirReceipt == nil {
		t.Fatalf("nil MIR receipt")
	}
	if mirReceipt.Status != types.ReceiptStatusSuccessful {
		if os.Getenv("MIR_DEBUG_GASDIFF_966") == "1" {
			dumpFirstGasLeftDiff966(t, baseSteps, mirSteps)
			// Now that MIR stream is "pre-charge", diff basePre vs mirPre to locate where MIR starts overcharging.
			dumpFirstPreGasDrift966(t, baseSteps, mirSteps)
			// Also show a small window around LOG1 (pc=5304) in the base trace.
			find := func(steps []gasStep, pc uint64, op byte) int {
				for i := range steps {
					if steps[i].pc == pc && steps[i].op == op {
						return i
					}
				}
				return -1
			}
			const logPC = uint64(5304)
			const logOp = byte(0xa1)
			bi := find(baseSteps, logPC, logOp)
			mi := find(mirSteps, logPC, logOp)
			if bi >= 0 {
				start := bi - 10
				if start < 0 {
					start = 0
				}
				end := bi + 5
				if end > len(baseSteps)-1 {
					end = len(baseSteps) - 1
				}
				t.Logf("[block966] base trace around LOG1 pc=%d:", logPC)
				for i := start; i <= end; i++ {
					t.Logf("  base i=%d pc=%d op=0x%x gasAfter=%d cost=%d", i, baseSteps[i].pc, baseSteps[i].op, baseSteps[i].gas, baseSteps[i].cost)
				}
			} else {
				t.Logf("[block966] base trace does not contain pc=%d op=0x%x (len=%d)", logPC, logOp, len(baseSteps))
			}
			if mi >= 0 {
				start := mi - 10
				if start < 0 {
					start = 0
				}
				end := mi + 5
				if end > len(mirSteps)-1 {
					end = len(mirSteps) - 1
				}
				t.Logf("[block966] MIR probe around LOG1 pc=%d:", logPC)
				for i := start; i <= end; i++ {
					t.Logf("  mir  i=%d pc=%d op=0x%x gasAfter=%d", i, mirSteps[i].pc, mirSteps[i].op, mirSteps[i].gas)
				}
			} else {
				t.Logf("[block966] MIR probe does not contain pc=%d op=0x%x (len=%d)", logPC, logOp, len(mirSteps))
			}
			t.Logf("[block966] MIR vmErr=%v gasUsed=%d logCount=%d", mirVMErr, mirReceipt.GasUsed, len(mirReceipt.Logs))
		}
		t.Fatalf("MIR tx failed: status=%d gasUsed=%d logs=%d", mirReceipt.Status, mirReceipt.GasUsed, len(mirReceipt.Logs))
	}
	if mirApplyErr != nil {
		t.Fatalf("MIR ApplyMessage returned error: %v", mirApplyErr)
	}
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")
	if len(mirReceipt.Logs) != 1 || len(mirReceipt.Logs[0].Topics) != 1 || mirReceipt.Logs[0].Topics[0] != wantTopic0 {
		t.Fatalf("MIR logs mismatch: logs=%d topic0=%v wantTopic0=%s", len(mirReceipt.Logs), func() common.Hash {
			if len(mirReceipt.Logs) == 0 || len(mirReceipt.Logs[0].Topics) == 0 {
				return common.Hash{}
			}
			return mirReceipt.Logs[0].Topics[0]
		}(), wantTopic0)
	}
}


