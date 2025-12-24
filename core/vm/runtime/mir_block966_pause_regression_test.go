package runtime_test

import (
	"encoding/hex"
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
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Regression test for Chapel block 966 tx0:
// 0x51a2684dff1919c2dc9401b24d907cacdb35087acc16fcde95e9a1351509a25b
//
// Native receipt: status=1, gasUsed=0x3a34 (14900), logs[0].topic0=0x7805862f...
//
// Historically MIR diverged here during full sync (Parlia "System tx hash mismatch")
// because MIR treated tx0 as OOG and consumed the full gasLimit (0x7468=29800),
// doubling the SystemAddress fee pot and thus the system-reward tx value.
func TestMIR_Block966_Pause_GasAndLogsParity(t *testing.T) {
	compiler.EnableOpcodeParse()

	// Load the real on-chain runtime bytecode (captured via prestateTracer).
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

	// Chapel block 966 tx0 parameters.
	blockNumber := big.NewInt(966)
	contractAddr := common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")
	gasLimit := uint64(0x7468) // 29800
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16) // 27 gwei
	value := big.NewInt(0)

	// calldata: selector 0x3f4ba83a (pause())
	input := common.Hex2Bytes("3f4ba83a")

	// Build base/native EVM env.
	baseCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    gasLimit,
		Origin:      sender,
		GasPrice:    gasPrice,
		BlockNumber: blockNumber,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true},
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
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
		},
	}
	if baseCfg.State == nil {
		baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}
	if mirCfg.State == nil {
		mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	}

	// Install identical prestate (from prestateTracer) into both states.
	// - contract nonce=1, storage slot4=owner, slot5=flags (nonzero)
	// - sender balance high, nonce=20
	// - coinbase nonce=8 (not needed for this direct call, but matches captured state)
	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	for _, st := range []*state.StateDB{baseCfg.State, mirCfg.State} {
		st.CreateAccount(coinbase)
		st.SetNonce(coinbase, 8, tracing.NonceChangeUnspecified)

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
	}

	evmBase := runtime.NewEnv(baseCfg)
	evmMIR := runtime.NewEnv(mirCfg)

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
		if errBase.Error() != errMIR.Error() {
			t.Fatalf("error message mismatch base=%q mir=%q (lastMIRPC=%d)", errBase.Error(), errMIR.Error(), lastMIRPC)
		}
		return
	}

	if leftBase != leftMIR {
		t.Fatalf("gasLeft mismatch base=%d mir=%d (gasUsed base=%d mir=%d)",
			leftBase, leftMIR, gasLimit-leftBase, gasLimit-leftMIR)
	}
	if got, want := gasLimit-leftBase, uint64(0x3a34); got != want {
		t.Fatalf("unexpected base gasUsed=%d want=%d (sanity check against native receipt)", got, want)
	}
	if !strings.EqualFold(hex.EncodeToString(retBase), hex.EncodeToString(retMIR)) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retBase, retMIR)
	}

	// The critical consensus signal: Pause log must be present.
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")

	logsBase := baseCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	logsMIR := mirCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)

	if len(logsBase) != 1 {
		t.Fatalf("base logs mismatch: got %d want %d", len(logsBase), 1)
	}
	if len(logsMIR) != 1 {
		t.Fatalf("mir logs mismatch: got %d want %d", len(logsMIR), 1)
	}
	if logsBase[0].Address != contractAddr || logsMIR[0].Address != contractAddr {
		t.Fatalf("log address mismatch base=%s mir=%s want=%s", logsBase[0].Address, logsMIR[0].Address, contractAddr)
	}
	if len(logsBase[0].Topics) != 1 || len(logsMIR[0].Topics) != 1 {
		t.Fatalf("log topics len mismatch base=%d mir=%d want=1", len(logsBase[0].Topics), len(logsMIR[0].Topics))
	}
	if logsBase[0].Topics[0] != wantTopic0 {
		t.Fatalf("base topic0 mismatch got=%s want=%s", logsBase[0].Topics[0], wantTopic0)
	}
	if logsMIR[0].Topics[0] != wantTopic0 {
		t.Fatalf("mir topic0 mismatch got=%s want=%s", logsMIR[0].Topics[0], wantTopic0)
	}
	if !strings.EqualFold(hex.EncodeToString(logsBase[0].Data), hex.EncodeToString(logsMIR[0].Data)) {
		t.Fatalf("log data mismatch base=%x mir=%x", logsBase[0].Data, logsMIR[0].Data)
	}
}

// Tx-level regression for Chapel block 966 tx0 fee accounting.
// This runs a full state transition (intrinsic gas, refunds, returnGas, fee credit),
// and asserts that the SystemAddress fee pot matches between native EVM and MIR.
func TestMIR_Block966_Tx0_SystemFeeParity(t *testing.T) {
	if os.Getenv("MIR_RUN_BLOCK966_TX_TEST") != "1" {
		t.Skip("skipping tx-level block966 test by default; set MIR_RUN_BLOCK966_TX_TEST=1 to run")
	}
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
	blockTime := uint64(0x5f06d951)
	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	contractAddr := common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")

	gasLimit := uint64(0x7468) // 29800
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16)
	value := big.NewInt(0)
	input := common.Hex2Bytes("3f4ba83a")

	// Create unsigned tx object for receipt/log indexing only; execution is driven by `msg`.
	// Use the real on-chain signature (v/r/s) so tx.Hash matches the canonical one
	// and our MIR_TRACE_BLOCK966 instrumentation in core.ApplyTransactionWithEVM can trigger.
	v := new(big.Int)
	v.SetString("e5", 16)
	r := new(big.Int)
	r.SetString("a2442ecaa716d164f7a09a68a520b93e7898f737f1ea1b22feb871716c5abd4d", 16)
	s := new(big.Int)
	s.SetString("24691a3482ee9fa3aec735ac37eb0ef8d001d234a902d80cf76ae892cca2e31a", 16)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    20,
		To:       &contractAddr,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     input,
		V:        v,
		R:        r,
		S:        s,
	})
	if got, want := tx.Hash(), common.HexToHash("0x51a2684dff1919c2dc9401b24d907cacdb35087acc16fcde95e9a1351509a25b"); got != want {
		t.Fatalf("tx hash mismatch in test setup: got=%s want=%s", got, want)
	}

	makeCfg := func(enableMIR bool) *runtime.Config {
		cfg := &runtime.Config{
			ChainConfig: params.ChapelChainConfig,
			Difficulty:  big.NewInt(0),
			Origin:      sender,
			Coinbase:    coinbase,
			BlockNumber: blockNumber,
			Time:        blockTime,
			GasLimit:    30_000_000,
			GasPrice:    gasPrice,
			Value:       value,
			BaseFee:     big.NewInt(0),
			EVMConfig: vm.Config{
				EnableOpcodeOptimizations: true,
				EnableMIR:                 enableMIR,
			},
		}
		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		// prestate
		cfg.State.CreateAccount(consensus.SystemAddress)
		cfg.State.CreateAccount(coinbase)
		cfg.State.SetNonce(coinbase, 8, tracing.NonceChangeUnspecified)

		cfg.State.CreateAccount(sender)
		cfg.State.SetNonce(sender, 20, tracing.NonceChangeUnspecified)
		bal := new(big.Int)
		bal.SetString("1030d9a9661396fe00", 16)
		cfg.State.SetBalance(sender, uint256.MustFromBig(bal), tracing.BalanceChangeTouchAccount)

		cfg.State.CreateAccount(contractAddr)
		cfg.State.SetNonce(contractAddr, 1, tracing.NonceChangeUnspecified)
		cfg.State.SetCode(contractAddr, code)
		cfg.State.SetState(contractAddr,
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"),
			common.HexToHash("0x000000000000000000000000fa5e36a04eef3152092099f352ddbe88953bb540"),
		)
		cfg.State.SetState(contractAddr,
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),
			common.HexToHash("0x0000000000000000000000010000000000000000000000000000000000000000"),
		)
		return cfg
	}

	baseCfg := makeCfg(false)
	mirCfg := makeCfg(true)

	evmBase := runtime.NewEnv(baseCfg)
	evmMIR := runtime.NewEnv(mirCfg)

	msg := &core.Message{
		From:       sender,
		To:         &contractAddr,
		Nonce:      20,
		Value:      value,
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
		GasFeeCap:  gasPrice,
		GasTipCap:  gasPrice,
		Data:       input,
		AccessList: nil,
	}

	var (
		usedGasBase uint64
		usedGasMIR  uint64
	)
	gpBase := new(core.GasPool).AddGas(30_000_000)
	gpMIR := new(core.GasPool).AddGas(30_000_000)

	receiptBase, errBase := core.ApplyTransactionWithEVM(msg, gpBase, baseCfg.State, blockNumber, common.Hash{}, blockTime, tx, &usedGasBase, evmBase)
	receiptMIR, errMIR := core.ApplyTransactionWithEVM(msg, gpMIR, mirCfg.State, blockNumber, common.Hash{}, blockTime, tx, &usedGasMIR, evmMIR)

	if (errBase != nil) != (errMIR != nil) {
		t.Fatalf("error mismatch base=%v mir=%v", errBase, errMIR)
	}
	if errBase != nil {
		if errBase.Error() != errMIR.Error() {
			t.Fatalf("error message mismatch base=%q mir=%q", errBase.Error(), errMIR.Error())
		}
		return
	}

	if receiptBase.GasUsed != receiptMIR.GasUsed {
		t.Fatalf("receipt gasUsed mismatch base=%d mir=%d", receiptBase.GasUsed, receiptMIR.GasUsed)
	}
	if got, want := receiptBase.GasUsed, uint64(0x3a34); got != want {
		t.Fatalf("unexpected base receipt gasUsed=%d want=%d (sanity check against native receipt)", got, want)
	}

	feeBase := new(uint256.Int).SetUint64(receiptBase.GasUsed)
	feeBase.Mul(feeBase, uint256.MustFromBig(gasPrice))
	sysBalBase := baseCfg.State.GetBalance(consensus.SystemAddress)
	sysBalMIR := mirCfg.State.GetBalance(consensus.SystemAddress)

	if sysBalBase.Cmp(feeBase) != 0 {
		t.Fatalf("base SystemAddress balance unexpected: got=%s want=%s", sysBalBase, feeBase)
	}
	if sysBalMIR.Cmp(sysBalBase) != 0 {
		t.Fatalf("SystemAddress balance mismatch base=%s mir=%s", sysBalBase, sysBalMIR)
	}

	// Also ensure log parity at tx-level (receipt logs are sourced via tx.Hash()).
	if receiptBase.Status != receiptMIR.Status {
		t.Fatalf("receipt status mismatch base=%d mir=%d", receiptBase.Status, receiptMIR.Status)
	}
	if len(receiptBase.Logs) != 1 || len(receiptMIR.Logs) != 1 {
		t.Fatalf("receipt logs len mismatch base=%d mir=%d want=1", len(receiptBase.Logs), len(receiptMIR.Logs))
	}
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")
	if receiptBase.Logs[0].Topics[0] != wantTopic0 || receiptMIR.Logs[0].Topics[0] != wantTopic0 {
		t.Fatalf("receipt topic0 mismatch base=%s mir=%s want=%s", receiptBase.Logs[0].Topics[0], receiptMIR.Logs[0].Topics[0], wantTopic0)
	}
}

// Reproduce Chapel block 966 tx0 divergence under MIR without fullnode restarts.
//
// In block processing, tx0 has gasLimit=29800 and calldata len=4.
// Intrinsic gas (with current params) is 21064, leaving 8736 for EVM execution.
//
// NativeEVM succeeds. MIR currently overcharges ~94 gas somewhere before LOG1 (pc=5304),
// so it hits OOG at LOG1 and tx0 becomes invalid -> Parlia system-tx mismatch.
func TestMIR_Block966_Pause_TightGas_LOG1_OOG_Repro(t *testing.T) {
	compiler.EnableOpcodeParse()

	// Load runtime bytecode captured via prestateTracer.
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
	gasLimitTx := uint64(0x7468) // 29800
	value := big.NewInt(0)
	input := common.Hex2Bytes("3f4ba83a") // pause()

	// Call gas passed into EVM execution during block processing for this tx appears to be the full tx gasLimit.
	callGas := gasLimitTx

	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16) // 27 gwei

	baseCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    callGas,
		Origin:      sender,
		GasPrice:    gasPrice,
		BlockNumber: blockNumber,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig:   vm.Config{EnableOpcodeOptimizations: true},
	}
	mirCfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		GasLimit:    callGas,
		Origin:      sender,
		GasPrice:    gasPrice,
		BlockNumber: blockNumber,
		Value:       value,
		BaseFee:     big.NewInt(0),
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
		},
	}
	baseCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	mirCfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())

	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	for _, st := range []*state.StateDB{baseCfg.State, mirCfg.State} {
		st.CreateAccount(coinbase)
		st.SetNonce(coinbase, 8, tracing.NonceChangeUnspecified)

		st.CreateAccount(sender)
		st.SetNonce(sender, 20, tracing.NonceChangeUnspecified)
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
	}

	evmBase := runtime.NewEnv(baseCfg)
	evmMIR := runtime.NewEnv(mirCfg)

	retBase, leftBase, errBase := evmBase.Call(sender, contractAddr, input, callGas, uint256.MustFromBig(value))
	retMIR, leftMIR, errMIR := evmMIR.Call(sender, contractAddr, input, callGas, uint256.MustFromBig(value))

	// Native should succeed; MIR currently fails with OOG at LOG1. If this ever changes,
	// we keep strict parity assertions.
	if errBase != nil {
		t.Fatalf("base unexpected error: %v", errBase)
	}
	if errMIR != nil {
		t.Fatalf("mir error: %v (leftBase=%d leftMIR=%d retBaseLen=%d retMIRLen=%d)",
			errMIR, leftBase, leftMIR, len(retBase), len(retMIR))
	}

	// If both succeed, enforce full parity.
	if leftBase != leftMIR {
		t.Fatalf("gasLeft mismatch base=%d mir=%d (callGas=%d)", leftBase, leftMIR, callGas)
	}
	if !strings.EqualFold(hex.EncodeToString(retBase), hex.EncodeToString(retMIR)) {
		t.Fatalf("returndata mismatch base=%x mir=%x", retBase, retMIR)
	}
	// log parity (Paused topic)
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")
	logsBase := baseCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	logsMIR := mirCfg.State.GetLogs(common.Hash{}, blockNumber.Uint64(), common.Hash{}, 0)
	if len(logsBase) != 1 || len(logsMIR) != 1 {
		t.Fatalf("logs len mismatch base=%d mir=%d", len(logsBase), len(logsMIR))
	}
	if logsBase[0].Topics[0] != wantTopic0 || logsMIR[0].Topics[0] != wantTopic0 {
		t.Fatalf("topic0 mismatch base=%s mir=%s want=%s", logsBase[0].Topics[0], logsMIR[0].Topics[0], wantTopic0)
	}
}

// Full-tx style regression harness (MIR-only) for block 966 tx0.
//
// This mirrors fullnode execution more closely than a raw `evm.Call`, and is intended
// to reproduce the same LOG1 OOG seen on the MIR fullnode without node restarts.
func TestMIR_Block966_Tx0_MIROnly_ShouldSucceed(t *testing.T) {
	compiler.EnableOpcodeParse()
	t.Setenv("MIR_TRACE_BLOCK966", "1")

	// tx0 fields from native node:
	// gas=0x7468, gasPrice=0x649534e00, input=0x3f4ba83a, nonce=0x14, v/r/s known.
	blockNumber := big.NewInt(966)
	blockTime := uint64(0x5f06d951)
	blockGasLimit := uint64(0x1c9c380)

	coinbase := common.HexToAddress("0x1284214b9b9c85549aB3D2b972df0dEEf66aC2c9")
	contractAddr := common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	sender := common.HexToAddress("0xfa5e36a04eef3152092099f352ddbe88953bb540")

	gasLimitTx := uint64(0x7468) // 29800
	gasPrice := new(big.Int)
	gasPrice.SetString("649534e00", 16)
	value := big.NewInt(0)
	input := common.Hex2Bytes("3f4ba83a")

	// Construct tx with real signature so tx hash matches.
	v := new(big.Int)
	v.SetString("e5", 16)
	r := new(big.Int)
	r.SetString("a2442ecaa716d164f7a09a68a520b93e7898f737f1ea1b22feb871716c5abd4d", 16)
	s := new(big.Int)
	s.SetString("24691a3482ee9fa3aec735ac37eb0ef8d001d234a902d80cf76ae892cca2e31a", 16)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    20,
		To:       &contractAddr,
		Value:    value,
		Gas:      gasLimitTx,
		GasPrice: gasPrice,
		Data:     input,
		V:        v,
		R:        r,
		S:        s,
	})

	// Build state from prestate tracer output (accounts: coinbase, sender, contract).
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(coinbase)
	statedb.SetNonce(coinbase, 8, tracing.NonceChangeUnspecified)

	statedb.CreateAccount(sender)
	statedb.SetNonce(sender, 20, tracing.NonceChangeUnspecified)
	bal := new(big.Int)
	bal.SetString("1030d9a9661396fe00", 16)
	statedb.SetBalance(sender, uint256.MustFromBig(bal), tracing.BalanceChangeTouchAccount)

	// Contract code from captured prestate tracer.
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
	statedb.CreateAccount(contractAddr)
	statedb.SetNonce(contractAddr, 1, tracing.NonceChangeUnspecified)
	statedb.SetCode(contractAddr, code)
	statedb.SetState(contractAddr,
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"),
		common.HexToHash("0x000000000000000000000000fa5e36a04eef3152092099f352ddbe88953bb540"),
	)
	statedb.SetState(contractAddr,
		common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),
		common.HexToHash("0x0000000000000000000000010000000000000000000000000000000000000000"),
	)

	// Create an EVM env with MIR enabled. Use opcode optimizations to match the fullnode default.
	cfg := &runtime.Config{
		ChainConfig: params.ChapelChainConfig,
		Origin:      sender,
		Coinbase:    coinbase,
		BlockNumber: blockNumber,
		Time:        blockTime,
		GasLimit:    blockGasLimit,
		GasPrice:    gasPrice,
		Value:       value,
		BaseFee:     big.NewInt(0),
		State:       statedb,
		EVMConfig: vm.Config{
			EnableOpcodeOptimizations: true,
			EnableMIR:                 true,
		},
	}
	evm := runtime.NewEnv(cfg)

	header := &types.Header{
		Number:   blockNumber,
		Time:     blockTime,
		Coinbase: coinbase,
		GasLimit: blockGasLimit,
		BaseFee:  big.NewInt(0),
	}
	gp := new(core.GasPool).AddGas(blockGasLimit)
	var usedGas uint64

	// Set tx context so logs are indexed deterministically.
	statedb.SetTxContext(tx.Hash(), 0)

	receipt, err := core.ApplyTransaction(evm, gp, statedb, header, tx, &usedGas)
	if err != nil {
		t.Fatalf("MIR ApplyTransaction failed: %v", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("receipt status unexpected: got=%d want=%d", receipt.Status, types.ReceiptStatusSuccessful)
	}
	if len(receipt.Logs) != 1 {
		t.Fatalf("receipt logs len mismatch: got=%d want=1", len(receipt.Logs))
	}
	wantTopic0 := common.HexToHash("0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33")
	if receipt.Logs[0].Topics[0] != wantTopic0 {
		t.Fatalf("receipt topic0 mismatch got=%s want=%s", receipt.Logs[0].Topics[0], wantTopic0)
	}
}


