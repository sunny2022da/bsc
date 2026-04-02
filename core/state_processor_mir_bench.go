package core

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	mir "github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler/MIR"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
)

// mirBenchTxResult holds the per-transaction timing outcome for one benchmarked tx.
type mirBenchTxResult struct {
	txHash  common.Hash
	txIdx   int
	mirNs   int64 // MIR execution time in nanoseconds
	baseNs  int64 // stock interpreter execution time in nanoseconds
	gasUsed uint64
}

// mirBenchBlockStats accumulates block-level benchmark statistics.
type mirBenchBlockStats struct {
	benchmarked int     // txs where MIR ran without fallback (both timings recorded)
	fallback    int     // txs where MIR fell back (only MIR/fallback time recorded)
	totalMirNs  int64   // total MIR nanoseconds (benchmarked txs only)
	totalBaseNs int64   // total stock interp nanoseconds (benchmarked txs only)
}

// mirBenchmarkTx executes one transaction under the MIR benchmark harness.
//
// When MIR runs without fallback the tx is executed three times:
//  1. Timing run via MIR    (state reverted afterward)
//  2. Timing run via stock  (state reverted afterward)
//  3. Real run via MIR      (state kept, receipt returned)
//
// When MIR falls back the tx is executed twice:
//  1. Probe/timing run via MIR (same as real run since fallback == stock; state reverted)
//  2. Real run via MIR         (state kept, receipt returned)
//
// The real receipt/error are always returned. Timing results are appended to stats.
func mirBenchmarkTx(
	mirEVM *vm.EVM,
	msg *Message,
	gp *GasPool,
	statedb *state.StateDB,
	blockNumber *big.Int,
	blockHash common.Hash,
	blockTime uint64,
	tx *types.Transaction,
	txIdx int,
	usedGas *uint64,
	bloomProcessors []ReceiptProcessor,
	stats *mirBenchBlockStats,
) (*types.Receipt, error) {

	// ── Snapshot state and gas pool before this tx ──────────────────────────
	snap := statedb.Snapshot()
	preGas := gp.Gas()

	// ── MIR probe/timing run ─────────────────────────────────────────────────
	gpMIR := new(GasPool).AddGas(preGas)
	var dummyUsedGas uint64
	statedb.SetTxContext(tx.Hash(), txIdx)
	mirStart := time.Now()
	_, _ = ApplyTransactionWithEVM(msg, gpMIR, statedb, blockNumber, blockHash, blockTime, tx, &dummyUsedGas, mirEVM)
	mirNs := time.Since(mirStart).Nanoseconds()

	// Determine if MIR actually ran (no fallback).
	runner, _ := mirEVM.GetMIRRunner().(*mir.EVMRunner)
	usedMIR := runner != nil && !runner.FellBack()

	// Always revert; the real run below is authoritative.
	statedb.RevertToSnapshot(snap)

	var baseNs int64
	if usedMIR {
		// ── Stock interpreter shadow timing run ──────────────────────────────
		stockCfg := mirEVM.Config
		stockCfg.EnableMIR = false
		stockCfg.MIRBenchmark = false
		stockEVM := vm.NewEVM(mirEVM.Context, statedb, mirEVM.ChainConfig(), stockCfg)

		gpBase := new(GasPool).AddGas(preGas)
		var dummyUsedGas2 uint64
		statedb.SetTxContext(tx.Hash(), txIdx)
		baseStart := time.Now()
		_, _ = ApplyTransactionWithEVM(msg, gpBase, statedb, blockNumber, blockHash, blockTime, tx, &dummyUsedGas2, stockEVM)
		baseNs = time.Since(baseStart).Nanoseconds()

		statedb.RevertToSnapshot(snap)

		// Accumulate block stats.
		stats.benchmarked++
		stats.totalMirNs += mirNs
		stats.totalBaseNs += baseNs

		// Log per-tx result.
		var speedupPct float64
		if baseNs > 0 {
			speedupPct = float64(baseNs-mirNs) / float64(baseNs) * 100
		}
		log.Info("MIR bench tx",
			"block", blockNumber,
			"txIdx", txIdx,
			"txHash", tx.Hash(),
			"mir_ns", mirNs,
			"base_ns", baseNs,
			"speedup_pct", speedupPct,
		)
	} else {
		stats.fallback++
		log.Info("MIR bench tx (fallback)",
			"block", blockNumber,
			"txIdx", txIdx,
			"txHash", tx.Hash(),
			"mir_ns", mirNs,
		)
	}

	// ── Real run (authoritative, state kept) ────────────────────────────────
	statedb.SetTxContext(tx.Hash(), txIdx)
	return ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, blockTime, tx, usedGas, mirEVM, bloomProcessors...)
}

// mirBenchLogBlock logs the block-level benchmark summary.
func mirBenchLogBlock(blockNumber *big.Int, stats *mirBenchBlockStats) {
	if stats.benchmarked == 0 && stats.fallback == 0 {
		return
	}
	var blockSpeedupPct float64
	if stats.totalBaseNs > 0 {
		blockSpeedupPct = float64(stats.totalBaseNs-stats.totalMirNs) / float64(stats.totalBaseNs) * 100
	}
	log.Info("MIR bench block summary",
		"block", blockNumber,
		"benchmarked_txs", stats.benchmarked,
		"fallback_txs", stats.fallback,
		"total_mir_ns", stats.totalMirNs,
		"total_base_ns", stats.totalBaseNs,
		"block_speedup_pct", blockSpeedupPct,
	)
}
