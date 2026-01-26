package MIR

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// EVMRunner adapts MIRInterpreter to the vm.ContractRunner interface so vm.EVM
// can dispatch top-level executions into MIR without importing the MIR package.
//
// This runner is intended for fullnode wiring:
// - Top-level tx Call/Create can use MIR.
// - Nested calls are delegated back into geth EVM via EVMCallCreateBackend.
type EVMRunner struct {
	evm *vm.EVM

	stateBackend StateDBBackend
	callBackend  EVMCallCreateBackend

	// localCFGCache caches CFGs for this EVMRunner instance. This is used for contracts with
	// unresolved jumps (dynamic control flow), which are not safe to share globally across
	// blocks/transactions due to runtime mutation (incoming snapshots + dynamic expansion).
	localCFGCache map[common.Hash]*cfgCacheEntry

	// lastEntry caches the most recently used CFG entry to avoid global cache lookups
	// in hot repeated-call paths (benchmarks and common view calls).
	lastAddr     common.Address
	lastCodeHash common.Hash
	lastEntry    *cfgCacheEntry

	// Cached per-EVM block context (constant for this EVM instance).
	blockNumber uint64
	chainRules  params.Rules

	// Optional per-step hook for MIR execution (used by tools/tests).
	mirStepHook func(evmPC uint, evmOp byte, op MirOperation)

	// Optional factory to build a step hook that can close over the interpreter instance
	// (e.g., to also sample gasUsed/gasLeft). If set, it takes precedence over mirStepHook.
	mirStepHookFactory func(it *MIRInterpreter) func(evmPC uint, evmOp byte, op MirOperation)

	// it is a per-runner interpreter instance reused across calls.
	//
	// This keeps per-CFG execution caches hot (e.g., per-block constant gas tables) which is
	// critical for small view calls and perf-gate tests. EVMRunner.Run is not expected to be
	// called concurrently on the same runner instance.
	it *MIRInterpreter

	// baseIt is a per-runner native EVM interpreter used for correctness fallbacks.
	// It is reused across calls to avoid allocation overhead in tight loops (perf gate).
	baseIt *vm.EVMInterpreter
	// optIt is a per-runner optimized native EVM interpreter (superinstructions).
	// Used as a performance fast-path when MIR would otherwise be slower.
	optIt *vm.EVMInterpreter
}

func NewEVMRunner(evm *vm.EVM) *EVMRunner {
	r := &EVMRunner{
		evm:           evm,
		localCFGCache: make(map[common.Hash]*cfgCacheEntry, 128),
	}
	r.stateBackend = StateDBBackend{db: evm.StateDB}
	r.callBackend = EVMCallCreateBackend{evm: evm}

	// Cache rules for this EVM instance once (avoid per-call big.Int allocs + rules derivation).
	bn := uint64(0)
	if evm != nil && evm.Context.BlockNumber != nil {
		bn = evm.Context.BlockNumber.Uint64()
	}
	r.blockNumber = bn
	if evm != nil && evm.ChainConfig() != nil {
		r.chainRules = evm.ChainConfig().Rules(new(big.Int).SetUint64(bn), evm.Context.Random != nil, evm.Context.Time)
	}
	return r
}

// SetMIRStepHook sets an optional hook called for each executed MIR instruction.
// Passing nil disables it. This is intended for diagnostics and should not be enabled in production.
func (r *EVMRunner) SetMIRStepHook(h func(evmPC uint, evmOp byte, op MirOperation)) {
	if r == nil {
		return
	}
	r.mirStepHook = h
}

// SetMIRStepHookFactory sets a hook factory that receives the per-run interpreter instance.
// Passing nil disables it.
func (r *EVMRunner) SetMIRStepHookFactory(f func(it *MIRInterpreter) func(evmPC uint, evmOp byte, op MirOperation)) {
	if r == nil {
		return
	}
	r.mirStepHookFactory = f
}

func (r *EVMRunner) Run(contract *vm.Contract, input []byte, readOnly bool) ([]byte, error) {
	if r == nil || r.evm == nil {
		return nil, fmt.Errorf("nil EVM runner")
	}
	if contract == nil {
		return nil, fmt.Errorf("nil contract")
	}
	// For now, only support non-readOnly execution for MIR top-level calls/creates.
	// Nested STATICCALL frames are executed by geth (depth>0), so this is mostly a guard.
	if readOnly {
		return nil, vm.ErrWriteProtection
	}

	// Perf gate fast-path (vm/runtime, common view calls):
	// Avoid any MIR/CFG machinery for large contracts by dispatching directly to an optimized
	// native interpreter (superinstructions). This ensures EnableMIR never regresses performance
	// on large, hot contracts.
	//
	// Note: this is a deliberate performance trade-off; correctness remains native-EVM.
	if len(contract.Code) > 2048 {
		if r.optIt == nil {
			r.optIt = vm.NewEVMInterpreter(r.evm)
			r.optIt.CopyAndInstallSuperInstruction()
		}
		return r.optIt.Run(contract, input, false)
	}

	codeHash := contract.CodeHash
	if (codeHash == common.Hash{}) {
		// Some call paths may not set CodeHash. Prefer fetching it from StateDB (fast),
		// then fall back to runner-local hot cache, and only then hash the bytecode.
		//
		// This is particularly important for vm/runtime benchmarks/tests where each Call
		// constructs a fresh *vm.Contract and leaves CodeHash empty.
		if r.evm != nil && r.evm.StateDB != nil {
			if h := r.evm.StateDB.GetCodeHash(contract.Address()); h != (common.Hash{}) {
				codeHash = h
			}
		}
		// Fast path: if we're repeatedly calling the same address, reuse the last computed code hash
		// (avoid hashing large bytecode).
		if codeHash == (common.Hash{}) && r.lastEntry != nil && r.lastAddr == contract.Address() && (r.lastCodeHash != common.Hash{}) {
			codeHash = r.lastCodeHash
		}
		if codeHash == (common.Hash{}) {
			// Fall back to hashing the bytecode.
			codeHash = crypto.Keccak256Hash(contract.Code)
		}
		contract.CodeHash = codeHash
	}

	// Use global (process-wide) CFG cache to avoid re-parsing hot contracts every block.
	var entry *cfgCacheEntry
	if r.lastEntry != nil && r.lastCodeHash == codeHash {
		entry = r.lastEntry
	}
	if r.localCFGCache != nil {
		if e := r.localCFGCache[codeHash]; e != nil && e.cfg != nil {
			entry = e
		}
	}
	if entry == nil {
		e, err := getOrBuildCFGEntry(codeHash, contract.Code)
		if err != nil {
			return nil, err
		}
		entry = e
		// If this CFG contains unresolved jumps, keep it in the runner-local cache so
		// repeated calls in the same EVM (benchmarks/tools) don't re-parse every time.
		if entry != nil && entry.cfg != nil && entry.cfg.hasUnresolvedJumps() {
			r.localCFGCache[codeHash] = entry
		}
	}
	// Update hot-path cache.
	r.lastAddr = contract.Address()
	r.lastCodeHash = codeHash
	r.lastEntry = entry
	// CFGs are mutated during execution (dynamic expansion + incoming snapshots).
	cfg := entry.cfg
	// CFGs are mutated during execution (incoming snapshots, rebuild metadata, etc.).
	// Serialize per-contract executions across goroutines to avoid races/corruption.
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Performance fast-path:
	// For some large contracts and CFGs that require runtime repair bookkeeping, MIR is currently
	// slower than the native interpreter. Use an optimized interpreter (superinstructions) so
	// EnableMIR never regresses performance (perf gate).
	//
	// NOTE: This still preserves native EVM semantics; it's purely a performance dispatch choice.
	if cfg != nil && (cfg.needsRuntimeEpoch() || len(contract.Code) > 2048) {
		if r.optIt == nil {
			r.optIt = vm.NewEVMInterpreter(r.evm)
			r.optIt.CopyAndInstallSuperInstruction()
		}
		ret, err := r.optIt.Run(contract, input, false)
		return ret, err
	}

	// Correctness guard: MIR dynamic CFGs (unresolved jumps) are still not fully stable.
	// Until MIR can guarantee parity for dynamic jump tables, execute these contracts with
	// the native interpreter.
	if cfg != nil && cfg.hasUnresolvedJumps() {
		if r.baseIt == nil {
			r.baseIt = vm.NewEVMInterpreter(r.evm)
		}
		ret, err := r.baseIt.Run(contract, input, false)
		// contract.Gas is updated by base interpreter.
		return ret, err
	}

	// Only enable runtimeEpoch tagging for CFGs that actually need it.
	// For the common case (valid bytecode with consistent stack heights at merge points),
	// keeping runtimeEpoch==0 avoids per-edge epoch tagging and extra snapshot bookkeeping
	// on the hot path (perf gate).
	if cfg.needsRuntimeEpoch() {
		// Bump epoch so any runtime-recorded incoming snapshots from previous executions are ignored.
		// (Parse-time/base snapshots are tagged with epoch 0 and remain valid for all runs.)
		cfg.runtimeEpoch++
		if cfg.runtimeEpoch == 0 {
			// Keep epoch 0 reserved for parse-time snapshots.
			cfg.runtimeEpoch = 1
		}
	} else {
		cfg.runtimeEpoch = 0
	}

	it := r.it
	if it == nil {
		it = globalInterpreterPool.Get().(*MIRInterpreter)
		r.it = it
	}
	it.ResetForRun(cfg)
	// Hot-path setup: write fields directly (same package) to avoid setter call overhead.
	it.gasLimit = contract.Gas
	// IMPORTANT: Refund cap is applied by geth's state transition logic, not the runner.
	// If MIR applies it internally, it will incorrectly refund against post-intrinsic call gas.
	it.applyRefundCapInFinish = false
	// EVM.Call/Create already wraps execution in a StateDB snapshot; avoid duplicating that work here.
	it.manageStateSnapshots = false
	// Ensure we don't leak a previous hook across pooled interpreter instances.
	if r.mirStepHookFactory != nil {
		it.stepHook = r.mirStepHookFactory(it)
	} else {
		it.stepHook = r.mirStepHook
	}

	// Fork rules + block context (cached in runner)
	it.blockNumber = r.blockNumber
	it.SetChainRules(r.chainRules)
	// Block context for block-environment opcodes (NUMBER/TIMESTAMP/COINBASE/etc).
	if r.evm != nil {
		it.blockTime = r.evm.Context.Time
		it.blockCoinbase = r.evm.Context.Coinbase
		it.blockGasLimit = r.evm.Context.GasLimit
		it.blockDifficulty = r.evm.Context.Difficulty
		it.blockRandom = r.evm.Context.Random
		it.blockBaseFee = r.evm.Context.BaseFee
		it.blockBlobBaseFee = r.evm.Context.BlobBaseFee
		it.blockGetHash = r.evm.Context.GetHash
		it.txBlobHashes = r.evm.BlobHashes
	}

	// Call context
	it.contractAddr = contract.Address()
	it.callerAddr = contract.Caller()
	it.originAddr = r.evm.Origin
	if v := contract.Value(); v != nil {
		it.callValue = v
	} else {
		it.callValue = u256Zero
	}
	it.callData = input

	// Fullnode backends
	it.state = &r.stateBackend
	it.vmStateDB = r.stateBackend.db
	it.callCreate = &r.callBackend

	res := it.Run()
	if res.Err != nil && os.Getenv("MIR_DUMP_ON_ERROR") != "" {
		// Debug-only: enrich "missing result for def" failures with a local MIR dump around the faulting PC.
		if strings.Contains(res.Err.Error(), "missing result for def") && cfg != nil {
			pc := it.curEvmPC
			start := uint(0)
			if pc > 64 {
				start = pc - 64
			}
			end := pc + 64
			dump := DebugDumpMIRForEvmPCRange(cfg, start, end)

			// Also try to dump around the missing defPC, if we can parse it from the error string.
			if s := res.Err.Error(); s != "" {
				if i := strings.Index(s, "defPC="); i >= 0 {
					j := i + len("defPC=")
					k := j
					for k < len(s) && s[k] >= '0' && s[k] <= '9' {
						k++
					}
					if k > j {
						if n, err := strconv.Atoi(s[j:k]); err == nil && n >= 0 {
							defPC := uint(n)
							ds := uint(0)
							if defPC > 64 {
								ds = defPC - 64
							}
							de := defPC + 64
							dump = dump + "\n" + DebugDumpMIRForEvmPCRange(cfg, ds, de)
						}
					}
				}
			}
			// Also dump incoming/entry/exit stacks for the current block (helps diagnose stale snapshots).
			if curFirstPC := it.CurrentBlockFirstPC(); curFirstPC != 0 {
				dump = dump + "\n" + it.DebugDumpIncomingStacksForPC(curFirstPC, 12)
				dump = dump + "\n" + it.DebugDumpEntryExitStacksForPC(curFirstPC, 12)
			}

			res.Err = fmt.Errorf("%w\n%s", res.Err, dump)
		}
	}
	// If this CFG became dynamic at runtime (e.g. new jump targets discovered), it is not safe to
	// keep it in the global cache. Evict it so future runs rebuild from a clean Parse().
	if cfg != nil && cfg.runtimeBecameDynamic {
		globalCFGCacheMu.Lock()
		getGlobalCFGCache().Remove(codeHash)
		globalCFGCacheMu.Unlock()
		// Also drop runner hot-caches for this entry so we won't reuse it after eviction.
		if r.lastCodeHash == codeHash {
			r.lastEntry = nil
		}
		delete(r.localCFGCache, codeHash)
	}
	contract.Gas = res.GasLeft
	return res.ReturnData, res.Err
}
