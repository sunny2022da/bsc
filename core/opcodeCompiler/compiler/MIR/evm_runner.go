package MIR

import (
	"fmt"
	"math/big"

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

	codeHash := contract.CodeHash
	if (codeHash == common.Hash{}) {
		// Some call paths may not set CodeHash. Fast path: if we're repeatedly calling the
		// same address, reuse the last computed code hash (avoid hashing large bytecode).
		if r.lastEntry != nil && r.lastAddr == contract.Address() && (r.lastCodeHash != common.Hash{}) {
			codeHash = r.lastCodeHash
		} else {
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
	if entry.mutable {
		// Serialize per-contract executions across goroutines.
		entry.mu.Lock()
		defer entry.mu.Unlock()
		// Bump epoch so any runtime-recorded incoming snapshots from previous executions are ignored.
		// (Parse-time/base snapshots are tagged with epoch 0 and remain valid for all runs.)
		cfg.runtimeEpoch = globalCFGRuntimeEpoch.Add(1)
	} else {
		// Immutable CFG: avoid lock + epoch overhead (hot for small view calls).
		cfg.runtimeEpoch = 0
	}

	it := globalInterpreterPool.Get().(*MIRInterpreter)
	it.ResetForRun(cfg)
	defer globalInterpreterPool.Put(it)
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
	contract.Gas = res.GasLeft
	return res.ReturnData, res.Err
}
