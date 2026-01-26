package MIR

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
)

// Global (process-wide) CFG cache.
//
// Rationale:
// The fullnode creates a new vm.EVM (and thus a new MIR EVMRunner) per block. If CFG caching is
// per-runner, hot contracts get re-parsed every block, which is extremely expensive and dominates
// runtime. This cache persists across blocks to amortize CFG.Parse.
//
// Concurrency:
// CFGs are mutated during execution (dynamic CFG expansion, incoming edge snapshots), so the same
// CFG must not be used concurrently by multiple goroutines. Each cached CFG has its own mutex and
// is locked for the duration of a top-level MIR run.

type cfgCacheEntry struct {
	mu  sync.Mutex
	cfg *CFG
	// mutable indicates the CFG is expected to be mutated at runtime (dynamic CFG expansion /
	// runtime incoming snapshots). Immutable CFGs can be executed without taking the lock.
	mutable bool
}

var (
	globalCFGCacheOnce sync.Once
	globalCFGCache     *lru.Cache[common.Hash, *cfgCacheEntry]
	// globalCFGCacheMu protects the LRU cache itself. The underlying lru.Cache is NOT safe for
	// concurrent use, and fullnodes can execute multiple EVMs concurrently (sync, RPC, etc.).
	// Without this lock, cache corruption or wrong lookups can cause consensus divergence.
	globalCFGCacheMu sync.RWMutex

	// Pool interpreters to avoid per-call allocations (maps/slices). ResetForRun() clears state.
	globalInterpreterPool = sync.Pool{New: func() any { return NewMIRInterpreter(nil) }}

	globalCFGCacheHits   atomic.Uint64
	globalCFGCacheMisses atomic.Uint64
	globalCFGCacheBuilds atomic.Uint64
)

func getGlobalCFGCache() *lru.Cache[common.Hash, *cfgCacheEntry] {
	globalCFGCacheOnce.Do(func() {
		// Default chosen to keep memory bounded while still capturing hot contracts.
		// Can be overridden for perf experiments.
		capacity := 4096
		if s := os.Getenv("MIR_CFG_CACHE_SIZE"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				capacity = n
			}
		}
		globalCFGCache = lru.NewCache[common.Hash, *cfgCacheEntry](capacity)
	})
	return globalCFGCache
}

// getOrBuildCFGEntry returns a cached CFG entry for the given code hash, building it if needed.
func getOrBuildCFGEntry(codeHash common.Hash, code []byte) (*cfgCacheEntry, error) {
	c := getGlobalCFGCache()
	// Fast path: read lock for lookup.
	globalCFGCacheMu.RLock()
	if e, ok := c.Get(codeHash); ok && e != nil && e.cfg != nil {
		globalCFGCacheMu.RUnlock()
		globalCFGCacheHits.Add(1)
		return e, nil
	}
	globalCFGCacheMu.RUnlock()
	globalCFGCacheMisses.Add(1)

	// Slow path: create placeholder under write lock so only one entry exists per key.
	globalCFGCacheMu.Lock()
	if e, ok := c.Get(codeHash); ok && e != nil {
		globalCFGCacheMu.Unlock()
		// Another goroutine created it; wait for build if needed.
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.cfg != nil {
			return e, nil
		}
		// Fall through to build below (rare).
	} else {
		e := &cfgCacheEntry{}
		c.Add(codeHash, e)
		globalCFGCacheMu.Unlock()
		// Continue with build using the newly inserted entry.
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.cfg != nil {
			return e, nil
		}
		built := NewCFG(codeHash, code)
		if err := built.Parse(); err != nil {
			// Don't keep a permanently broken entry in cache.
			globalCFGCacheMu.Lock()
			c.Remove(codeHash)
			globalCFGCacheMu.Unlock()
			return nil, err
		}
		e.cfg = built
		e.mutable = built.hasUnresolvedJumps()
		// Correctness guard: CFGs with unresolved jumps are mutated heavily at runtime
		// (dynamic expansion + incoming snapshots). Sharing them globally across blocks/transactions
		// can leak path-dependent snapshots and cause consensus divergence.
		//
		// For these CFGs, let callers optionally keep them in a runner-local cache instead.
		if built.hasUnresolvedJumps() {
			globalCFGCacheMu.Lock()
			c.Remove(codeHash)
			globalCFGCacheMu.Unlock()
		}
		globalCFGCacheBuilds.Add(1)
		return e, nil
	}

	// If we reached here, we have an existing entry e locked but cfg is still nil: build it.
	// (This can happen if two goroutines raced and the first inserted placeholder but crashed
	// before building; extremely rare but keep it correct.)
	built := NewCFG(codeHash, code)
	if err := built.Parse(); err != nil {
		// Don't keep a permanently broken entry in cache.
		// (It's fine if another goroutine re-adds later.)
		globalCFGCacheMu.Lock()
		c.Remove(codeHash)
		globalCFGCacheMu.Unlock()
		return nil, err
	}
	// Re-fetch entry under lock (it should still exist).
	globalCFGCacheMu.RLock()
	e2, _ := c.Get(codeHash)
	globalCFGCacheMu.RUnlock()
	if e2 == nil {
		// Re-insert if evicted while we were building.
		e2 = &cfgCacheEntry{}
		globalCFGCacheMu.Lock()
		c.Add(codeHash, e2)
		globalCFGCacheMu.Unlock()
	}
	e2.mu.Lock()
	defer e2.mu.Unlock()
	e2.cfg = built
	e2.mutable = built.hasUnresolvedJumps()
	// Correctness guard: CFGs with unresolved jumps are mutated heavily at runtime
	// (dynamic expansion + incoming snapshots). Sharing them globally across blocks/transactions
	// can leak path-dependent snapshots and cause consensus divergence.
	//
	// For these CFGs, let callers optionally keep them in a runner-local cache instead.
	if built.hasUnresolvedJumps() {
		globalCFGCacheMu.Lock()
		c.Remove(codeHash)
		globalCFGCacheMu.Unlock()
	}
	globalCFGCacheBuilds.Add(1)
	return e2, nil
}
