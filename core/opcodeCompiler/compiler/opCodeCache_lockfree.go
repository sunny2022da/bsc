package compiler

import (
	"sync/atomic"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
)

// LockFreeOpCodeCache provides lock-free operations using atomic operations
type LockFreeOpCodeCache struct {
	optimizedCodeCache *lockFreeCache[common.Hash, []byte]
	bitvecCache        *lockFreeCache[common.Hash, []byte]
}

// lockFreeCache implements a simple lock-free cache using atomic operations
type lockFreeCache[K comparable, V any] struct {
	entries []*cacheEntry[K, V]
	mask    uint64
}

type cacheEntry[K comparable, V any] struct {
	key   K
	value V
	used  int32 // atomic flag
}

// NewLockFreeOpCodeCache creates a new lock-free cache
func NewLockFreeOpCodeCache(capacity int) *LockFreeOpCodeCache {
	// Ensure capacity is a power of 2
	capacity = nextPowerOfTwoLockFree(capacity)

	return &LockFreeOpCodeCache{
		optimizedCodeCache: newLockFreeCache[common.Hash, []byte](capacity),
		bitvecCache:        newLockFreeCache[common.Hash, []byte](capacity),
	}
}

func newLockFreeCache[K comparable, V any](capacity int) *lockFreeCache[K, V] {
	entries := make([]*cacheEntry[K, V], capacity)
	for i := range entries {
		entries[i] = &cacheEntry[K, V]{}
	}

	return &lockFreeCache[K, V]{
		entries: entries,
		mask:    uint64(capacity - 1),
	}
}

// getIndex computes the index for a key using fast hash
func (c *lockFreeCache[K, V]) getIndex(key K) uint64 {
	// Simple hash function for common.Hash
	if hash, ok := any(key).(common.Hash); ok {
		return *(*uint64)(unsafe.Pointer(&hash[0])) & c.mask
	}
	// Fallback for other types
	return uint64(any(key).(common.Hash)[0]) & c.mask
}

// Get retrieves a value from the cache
func (c *lockFreeCache[K, V]) Get(key K) (V, bool) {
	index := c.getIndex(key)
	entry := c.entries[index]

	// Check if entry is used and key matches
	if atomic.LoadInt32(&entry.used) == 1 {
		if entry.key == key {
			return entry.value, true
		}
	}

	var zero V
	return zero, false
}

// Add adds a value to the cache
func (c *lockFreeCache[K, V]) Add(key K, value V) {
	index := c.getIndex(key)
	entry := c.entries[index]

	// Try to claim the entry
	if atomic.CompareAndSwapInt32(&entry.used, 0, 1) {
		entry.key = key
		entry.value = value
		return
	}

	// Entry is already used, check if it's the same key
	if entry.key == key {
		// Update the value
		entry.value = value
		return
	}

	// Entry is used by different key, we need to evict
	// This is a simplified implementation - in practice, you might want
	// a more sophisticated eviction strategy
	entry.key = key
	entry.value = value
}

// Remove removes an entry from the cache
func (c *lockFreeCache[K, V]) Remove(key K) {
	index := c.getIndex(key)
	entry := c.entries[index]

	if atomic.LoadInt32(&entry.used) == 1 && entry.key == key {
		atomic.StoreInt32(&entry.used, 0)
	}
}

func (c *LockFreeOpCodeCache) GetCachedBitvec(codeHash common.Hash) []byte {
	bitvec, _ := c.bitvecCache.Get(codeHash)
	return bitvec
}

func (c *LockFreeOpCodeCache) AddBitvecCache(codeHash common.Hash, bitvec []byte) {
	c.bitvecCache.Add(codeHash, bitvec)
}

func (c *LockFreeOpCodeCache) RemoveCachedCode(hash common.Hash) {
	c.optimizedCodeCache.Remove(hash)
}

func (c *LockFreeOpCodeCache) GetCachedCode(hash common.Hash) []byte {
	processedCode, _ := c.optimizedCodeCache.Get(hash)
	return processedCode
}

func (c *LockFreeOpCodeCache) AddCodeCache(hash common.Hash, optimizedCode []byte) {
	c.optimizedCodeCache.Add(hash, optimizedCode)
}

// nextPowerOfTwoLockFree returns the next power of 2 >= n
func nextPowerOfTwoLockFree(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

// Global lock-free cache instance
var lockFreeOpcodeCache *LockFreeOpCodeCache

func init() {
	lockFreeOpcodeCache = NewLockFreeOpCodeCache(1024 * 1024)
}

func getLockFreeOpCodeCacheInstance() *LockFreeOpCodeCache {
	return lockFreeOpcodeCache
}
