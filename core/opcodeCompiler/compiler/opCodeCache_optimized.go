package compiler

import (
	"sync"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
)

// OptimizedOpCodeCache provides better performance through sharding and lock-free operations
type OptimizedOpCodeCache struct {
	shards    []*cacheShard
	shardMask uint64
}

type cacheShard struct {
	optimizedCodeCache *lru.Cache[common.Hash, []byte]
	bitvecCache        *lru.Cache[common.Hash, []byte]
	mu                 sync.RWMutex
}

// NewOptimizedOpCodeCache creates a new sharded cache with better concurrency
func NewOptimizedOpCodeCache(shardCount int, capacityPerShard int) *OptimizedOpCodeCache {
	if shardCount <= 0 {
		shardCount = 16 // Default to 16 shards
	}
	if capacityPerShard <= 0 {
		capacityPerShard = 64 // Default to 64 entries per shard
	}

	// Ensure shardCount is a power of 2 for efficient modulo operation
	shardCount = nextPowerOfTwo(shardCount)

	cache := &OptimizedOpCodeCache{
		shards:    make([]*cacheShard, shardCount),
		shardMask: uint64(shardCount - 1),
	}

	for i := 0; i < shardCount; i++ {
		cache.shards[i] = &cacheShard{
			optimizedCodeCache: lru.NewCache[common.Hash, []byte](capacityPerShard),
			bitvecCache:        lru.NewCache[common.Hash, []byte](capacityPerShard),
		}
	}

	return cache
}

// getShard returns the shard for a given hash using fast modulo
func (c *OptimizedOpCodeCache) getShard(hash common.Hash) *cacheShard {
	// Use the first 8 bytes of the hash for shard selection
	shardIndex := *(*uint64)(unsafe.Pointer(&hash[0])) & c.shardMask
	return c.shards[shardIndex]
}

func (c *OptimizedOpCodeCache) GetCachedBitvec(codeHash common.Hash) []byte {
	shard := c.getShard(codeHash)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	bitvec, _ := shard.bitvecCache.Get(codeHash)
	return bitvec
}

func (c *OptimizedOpCodeCache) AddBitvecCache(codeHash common.Hash, bitvec []byte) {
	shard := c.getShard(codeHash)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.bitvecCache.Add(codeHash, bitvec)
}

func (c *OptimizedOpCodeCache) RemoveCachedCode(hash common.Hash) {
	shard := c.getShard(hash)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.optimizedCodeCache.Remove(hash)
}

func (c *OptimizedOpCodeCache) GetCachedCode(hash common.Hash) []byte {
	shard := c.getShard(hash)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	processedCode, _ := shard.optimizedCodeCache.Get(hash)
	return processedCode
}

func (c *OptimizedOpCodeCache) AddCodeCache(hash common.Hash, optimizedCode []byte) {
	shard := c.getShard(hash)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.optimizedCodeCache.Add(hash, optimizedCode)
}

// nextPowerOfTwo returns the next power of 2 >= n
func nextPowerOfTwo(n int) int {
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

// Global optimized cache instance
var optimizedOpcodeCache *OptimizedOpCodeCache

func init() {
	// Initialize with 16 shards, 64 entries per shard (total 1024 entries)
	optimizedOpcodeCache = NewOptimizedOpCodeCache(16, 64)
}

func getOptimizedOpCodeCacheInstance() *OptimizedOpCodeCache {
	return optimizedOpcodeCache
}
