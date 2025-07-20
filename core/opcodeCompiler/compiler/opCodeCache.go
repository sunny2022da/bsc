package compiler

import (
	"sync"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
)

// OpCodeCache provides better performance through sharding and optimized operations
type OpCodeCache struct {
	shards    []*cacheShard
	shardMask uint64
}

type cacheShard struct {
	optimizedCodeCache *lru.Cache[common.Hash, []byte]
	bitvecCache        *lru.Cache[common.Hash, []byte]
	mu                 sync.RWMutex
}

// getShard returns the shard for a given hash using fast modulo
func (c *OpCodeCache) getShard(hash common.Hash) *cacheShard {
	// Use the first 8 bytes of the hash for shard selection
	shardIndex := *(*uint64)(unsafe.Pointer(&hash[0])) & c.shardMask
	return c.shards[shardIndex]
}

func (c *OpCodeCache) GetCachedBitvec(codeHash common.Hash) []byte {
	shard := c.getShard(codeHash)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	bitvec, _ := shard.bitvecCache.Get(codeHash)
	return bitvec
}

func (c *OpCodeCache) AddBitvecCache(codeHash common.Hash, bitvec []byte) {
	shard := c.getShard(codeHash)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.bitvecCache.Add(codeHash, bitvec)
}

func (c *OpCodeCache) RemoveCachedCode(hash common.Hash) {
	shard := c.getShard(hash)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.optimizedCodeCache.Remove(hash)
}

func (c *OpCodeCache) GetCachedCode(hash common.Hash) []byte {
	shard := c.getShard(hash)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	processedCode, _ := shard.optimizedCodeCache.Get(hash)
	return processedCode
}

func (c *OpCodeCache) AddCodeCache(hash common.Hash, optimizedCode []byte) {
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

var opcodeCache *OpCodeCache

const (
	shardCount            = 16
	capacityPerShard      = 64
	optimizedCodeCacheCap = shardCount * capacityPerShard
	bitvecCacheCap        = shardCount * capacityPerShard
)

func init() {
	// Ensure shardCount is a power of 2 for efficient modulo operation
	actualShardCount := nextPowerOfTwo(shardCount)

	cache := &OpCodeCache{
		shards:    make([]*cacheShard, actualShardCount),
		shardMask: uint64(actualShardCount - 1),
	}

	for i := 0; i < actualShardCount; i++ {
		cache.shards[i] = &cacheShard{
			optimizedCodeCache: lru.NewCache[common.Hash, []byte](capacityPerShard),
			bitvecCache:        lru.NewCache[common.Hash, []byte](capacityPerShard),
		}
	}

	opcodeCache = cache
}

func getOpCodeCacheInstance() *OpCodeCache {
	return opcodeCache
}
