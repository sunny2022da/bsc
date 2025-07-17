package compiler

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
)

// SizeConstrainedOpCodeCache uses memory size constraints instead of entry count
type SizeConstrainedOpCodeCache struct {
	optimizedCodeCache *lru.SizeConstrainedCache[common.Hash, []byte]
	bitvecCache        *lru.SizeConstrainedCache[common.Hash, []byte]
}

// NewSizeConstrainedOpCodeCache creates a cache with memory size limits
func NewSizeConstrainedOpCodeCache(optimizedCodeMaxSize, bitvecMaxSize uint64) *SizeConstrainedOpCodeCache {
	return &SizeConstrainedOpCodeCache{
		optimizedCodeCache: lru.NewSizeConstrainedCache[common.Hash, []byte](optimizedCodeMaxSize),
		bitvecCache:        lru.NewSizeConstrainedCache[common.Hash, []byte](bitvecMaxSize),
	}
}

func (c *SizeConstrainedOpCodeCache) GetCachedBitvec(codeHash common.Hash) []byte {
	bitvec, _ := c.bitvecCache.Get(codeHash)
	return bitvec
}

func (c *SizeConstrainedOpCodeCache) AddBitvecCache(codeHash common.Hash, bitvec []byte) {
	c.bitvecCache.Add(codeHash, bitvec)
}

func (c *SizeConstrainedOpCodeCache) RemoveCachedCode(hash common.Hash) {
	// Size-constrained cache doesn't have explicit remove, but we can add an empty value
	// This is a limitation of the current SizeConstrainedCache implementation
}

func (c *SizeConstrainedOpCodeCache) GetCachedCode(hash common.Hash) []byte {
	processedCode, _ := c.optimizedCodeCache.Get(hash)
	return processedCode
}

func (c *SizeConstrainedOpCodeCache) AddCodeCache(hash common.Hash, optimizedCode []byte) {
	c.optimizedCodeCache.Add(hash, optimizedCode)
}

// Global size-constrained cache instance
var sizeConstrainedOpcodeCache *SizeConstrainedOpCodeCache

func init() {
	// 64MB for optimized code cache, 16MB for bitvec cache
	sizeConstrainedOpcodeCache = NewSizeConstrainedOpCodeCache(64*1024*1024, 16*1024*1024)
}

func getSizeConstrainedOpCodeCacheInstance() *SizeConstrainedOpCodeCache {
	return sizeConstrainedOpcodeCache
}
