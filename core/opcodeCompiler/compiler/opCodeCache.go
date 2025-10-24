package compiler

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
)

type OpCodeCache struct {
	optimizedCodeCache *lru.Cache[common.Hash, []byte]
	bitvecCache        *lru.Cache[common.Hash, []byte]
	blockGasCache      *lru.Cache[common.Hash, map[uint]*MIRBasicBlock] // codeHash -> (blockNum -> *MIRBasicBlock with StaticGas)
}

func (c *OpCodeCache) GetCachedBitvec(codeHash common.Hash) []byte {
	bitvec, _ := c.bitvecCache.Get(codeHash)
	return bitvec
}

func (c *OpCodeCache) AddBitvecCache(codeHash common.Hash, bitvec []byte) {
	c.bitvecCache.Add(codeHash, bitvec)
}

func (c *OpCodeCache) RemoveCachedCode(hash common.Hash) {
	c.optimizedCodeCache.Remove(hash)
}

func (c *OpCodeCache) GetCachedCode(hash common.Hash) []byte {
	processedCode, _ := c.optimizedCodeCache.Get(hash)
	return processedCode
}

func (c *OpCodeCache) AddCodeCache(hash common.Hash, optimizedCode []byte) {
	c.optimizedCodeCache.Add(hash, optimizedCode)
}

var opcodeCache *OpCodeCache

const (
	optimizedCodeCacheCap = 1024 * 1024
	bitvecCacheCap        = 1024 * 1024
	blockGasCacheCap      = 1024 * 1024
)

func init() {
	opcodeCache = &OpCodeCache{
		optimizedCodeCache: lru.NewCache[common.Hash, []byte](optimizedCodeCacheCap),
		bitvecCache:        lru.NewCache[common.Hash, []byte](bitvecCacheCap),
		blockGasCache:      lru.NewCache[common.Hash, map[uint]*MIRBasicBlock](blockGasCacheCap),
	}
}

func getOpCodeCacheInstance() *OpCodeCache {
	return opcodeCache
}

// AddBlockGasCache stores the block gas info for a given code hash
func (c *OpCodeCache) AddBlockGasCache(codeHash common.Hash, blockMap map[uint]*MIRBasicBlock) {
	c.blockGasCache.Add(codeHash, blockMap)
}

// GetBlockGasCache retrieves the cached block gas info for a given code hash
func (c *OpCodeCache) GetBlockGasCache(codeHash common.Hash) (map[uint]*MIRBasicBlock, bool) {
	blockMap, ok := c.blockGasCache.Get(codeHash)
	return blockMap, ok
}

// IsBlockGasCached checks if block gas info exists for a given code hash
func (c *OpCodeCache) IsBlockGasCached(codeHash common.Hash) bool {
	_, ok := c.blockGasCache.Get(codeHash)
	return ok
}

// RemoveBlockGasCache removes the cached block gas info
func (c *OpCodeCache) RemoveBlockGasCache(codeHash common.Hash) {
	c.blockGasCache.Remove(codeHash)
}
