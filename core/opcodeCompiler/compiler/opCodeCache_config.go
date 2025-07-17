package compiler

import (
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
)

// CacheType represents different cache implementations
type CacheType int

const (
	CacheTypeOriginal CacheType = iota
	CacheTypeOptimized
	CacheTypeSizeConstrained
	CacheTypeLockFree
)

// CacheConfig holds configuration for the opcode cache
type CacheConfig struct {
	Type                 CacheType
	ShardCount           int
	CapacityPerShard     int
	OptimizedCodeMaxSize uint64
	BitvecMaxSize        uint64
	TotalCapacity        int
}

// Default configurations for different cache types
var (
	DefaultOriginalConfig = CacheConfig{
		Type:          CacheTypeOriginal,
		TotalCapacity: 1024,
	}

	DefaultOptimizedConfig = CacheConfig{
		Type:             CacheTypeOptimized,
		ShardCount:       16,
		CapacityPerShard: 64,
	}

	DefaultSizeConstrainedConfig = CacheConfig{
		Type:                 CacheTypeSizeConstrained,
		OptimizedCodeMaxSize: 64 * 1024 * 1024, // 64MB
		BitvecMaxSize:        16 * 1024 * 1024, // 16MB
	}

	DefaultLockFreeConfig = CacheConfig{
		Type:          CacheTypeLockFree,
		TotalCapacity: 1024,
	}
)

// Global cache configuration
var (
	currentCacheType atomic.Value
	cacheConfig      atomic.Value
)

func init() {
	currentCacheType.Store(CacheTypeOriginal)
	cacheConfig.Store(DefaultOriginalConfig)
}

// SetCacheType changes the cache implementation at runtime
func SetCacheType(cacheType CacheType) {
	currentCacheType.Store(cacheType)
}

// SetCacheConfig sets the cache configuration
func SetCacheConfig(config CacheConfig) {
	cacheConfig.Store(config)
}

// GetCurrentCache returns the currently active cache instance
func GetCurrentCache() interface{} {
	cacheType := currentCacheType.Load().(CacheType)

	switch cacheType {
	case CacheTypeOptimized:
		return getOptimizedOpCodeCacheInstance()
	case CacheTypeSizeConstrained:
		return getSizeConstrainedOpCodeCacheInstance()
	case CacheTypeLockFree:
		return getLockFreeOpCodeCacheInstance()
	default:
		return getOpCodeCacheInstance()
	}
}

// GetCachedCodeWithType gets cached code using the current cache type
func GetCachedCodeWithType(hash common.Hash) []byte {
	cacheType := currentCacheType.Load().(CacheType)

	switch cacheType {
	case CacheTypeOptimized:
		return getOptimizedOpCodeCacheInstance().GetCachedCode(hash)
	case CacheTypeSizeConstrained:
		return getSizeConstrainedOpCodeCacheInstance().GetCachedCode(hash)
	case CacheTypeLockFree:
		return getLockFreeOpCodeCacheInstance().GetCachedCode(hash)
	default:
		return getOpCodeCacheInstance().GetCachedCode(hash)
	}
}

// AddCodeCacheWithType adds code to cache using the current cache type
func AddCodeCacheWithType(hash common.Hash, optimizedCode []byte) {
	cacheType := currentCacheType.Load().(CacheType)

	switch cacheType {
	case CacheTypeOptimized:
		getOptimizedOpCodeCacheInstance().AddCodeCache(hash, optimizedCode)
	case CacheTypeSizeConstrained:
		getSizeConstrainedOpCodeCacheInstance().AddCodeCache(hash, optimizedCode)
	case CacheTypeLockFree:
		getLockFreeOpCodeCacheInstance().AddCodeCache(hash, optimizedCode)
	default:
		getOpCodeCacheInstance().AddCodeCache(hash, optimizedCode)
	}
}

// GetCachedBitvecWithType gets cached bitvec using the current cache type
func GetCachedBitvecWithType(codeHash common.Hash) []byte {
	cacheType := currentCacheType.Load().(CacheType)

	switch cacheType {
	case CacheTypeOptimized:
		return getOptimizedOpCodeCacheInstance().GetCachedBitvec(codeHash)
	case CacheTypeSizeConstrained:
		return getSizeConstrainedOpCodeCacheInstance().GetCachedBitvec(codeHash)
	case CacheTypeLockFree:
		return getLockFreeOpCodeCacheInstance().GetCachedBitvec(codeHash)
	default:
		return getOpCodeCacheInstance().GetCachedBitvec(codeHash)
	}
}

// AddBitvecCacheWithType adds bitvec to cache using the current cache type
func AddBitvecCacheWithType(codeHash common.Hash, bitvec []byte) {
	cacheType := currentCacheType.Load().(CacheType)

	switch cacheType {
	case CacheTypeOptimized:
		getOptimizedOpCodeCacheInstance().AddBitvecCache(codeHash, bitvec)
	case CacheTypeSizeConstrained:
		getSizeConstrainedOpCodeCacheInstance().AddBitvecCache(codeHash, bitvec)
	case CacheTypeLockFree:
		getLockFreeOpCodeCacheInstance().AddBitvecCache(codeHash, bitvec)
	default:
		getOpCodeCacheInstance().AddBitvecCache(codeHash, bitvec)
	}
}
