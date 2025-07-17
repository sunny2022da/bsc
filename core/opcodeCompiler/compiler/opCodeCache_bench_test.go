package compiler

import (
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Benchmark tests for different cache implementations

func BenchmarkOriginalCache_Get(b *testing.B) {
	cache := getOpCodeCacheInstance()

	// Pre-populate cache
	testHashes := generateTestHashes(1000)
	for _, hash := range testHashes {
		cache.AddCodeCache(hash, []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			_ = cache.GetCachedCode(hash)
			i++
		}
	})
}

func BenchmarkOptimizedCache_Get(b *testing.B) {
	cache := getOptimizedOpCodeCacheInstance()

	// Pre-populate cache
	testHashes := generateTestHashes(1000)
	for _, hash := range testHashes {
		cache.AddCodeCache(hash, []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			_ = cache.GetCachedCode(hash)
			i++
		}
	})
}

func BenchmarkSizeConstrainedCache_Get(b *testing.B) {
	cache := getSizeConstrainedOpCodeCacheInstance()

	// Pre-populate cache
	testHashes := generateTestHashes(1000)
	for _, hash := range testHashes {
		cache.AddCodeCache(hash, []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			_ = cache.GetCachedCode(hash)
			i++
		}
	})
}

func BenchmarkLockFreeCache_Get(b *testing.B) {
	cache := getLockFreeOpCodeCacheInstance()

	// Pre-populate cache
	testHashes := generateTestHashes(1000)
	for _, hash := range testHashes {
		cache.AddCodeCache(hash, []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			_ = cache.GetCachedCode(hash)
			i++
		}
	})
}

func BenchmarkOriginalCache_Add(b *testing.B) {
	cache := getOpCodeCacheInstance()
	testHashes := generateTestHashes(b.N)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			cache.AddCodeCache(hash, []byte("test_code"))
			i++
		}
	})
}

func BenchmarkOptimizedCache_Add(b *testing.B) {
	cache := getOptimizedOpCodeCacheInstance()
	testHashes := generateTestHashes(b.N)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			cache.AddCodeCache(hash, []byte("test_code"))
			i++
		}
	})
}

func BenchmarkSizeConstrainedCache_Add(b *testing.B) {
	cache := getSizeConstrainedOpCodeCacheInstance()
	testHashes := generateTestHashes(b.N)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			cache.AddCodeCache(hash, []byte("test_code"))
			i++
		}
	})
}

func BenchmarkLockFreeCache_Add(b *testing.B) {
	cache := getLockFreeOpCodeCacheInstance()
	testHashes := generateTestHashes(b.N)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			cache.AddCodeCache(hash, []byte("test_code"))
			i++
		}
	})
}

// Mixed workload benchmark
func BenchmarkOriginalCache_Mixed(b *testing.B) {
	cache := getOpCodeCacheInstance()
	testHashes := generateTestHashes(1000)

	// Pre-populate half the cache
	for i := 0; i < 500; i++ {
		cache.AddCodeCache(testHashes[i], []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			if i%2 == 0 {
				_ = cache.GetCachedCode(hash)
			} else {
				cache.AddCodeCache(hash, []byte("test_code"))
			}
			i++
		}
	})
}

func BenchmarkOptimizedCache_Mixed(b *testing.B) {
	cache := getOptimizedOpCodeCacheInstance()
	testHashes := generateTestHashes(1000)

	// Pre-populate half the cache
	for i := 0; i < 500; i++ {
		cache.AddCodeCache(testHashes[i], []byte("test_code"))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hash := testHashes[i%len(testHashes)]
			if i%2 == 0 {
				_ = cache.GetCachedCode(hash)
			} else {
				cache.AddCodeCache(hash, []byte("test_code"))
			}
			i++
		}
	})
}

// Helper function to generate test hashes
func generateTestHashes(count int) []common.Hash {
	hashes := make([]common.Hash, count)
	for i := 0; i < count; i++ {
		rand.Read(hashes[i][:])
	}
	return hashes
}
