// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package lru

import (
	"sync"
	"testing"
)

func TestLockFreeCacheBasic(t *testing.T) {
	cache := NewLockFreeCache[string, int](3)

	// Test basic operations
	cache.Add("a", 1)
	cache.Add("b", 2)
	cache.Add("c", 3)

	if cache.Len() != 3 {
		t.Errorf("Expected length 3, got %d", cache.Len())
	}

	// Test Get
	if val, ok := cache.Get("a"); !ok || val != 1 {
		t.Errorf("Expected (1, true), got (%d, %t)", val, ok)
	}

	// Test Contains
	if !cache.Contains("b") {
		t.Error("Expected to contain 'b'")
	}

	// Test Peek
	if val, ok := cache.Peek("c"); !ok || val != 3 {
		t.Errorf("Expected (3, true), got (%d, %t)", val, ok)
	}

	// Test eviction - note: this is not true LRU, just capacity management
	cache.Add("d", 4)
	if cache.Len() != 3 {
		t.Errorf("Expected length 3 after eviction, got %d", cache.Len())
	}

	// With lock-free implementation, we can't guarantee which item is evicted
	// Just check that we have exactly 3 items and one was evicted
	count := 0
	if cache.Contains("a") {
		count++
	}
	if cache.Contains("b") {
		count++
	}
	if cache.Contains("c") {
		count++
	}
	if cache.Contains("d") {
		count++
	}
	if count != 3 {
		t.Errorf("Expected exactly 3 items, got %d", count)
	}

	// Verify that one item was evicted
	if cache.Contains("a") && cache.Contains("b") && cache.Contains("c") && cache.Contains("d") {
		t.Error("Expected one item to be evicted, but all items are present")
	}
}

func TestLockFreeCacheConcurrent(t *testing.T) {
	cache := NewLockFreeCache[int, string](100)
	var wg sync.WaitGroup

	// Test concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := id*100 + j
				cache.Add(key, "value")
			}
		}(i)
	}

	// Test concurrent reads
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				cache.Get(j)
				cache.Contains(j)
				cache.Peek(j)
			}
		}()
	}

	wg.Wait()

	// Verify cache is in a consistent state
	if cache.Len() > 100 {
		t.Errorf("Cache exceeded capacity: %d", cache.Len())
	}
}

func TestLockFreeCacheRemove(t *testing.T) {
	cache := NewLockFreeCache[string, int](5)

	cache.Add("a", 1)
	cache.Add("b", 2)
	cache.Add("c", 3)

	if !cache.Remove("b") {
		t.Error("Expected Remove to return true")
	}

	if cache.Contains("b") {
		t.Error("Expected 'b' to be removed")
	}

	if cache.Len() != 2 {
		t.Errorf("Expected length 2, got %d", cache.Len())
	}

	// Test removing non-existent item
	if cache.Remove("x") {
		t.Error("Expected Remove to return false for non-existent item")
	}
}

func TestLockFreeCachePurge(t *testing.T) {
	cache := NewLockFreeCache[string, int](5)

	cache.Add("a", 1)
	cache.Add("b", 2)
	cache.Add("c", 3)

	cache.Purge()

	if cache.Len() != 0 {
		t.Errorf("Expected length 0 after purge, got %d", cache.Len())
	}

	if cache.Contains("a") {
		t.Error("Expected cache to be empty after purge")
	}
}

func BenchmarkLockFreeCacheAdd(b *testing.B) {
	cache := NewLockFreeCache[int, string](1000)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Add(i, "value")
			i++
		}
	})
}

func BenchmarkLockFreeCacheGet(b *testing.B) {
	cache := NewLockFreeCache[int, string](1000)

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		cache.Add(i, "value")
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Get(i % 1000)
			i++
		}
	})
}
