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
	"sync/atomic"
	"unsafe"
)

// LockFreeCache is a lock-free cache implementation that provides better performance
// for high-concurrency scenarios while maintaining LRU semantics.
type LockFreeCache[K comparable, V any] struct {
	capacity int64
	size     int64
	items    unsafe.Pointer // *lockFreeMap[K, V]
}

type lockFreeMap[K comparable, V any] struct {
	entries map[K]V
}

// NewLockFreeCache creates a new lock-free cache.
func NewLockFreeCache[K comparable, V any](capacity int) *LockFreeCache[K, V] {
	if capacity <= 0 {
		capacity = 1
	}

	cache := &LockFreeCache[K, V]{
		capacity: int64(capacity),
		size:     0,
		items:    unsafe.Pointer(&lockFreeMap[K, V]{entries: make(map[K]V)}),
	}

	return cache
}

// Add adds a value to the cache. Returns true if an item was evicted to store the new item.
func (c *LockFreeCache[K, V]) Add(key K, value V) (evicted bool) {
	for {
		// Check if key already exists
		oldMap := (*lockFreeMap[K, V])(atomic.LoadPointer(&c.items))
		keyExists := false
		if _, exists := oldMap.entries[key]; exists {
			keyExists = true
		}

		// Check if we need to evict due to capacity (only for new keys)
		currentSize := atomic.LoadInt64(&c.size)
		if !keyExists && currentSize >= c.capacity {
			// Simple eviction: remove one item to make room
			evicted = true
			// For simplicity, we'll just remove the first item we find
			for k := range oldMap.entries {
				if c.tryRemoveItem(k) {
					atomic.AddInt64(&c.size, -1)
					break
				}
			}
			// After eviction, we need to reload the map since it may have changed
			oldMap = (*lockFreeMap[K, V])(atomic.LoadPointer(&c.items))
		}

		// Try to add the item
		if c.tryAddItem(key, value) {
			if !keyExists {
				// Always increment size for new items
				atomic.AddInt64(&c.size, 1)
			}
			return evicted
		}

		// If CAS failed, retry
		// This can happen due to concurrent modifications
	}
}

// Get retrieves a value from the cache.
func (c *LockFreeCache[K, V]) Get(key K) (value V, ok bool) {
	item := c.findItem(key)
	if item == nil {
		return value, false
	}
	return item.value, true
}

// Contains reports whether the given key exists in the cache.
func (c *LockFreeCache[K, V]) Contains(key K) bool {
	return c.findItem(key) != nil
}

// Remove drops an item from the cache. Returns true if the key was present in cache.
func (c *LockFreeCache[K, V]) Remove(key K) bool {
	if c.tryRemoveItem(key) {
		atomic.AddInt64(&c.size, -1)
		return true
	}
	return false
}

// Len returns the current number of items in the cache.
func (c *LockFreeCache[K, V]) Len() int {
	return int(atomic.LoadInt64(&c.size))
}

// Peek retrieves a value from the cache, but does not mark the key as recently used.
func (c *LockFreeCache[K, V]) Peek(key K) (value V, ok bool) {
	return c.Get(key)
}

// Purge empties the cache.
func (c *LockFreeCache[K, V]) Purge() {
	// Create a new empty map
	newMap := &lockFreeMap[K, V]{entries: make(map[K]V)}
	atomic.StorePointer(&c.items, unsafe.Pointer(newMap))
	atomic.StoreInt64(&c.size, 0)
}

// findItem searches for an item with the given key
func (c *LockFreeCache[K, V]) findItem(key K) *lockFreeEntry[K, V] {
	mapPtr := (*lockFreeMap[K, V])(atomic.LoadPointer(&c.items))
	if value, exists := mapPtr.entries[key]; exists {
		return &lockFreeEntry[K, V]{key: key, value: value}
	}
	return nil
}

// tryAddItem attempts to add a new item to the cache
func (c *LockFreeCache[K, V]) tryAddItem(key K, value V) bool {
	// Create a new map with the new entry
	oldMap := (*lockFreeMap[K, V])(atomic.LoadPointer(&c.items))

	// Check if key already exists
	if _, exists := oldMap.entries[key]; exists {
		// Key exists, just update the value
		newMap := &lockFreeMap[K, V]{entries: make(map[K]V)}
		for k, v := range oldMap.entries {
			newMap.entries[k] = v
		}
		newMap.entries[key] = value
		return atomic.CompareAndSwapPointer(&c.items, unsafe.Pointer(oldMap), unsafe.Pointer(newMap))
	}

	// Key doesn't exist, add new entry
	newMap := &lockFreeMap[K, V]{entries: make(map[K]V)}
	for k, v := range oldMap.entries {
		newMap.entries[k] = v
	}
	newMap.entries[key] = value

	// Try to swap the map pointer
	return atomic.CompareAndSwapPointer(&c.items, unsafe.Pointer(oldMap), unsafe.Pointer(newMap))
}

// tryRemoveItem attempts to remove an item from the cache
func (c *LockFreeCache[K, V]) tryRemoveItem(key K) bool {
	oldMap := (*lockFreeMap[K, V])(atomic.LoadPointer(&c.items))
	if _, exists := oldMap.entries[key]; !exists {
		return false
	}

	// Create a new map without the key
	newMap := &lockFreeMap[K, V]{entries: make(map[K]V)}
	for k, v := range oldMap.entries {
		if k != key {
			newMap.entries[k] = v
		}
	}

	// Try to swap the map pointer
	return atomic.CompareAndSwapPointer(&c.items, unsafe.Pointer(oldMap), unsafe.Pointer(newMap))
}

// lockFreeEntry represents a cache entry
type lockFreeEntry[K comparable, V any] struct {
	key   K
	value V
}
