package compiler

import (
	"sync"
)

// OpCodeCache represents a cache for optimized opcodes
type OpCodeCache struct {
	mu    sync.RWMutex
	cache map[string][]byte
}

// NewOpCodeCache creates a new opcode cache
func NewOpCodeCache() *OpCodeCache {
	return &OpCodeCache{
		cache: make(map[string][]byte),
	}
}

// Get retrieves an optimized opcode sequence from the cache
func (c *OpCodeCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.cache[key]
	return val, ok
}

// Set stores an optimized opcode sequence in the cache
func (c *OpCodeCache) Set(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = value
}

// Clear removes all entries from the cache
func (c *OpCodeCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string][]byte)
}
