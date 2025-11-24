package compiler

import (
	"fmt"

	"github.com/holiman/uint256"
)

type ValueKind int

const (
	Konst     ValueKind = 0 + iota
	Arguments           // The input argument
	Variable            // The runtime determined
	Unknown             // Illegal
	Lazy                // Lazy thunk (unmaterialized PHI/Stack item)
)

type Value struct {
	kind    ValueKind
	def     *MIR
	use     []*MIR
	payload []byte
	u       *uint256.Int // pre-decoded constant value (for Konst)
	// liveIn marks that this Value originated from a parent basic block and
	// is considered a cross-BB live-in for the current block during CFG build.
	liveIn bool
	
	// Lazy provides a thunk for lazy materialization of values (e.g. PHI nodes).
	// If set, the value is considered "Lazy" and must be resolved before use.
	// If kind is Lazy, this MUST be set.
	Lazy func() *Value
}

// DebugString returns a human-readable string representation of the value
func (v *Value) DebugString() string {
	if v == nil {
		return "nil"
	}
	switch v.kind {
	case Konst:
		if v.u != nil {
			return fmt.Sprintf("const:0x%x", v.u.Bytes())
		}
		return fmt.Sprintf("const:0x%x", v.payload)
	case Arguments:
		return "arg"
	case Variable:
		if v.def != nil {
			return fmt.Sprintf("var:def@%d", v.def.idx)
		}
		return "var"
	case Lazy:
		return "lazy"
	default:
		return "unknown"
	}
}

// IsConst returns true if the value is a constant
func (v *Value) IsConst() bool {
	return v != nil && v.kind == Konst
}

type ValueStack struct {
	data     []Value
	Resolver func() *Value // Deprecated/Secondary: Lazy loader for stack underflow.
}

func (s *ValueStack) push(ptr *Value) {
	if ptr == nil {
		return
	}
	s.data = append(s.data, *ptr)
}

// resolveValue checks if v is lazy and resolves it if necessary.
func resolveValue(v *Value) *Value {
	if v.kind == Lazy && v.Lazy != nil {
		resolved := v.Lazy()
		if resolved != nil {
			return resolved
		}
	}
	return v
}

func (s *ValueStack) pop() (value Value) {
	if len(s.data) == 0 {
		// Try to resolve from entry stack (legacy/fallback)
		if s.Resolver != nil {
			val := s.Resolver()
			if val != nil {
				return *val
			}
		}
		// Return a default value if stack is empty
		return Value{kind: Unknown}
	}
	
	// Get top value
	idx := len(s.data)-1
	val := s.data[idx]
	
	// Check for Lazy Thunk
	if val.kind == Lazy && val.Lazy != nil {
		resolved := val.Lazy()
		if resolved != nil {
			val = *resolved
			// Update stack with resolved value to avoid re-resolution
			s.data[idx] = val
		}
	}
	
	s.data = s.data[:idx]
	return val
}

func (s *ValueStack) size() int {
	// This size is only the 'materialized' size + local pushes.
	return len(s.data)
}

// resetTo clears the stack and sets it to the given slice.
// It clears the Resolver.
func (s *ValueStack) resetTo(values []Value) {
	s.data = make([]Value, len(values))
	copy(s.data, values)
	s.Resolver = nil
}

// markAllLiveIn marks all values currently in the stack as live-ins.
func (s *ValueStack) markAllLiveIn() {
	for i := range s.data {
		s.data[i].liveIn = true
	}
}

// clone returns a copy of the current stack data.
func (s *ValueStack) clone() []Value {
	copied := make([]Value, len(s.data))
	copy(copied, s.data)
	return copied
}

// peek returns a pointer to the nth item from the top of the stack (0-indexed)
// peek(0) returns the top item, peek(1) returns the second item, etc.
func (s *ValueStack) peek(n int) *Value {
	// Ensure we have enough items in data (Legacy Resolver)
	for len(s.data) <= n {
		if s.Resolver == nil {
			return nil
		}
		val := s.Resolver()
		if val == nil {
			return nil
		}
		s.data = append([]Value{*val}, s.data...)
	}

	if n < 0 || n >= len(s.data) {
		return nil
	}
	// Stack grows from left to right, so top is at the end
	index := len(s.data) - 1 - n
	
	// Check for Lazy Thunk
	if s.data[index].kind == Lazy && s.data[index].Lazy != nil {
		resolved := s.data[index].Lazy()
		if resolved != nil {
			s.data[index] = *resolved
		}
	}
	
	return &s.data[index]
}

// swap exchanges the items at positions i and j from the top of the stack (0-indexed)
func (s *ValueStack) swap(i, j int) {
	// Ensure materialization
	max := i
	if j > max {
		max = j
	}
	// Peek to force materialization/resolution
	v1 := s.peek(i)
	v2 := s.peek(j)
	
	if v1 == nil || v2 == nil {
		return
	}

	if i < 0 || i >= len(s.data) || j < 0 || j >= len(s.data) {
		return
	}
	// Convert to actual array indices
	indexI := len(s.data) - 1 - i
	indexJ := len(s.data) - 1 - j
	s.data[indexI], s.data[indexJ] = s.data[indexJ], s.data[indexI]
}

func newValue(kind ValueKind, def *MIR, u *uint256.Int, payload []byte) *Value {
	return &Value{
		kind:    kind,
		def:     def,
		payload: payload,
		u:       u,
	}
}
