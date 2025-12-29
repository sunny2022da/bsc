package MIR

import (
	"encoding/hex"
	"testing"
)

func TestCFG_PhiFixpoint_LoopHeader(t *testing.T) {
	// Construct a loop where the loop header (pc=5) has two incoming stacks:
	// - from entry: [0]
	// - from backedge: [i+1]
	//
	// 0: PUSH1 0
	// 2: PUSH1 5
	// 4: JUMP
	// 5: JUMPDEST
	// 6: DUP1
	// 7: PUSH1 1
	// 9: ADD
	// 10: SWAP1
	// 11: POP
	// 12: PUSH1 5
	// 14: JUMP
	codeHex := "60006005565b806001019050600556"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	loop := cfg.pcToBlock[5]
	if loop == nil {
		t.Fatalf("expected loop header block at pc=5")
	}
	// Should have at least entry + backedge as parents.
	pmap := map[uint]bool{}
	for _, p := range loop.Parents() {
		if p != nil {
			pmap[p.FirstPC()] = true
		}
	}
	if !pmap[0] {
		t.Fatalf("expected loop header to have entry parent pc=0, got %v", pmap)
	}
	if !pmap[5] {
		t.Fatalf("expected loop header to have backedge parent pc=5 (self), got %v", pmap)
	}
	// A PHI must be created to merge [0] and [i+1].
	foundPhi := false
	for _, ins := range loop.Instructions() {
		if ins != nil && ins.op == MirPHI {
			foundPhi = true
			break
		}
	}
	if !foundPhi {
		t.Fatalf("expected MirPHI in loop header instructions")
	}
}


