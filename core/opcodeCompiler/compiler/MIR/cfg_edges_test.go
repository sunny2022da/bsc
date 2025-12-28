package MIR

import (
	"encoding/hex"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func mustParseCFG(t *testing.T, codeHex string) *CFG {
	t.Helper()
	cfg := NewCFG([32]byte{}, mustDecodeHex(t, codeHex))
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return cfg
}

func mustBlockAt(t *testing.T, cfg *CFG, pc uint) *MIRBasicBlock {
	t.Helper()
	if cfg == nil || cfg.pcToBlock == nil {
		t.Fatalf("nil cfg/pcToBlock")
	}
	b := cfg.pcToBlock[pc]
	if b == nil {
		t.Fatalf("expected block at pc=%d, got nil", pc)
	}
	return b
}

func childPCs(b *MIRBasicBlock) map[uint]bool {
	out := make(map[uint]bool)
	if b == nil {
		return out
	}
	for _, ch := range b.Children() {
		if ch == nil {
			continue
		}
		out[ch.FirstPC()] = true
	}
	return out
}

func parentPCs(b *MIRBasicBlock) map[uint]bool {
	out := make(map[uint]bool)
	if b == nil {
		return out
	}
	for _, p := range b.Parents() {
		if p == nil {
			continue
		}
		out[p.FirstPC()] = true
	}
	return out
}

func TestCFGEdges_JUMPIHasTwoEdges(t *testing.T) {
	// PUSH1 1; PUSH1 0x0a; JUMPI;
	// fallthrough: PUSH1 0x11; PUSH1 0x10; JUMP;
	// taken:       JUMPDEST; PUSH1 0x22; PUSH1 0x10; JUMP;
	// merge:       JUMPDEST; POP; STOP
	cfg := mustParseCFG(t, "6001600a5760116010565b60226010565b5000")

	entry := mustBlockAt(t, cfg, 0)
	// JUMPI at pc=4, so fallthrough opcode starts at pc=5.
	wantChildren := map[uint]bool{5: true, 10: true}
	got := childPCs(entry)
	for pc := range wantChildren {
		if !got[pc] {
			t.Fatalf("entry missing child pc=%d, got=%v", pc, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 children for JUMPI, got %d (%v)", len(got), got)
	}

	// Parent links should be present too.
	ft := mustBlockAt(t, cfg, 5)
	if !parentPCs(ft)[0] {
		t.Fatalf("expected fallthrough block to have parent at pc=0")
	}
	taken := mustBlockAt(t, cfg, 10)
	if !parentPCs(taken)[0] {
		t.Fatalf("expected taken block to have parent at pc=0")
	}
}

func TestCFGEdges_FallthroughSplitsAtJumpdest(t *testing.T) {
	// PUSH1 1; PUSH1 2; JUMPDEST; STOP
	// The JUMPDEST must start a new basic block.
	cfg := mustParseCFG(t, "600160025b00")

	b0 := mustBlockAt(t, cfg, 0)
	bJD := mustBlockAt(t, cfg, 4)
	if b0 == bJD {
		t.Fatalf("expected JUMPDEST pc=4 to start a different block than entry")
	}
	if !childPCs(b0)[4] {
		t.Fatalf("expected entry to have fallthrough edge to pc=4, got=%v", childPCs(b0))
	}
	if !parentPCs(bJD)[0] {
		t.Fatalf("expected pc=4 block to have parent pc=0")
	}
}

func TestCFGEdges_JUMPTerminatesBlock(t *testing.T) {
	// PUSH1 3; JUMP; JUMPDEST; STOP
	cfg := mustParseCFG(t, "6003565b00")

	b0 := mustBlockAt(t, cfg, 0)
	b3 := mustBlockAt(t, cfg, 3)
	got := childPCs(b0)
	if len(got) != 1 || !got[3] {
		t.Fatalf("expected JUMP block to have exactly one child pc=3, got=%v", got)
	}
	if !parentPCs(b3)[0] {
		t.Fatalf("expected pc=3 block to have parent pc=0")
	}
}


