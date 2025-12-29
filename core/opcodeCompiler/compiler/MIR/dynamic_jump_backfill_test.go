package MIR

import (
	"encoding/hex"
	"testing"
)

func TestDynamicJumpBackfill_ConnectsEdgeAndBuildsTarget(t *testing.T) {
	// Build-time dest is non-constant (ADD result), so builder marks unresolvedJump and does not connect edge.
	// Runtime dest becomes 0x0a and should jump to JUMPDEST at pc=10.
	codeHex := "600560050156000000005b00"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	entry := cfg.pcToBlock[0]
	if entry == nil {
		t.Fatalf("missing entry block")
	}
	if !entry.unresolvedJump {
		t.Fatalf("expected entry.unresolvedJump=true")
	}
	if len(entry.Children()) != 0 {
		t.Fatalf("expected no children before runtime backfill, got %d", len(entry.Children()))
	}

	it := NewMIRInterpreter(cfg)
	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if res.HaltOp != MirSTOP {
		t.Fatalf("expected STOP, got %s", res.HaltOp.String())
	}

	target := cfg.pcToBlock[10]
	if target == nil {
		t.Fatalf("expected target block at pc=10 after runtime backfill")
	}
	if !target.built {
		t.Fatalf("expected target block built")
	}
	// Edge should now exist.
	found := false
	for _, ch := range entry.Children() {
		if ch != nil && ch.firstPC == 10 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected entry to have child pc=10 after runtime backfill")
	}
	if target.incomingStacks[entry] == nil {
		t.Fatalf("expected incoming stack recorded for (entry->target)")
	}
}

func TestDynamicJumpBackfill_InvalidJumpdestErrors(t *testing.T) {
	// Jump to pc=9 (not a JUMPDEST) => should error.
	// PUSH1 4; PUSH1 5; ADD (=9); JUMP; [..] no JUMPDEST at 9
	codeHex := "600460050156000000005b00"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	it := NewMIRInterpreter(cfg)
	res := it.Run()
	if res.Err == nil {
		t.Fatalf("expected invalid jumpdest error, got nil")
	}
}
