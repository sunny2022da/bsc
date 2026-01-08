package MIR

import (
	"encoding/hex"
	"testing"
)

func TestDynamicJumpBackfill_ConnectsEdgeAndBuildsTarget(t *testing.T) {
	// Build-time dest is non-constant (CALLDATALOAD result), so builder marks unresolvedJump and does not connect edge.
	// Runtime dest becomes 0x0a (from calldata) and should jump to JUMPDEST at pc=10.
	//
	// PUSH1 0x00; CALLDATALOAD; JUMP; [padding]; JUMPDEST(at pc=10); STOP
	codeHex := "600035560000000000005b00"
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
	// Provide calldata such that CALLDATALOAD(0) yields 0x0a.
	calldata := make([]byte, 32)
	calldata[31] = 0x0a
	it.SetCallData(calldata)
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
	// Jump to pc=9 (not a JUMPDEST) => should error at runtime.
	// Build-time dest is non-constant (CALLDATALOAD result) so Parse succeeds.
	codeHex := "600035560000000000005b00"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	it := NewMIRInterpreter(cfg)
	// Provide calldata such that CALLDATALOAD(0) yields 0x09 (not a JUMPDEST).
	calldata := make([]byte, 32)
	calldata[31] = 0x09
	it.SetCallData(calldata)
	res := it.Run()
	if res.Err == nil {
		t.Fatalf("expected invalid jumpdest error, got nil")
	}
}
