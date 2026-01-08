package MIR

import "testing"

func TestCFG_ConstantFold_ResolvesJumpDest(t *testing.T) {
	// This program computes a constant jump destination through SHL, then JUMPs.
	// Without constant folding, the dest is a Variable and the block would be marked unresolved.
	//
	// 0x00: PUSH1 0x02
	// 0x02: PUSH1 0x03
	// 0x04: SHL              // result = 0x10 (16) under MIRInterpreter semantics
	// 0x05: JUMP
	// 0x06..0x0f: STOP padding
	// 0x10: JUMPDEST
	// 0x11: STOP
	code := []byte{
		0x60, 0x02, // PUSH1 0x02
		0x60, 0x03, // PUSH1 0x03
		0x1b, // SHL
		0x56, // JUMP
		// padding to reach pc=0x10
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x5b, // JUMPDEST (pc=0x10)
		0x00, // STOP
	}

	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	entry := cfg.pcToBlock[0]
	if entry == nil {
		t.Fatalf("missing entry block at pc=0")
	}
	if entry.unresolvedJump {
		t.Fatalf("expected entry.unresolvedJump=false (jump dest should be folded to const)")
	}
	target := cfg.pcToBlock[0x10]
	if target == nil {
		t.Fatalf("missing target block at pc=0x10")
	}
	found := false
	for _, ch := range entry.Children() {
		if ch == target {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected edge entry->target (pc=0x10) after constant folding")
	}
}


