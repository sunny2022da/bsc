package MIR

// Tests for compile-time def-chain tracing of dynamic JUMP destinations.
//
// The core pattern being tested is the "multi-caller internal function return":
//
//   Caller A: PUSH <retA>; PUSH <func>; JUMP → function
//   Caller B: PUSH <retB>; PUSH <func>; JUMP → function
//   Function: JUMPDEST; JUMP  ← dest = PHI(retA, retB)
//
// With traceJumpDestCandidates, the static CFG builder can resolve both retA and retB
// at parse time, connect the edges, and clear unresolvedJump on the function block.

import (
	"encoding/hex"
	"testing"
)

func decodeHexPhiJump(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestStaticPHIJumpTrace_MultiCallerReturn verifies that the static CFG builder
// resolves both return-address targets when a JUMP destination is a MirPHI whose
// operands are compile-time constants.
//
// Bytecode layout (22 bytes):
//
//	pc  0-4 : PUSH1 0x01; PUSH1 0x0a; JUMPI      → if cond(1)≠0, jump to callerA at pc=10
//	                                                  fallthrough → callerB at pc=5
//	pc  5-9 : PUSH1 0x14; PUSH1 0x10; JUMP        → callerB: call func@16, return to 20
//	pc 10-15: JUMPDEST; PUSH1 0x12; PUSH1 0x10; JUMP → callerA: call func@16, return to 18
//	pc 16-17: JUMPDEST; JUMP                       ← function: dest=PHI(18,20)
//	pc 18-19: JUMPDEST; STOP                       ← return site A
//	pc 20-21: JUMPDEST; STOP                       ← return site B
//
// Note: EVM JUMPI pops destination (top) then condition (second), so we
// push condition first, then destination.
func TestStaticPHIJumpTrace_MultiCallerReturn(t *testing.T) {
	// 6001   = PUSH1 0x01    (condition for JUMPI)
	// 600a   = PUSH1 0x0a    (destination 10 = callerA, on top)
	// 57     = JUMPI          (dest=10 if cond=1, fallthrough to pc=5 if cond=0)
	// 6014   = PUSH1 0x14    (return address 20 for callerB)
	// 6010   = PUSH1 0x10    (function address 16)
	// 56     = JUMP
	// 5b     = JUMPDEST       (callerA at pc=10)
	// 6012   = PUSH1 0x12    (return address 18 for callerA)
	// 6010   = PUSH1 0x10    (function address 16)
	// 56     = JUMP
	// 5b     = JUMPDEST       (function at pc=16)
	// 56     = JUMP            (return to caller, dest=PHI(18,20))
	// 5b     = JUMPDEST        (return site A at pc=18)
	// 00     = STOP
	// 5b     = JUMPDEST        (return site B at pc=20)
	// 00     = STOP
	codeHex := "6001600a576014601056" + "5b60126010565b565b005b00"
	code := decodeHexPhiJump(t, codeHex)

	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// --- CFG structure checks ---

	funcBlock := cfg.pcToBlock[16]
	if funcBlock == nil {
		t.Fatalf("missing function block at pc=16")
	}

	// traceJumpDestCandidates should resolve PHI(18,20) and clear unresolvedJump.
	if funcBlock.unresolvedJump {
		t.Errorf("funcBlock.unresolvedJump=true; expected static PHI tracing to resolve it")
	}

	// Both return sites must be children.
	wantTargets := map[uint]bool{18: false, 20: false}
	for _, ch := range funcBlock.Children() {
		if ch != nil {
			wantTargets[ch.firstPC] = true
		}
	}
	for pc, found := range wantTargets {
		if !found {
			t.Errorf("expected funcBlock child at pc=0x%02x, not found; children: %v",
				pc, funcBlock.Children())
		}
	}

	// jumpTable must contain both return sites.
	if funcBlock.jumpTable == nil {
		t.Fatalf("funcBlock.jumpTable is nil after static resolution")
	}
	for pc := range wantTargets {
		if funcBlock.jumpTable[pc] == nil {
			t.Errorf("funcBlock.jumpTable missing entry for pc=0x%02x", pc)
		}
	}

	// --- Execution: follow callerA path (JUMPI taken, cond=1) ---
	// pc=0: PUSH 1; PUSH 10; JUMPI → cond=1 → jump to pc=10
	// pc=10: PUSH 18; PUSH 16; JUMP → jump to pc=16 with retAddr=18
	// pc=16: JUMP → dest=18 (from runtime entry stack) → jump to pc=18
	// pc=18: STOP
	it := NewMIRInterpreter(cfg)
	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if res.HaltOp != MirSTOP {
		t.Errorf("expected MirSTOP, got %v", res.HaltOp)
	}
}

// TestStaticPHIJumpTrace_AllResolved_NoPerfGatePenalty checks that when all JUMP
// targets are resolved via def-chain tracing, the function block does not remain
// marked unresolvedJump.
func TestStaticPHIJumpTrace_AllResolved_NoPerfGatePenalty(t *testing.T) {
	codeHex := "6001600a576014601056" + "5b60126010565b565b005b00"
	code := decodeHexPhiJump(t, codeHex)
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	funcBlock := cfg.pcToBlock[16]
	if funcBlock == nil {
		t.Fatalf("missing block at pc=16")
	}
	if funcBlock.unresolvedJump {
		t.Errorf("funcBlock.unresolvedJump should be false when all PHI operands are constants")
	}
}

// TestStaticPHIJumpTrace_SingleCallerConst ensures the single-caller case still works:
// when only one predecessor pushes the return address, it becomes a Konst (no PHI),
// and the JUMP is already constant-folded by the parser.
//
// Bytecode (10 bytes):
//
//	pc 0-4: PUSH1 0x08; PUSH1 0x06; JUMP   → call func@6, return to 8
//	pc 5  : STOP                            (unreachable padding)
//	pc 6-7: JUMPDEST; JUMP                  ← function, dest=Konst(8)
//	pc 8-9: JUMPDEST; STOP                  ← return site
func TestStaticPHIJumpTrace_SingleCallerConst(t *testing.T) {
	// 6008 = PUSH1 0x08 (return address 8)
	// 6006 = PUSH1 0x06 (function address 6)
	// 56   = JUMP
	// 00   = STOP (padding at pc=5, unreachable)
	// 5b   = JUMPDEST (function at pc=6)
	// 56   = JUMP (return, dest=Konst(8))
	// 5b   = JUMPDEST (return site at pc=8)
	// 00   = STOP
	code := decodeHexPhiJump(t, "6008600656005b565b00")

	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	funcBlock := cfg.pcToBlock[6]
	if funcBlock == nil {
		t.Fatalf("missing block at pc=6")
	}
	// Single caller: return address is constant → no PHI → unresolvedJump=false.
	if funcBlock.unresolvedJump {
		t.Errorf("funcBlock.unresolvedJump should be false for single-constant-caller")
	}
	// Must have child at pc=8.
	found := false
	for _, ch := range funcBlock.Children() {
		if ch != nil && ch.firstPC == 8 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected child at pc=8; children: %v", funcBlock.Children())
	}

	it := NewMIRInterpreter(cfg)
	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if res.HaltOp != MirSTOP {
		t.Errorf("expected STOP, got %v", res.HaltOp)
	}
}
