package MIR

import (
	"encoding/hex"
	"testing"
)

func TestMIRInterpreter_PhiAndJump(t *testing.T) {
	// Bytecode used to validate PHI merge + JUMPI control flow:
	// PUSH1 1; PUSH1 0x0a; JUMPI;
	// else: PUSH1 0x11; PUSH1 0x10; JUMP;
	// then: JUMPDEST; PUSH1 0x22; PUSH1 0x10; JUMP;
	// merge: JUMPDEST; POP; STOP
	codeHex := "6001600a5760116010565b60226010565b5000"
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
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if res.HaltOp != MirSTOP {
		t.Fatalf("expected STOP, got %s", res.HaltOp.String())
	}
}


