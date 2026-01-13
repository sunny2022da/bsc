package MIR

import (
	"encoding/hex"
	"testing"
)

func TestDynamicCFGExpansion_Example_TwoTargets(t *testing.T) {
	// This example demonstrates a partially-built CFG at compile time and CFG expansion at runtime.
	//
	// Entry computes a jump destination from calldata and jumps there:
	//   dest = 0x20 + ((CALLDATALOAD(0) & 1) * 0x10)
	// So dest is either 0x20 or 0x30 depending on the last bit of calldata[0..31].
	//
	// Both targets are valid JUMPDESTs and return different constants (0xAA vs 0xBB).
	codeHex := "600035600116601002602001565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b60aa60005260206000f35b5b5b5b5b5b60bb60005260206000f3"
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
		t.Fatalf("expected entry.unresolvedJump=true (dynamic dest depends on calldata)")
	}
	if len(entry.Children()) != 0 {
		t.Fatalf("expected no children after Parse (dynamic jump), got %d", len(entry.Children()))
	}
	if cfg.pcToBlock[0x20] != nil || cfg.pcToBlock[0x30] != nil {
		t.Fatalf("expected targets to not exist before runtime backfill")
	}

	// Run #1: calldata LSB=0 -> dest=0x20 -> returns 0xAA.
	{
		it := NewMIRInterpreter(cfg)
		it.SetGasLimit(1_000_000)
		calldata := make([]byte, 32)
		calldata[31] = 0x00
		it.SetCallData(calldata)
		res := it.Run()
		if res.Err != nil {
			t.Fatalf("run1 error: %v", res.Err)
		}
		if res.HaltOp != MirRETURN {
			t.Fatalf("run1 expected RETURN, got %s", res.HaltOp.String())
		}
		if len(res.ReturnData) != 32 || res.ReturnData[31] != 0xAA {
			t.Fatalf("run1 unexpected return: len=%d last=0x%02x", len(res.ReturnData), func() byte {
				if len(res.ReturnData) == 0 {
					return 0
				}
				return res.ReturnData[len(res.ReturnData)-1]
			}())
		}
	}

	// After run #1, the CFG should have discovered target 0x20.
	if cfg.pcToBlock[0x20] == nil {
		t.Fatalf("expected block @0x20 created after runtime backfill (run1)")
	}

	// Run #2: calldata LSB=1 -> dest=0x30 -> returns 0xBB.
	{
		it := NewMIRInterpreter(cfg)
		it.SetGasLimit(1_000_000)
		calldata := make([]byte, 32)
		calldata[31] = 0x01
		it.SetCallData(calldata)
		res := it.Run()
		if res.Err != nil {
			t.Fatalf("run2 error: %v", res.Err)
		}
		if res.HaltOp != MirRETURN {
			t.Fatalf("run2 expected RETURN, got %s", res.HaltOp.String())
		}
		if len(res.ReturnData) != 32 || res.ReturnData[31] != 0xBB {
			t.Fatalf("run2 unexpected return: len=%d last=0x%02x", len(res.ReturnData), func() byte {
				if len(res.ReturnData) == 0 {
					return 0
				}
				return res.ReturnData[len(res.ReturnData)-1]
			}())
		}
	}

	// After both runs, CFG is "more complete": both dynamic targets exist and should be children of entry.
	if cfg.pcToBlock[0x30] == nil {
		t.Fatalf("expected block @0x30 created after runtime backfill (run2)")
	}
	found20, found30 := false, false
	for _, ch := range entry.Children() {
		if ch == nil {
			continue
		}
		if ch.firstPC == 0x20 {
			found20 = true
		}
		if ch.firstPC == 0x30 {
			found30 = true
		}
	}
	if !found20 || !found30 {
		t.Fatalf("expected entry to have children {0x20,0x30} after both runs, got found20=%v found30=%v", found20, found30)
	}
}
