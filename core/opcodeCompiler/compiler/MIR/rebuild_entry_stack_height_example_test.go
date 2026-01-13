package MIR

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/log"
)

func dumpCFGForTest(t *testing.T, tag string, cfg *CFG) {
	t.Helper()
	if t == nil || cfg == nil {
		return
	}
	type row struct {
		pc         uint
		entryLen   int
		built      bool
		unresolved bool
		parents    []uint
		children   []uint
	}
	var rows []row
	for _, b := range cfg.basicBlocks {
		if b == nil {
			continue
		}
		r := row{
			pc:         b.firstPC,
			built:      b.built,
			unresolved: b.unresolvedJump,
			entryLen: func() int {
				if b.entryStack == nil {
					return -1
				}
				return len(b.entryStack)
			}(),
		}
		for _, p := range b.parents {
			if p != nil {
				r.parents = append(r.parents, p.firstPC)
			}
		}
		for _, c := range b.children {
			if c != nil {
				r.children = append(r.children, c.firstPC)
			}
		}
		sort.Slice(r.parents, func(i, j int) bool { return r.parents[i] < r.parents[j] })
		sort.Slice(r.children, func(i, j int) bool { return r.children[i] < r.children[j] })
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].pc < rows[j].pc })

	t.Logf("=== CFG DUMP: %s ===", tag)
	for _, r := range rows {
		t.Logf("B@0x%02x built=%v unresolvedJump=%v entryLen=%d parents=%v children=%v",
			r.pc, r.built, r.unresolved, r.entryLen, r.parents, r.children)
	}
	// Also dump the special target block T@0x50 and its incoming stack lengths (per predecessor).
	if tgt := cfg.pcToBlock[0x50]; tgt != nil {
		keys := make([]uint, 0, len(tgt.incomingStacks))
		inLens := make(map[uint]int, len(tgt.incomingStacks))
		for p, in := range tgt.incomingStacks {
			if p == nil {
				continue
			}
			keys = append(keys, p.firstPC)
			if in == nil {
				inLens[p.firstPC] = -1
			} else {
				inLens[p.firstPC] = len(in)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("0x%02x:%d", k, inLens[k]))
		}
		t.Logf("T@0x50 incomingStacks lens by parent: %v", parts)
	}
}

func TestRebuildEntryStackHeightExample(t *testing.T) {
	// Enable WARN-level geth logging for this test so the throttled mismatch warning
	// added in MIRInterpreter.RunFrom is visible in `go test -v`.
	// By default, go-ethereum/log uses DiscardHandler in init(), so nothing prints.
	old := log.Root()
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelWarn, false)))
	defer log.SetDefault(old)

	// Synthetic example demonstrating why RunFrom may rebuild a block when the same JUMPDEST
	// is reached with different incoming stack heights (due to incremental CFG discovery).
	//
	// Layout:
	// - Entry chooses between:
	//   - P1: static jump to T with stack height 1 (pushes only b)
	//   - P0: dynamic jump to T with stack height 2 (pushes a,b; dest from calldata)
	//
	// Target block T uses SWAP1 before MSTORE+RETURN. With entry height 1, SWAP1 is a no-op in the
	// builder (stack underflow => no-op). With entry height 2, SWAP1 matters and changes which value
	// is stored/returned. Rebuild is required so T is compiled with the correct entry height for the
	// actual predecessor edge.
	//
	// PCs:
	// - P1 @ 0x30
	// - T  @ 0x50
	codeHex := "60003560011660305760aa60bb602035565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b60bb6050565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b9060005260206000f3"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	dumpCFGForTest(t, "after Parse()", cfg)

	// T exists at parse time due to the static P1 -> T edge.
	tgt := cfg.pcToBlock[0x50]
	if tgt == nil {
		t.Fatalf("expected target block @0x50 to exist after Parse")
	}
	// After Parse, T should have entry stack height 1 (only predecessor known statically is P1 with stack [b]).
	if es := tgt.EntryStack(); es == nil || len(es) != 1 {
		t.Fatalf("expected T entry stack len=1 after Parse, got %v", func() any {
			if es == nil {
				return nil
			}
			return len(es)
		}())
	}

	// Run 1: take P1 path (flag bit0 = 1). This jumps to P1@0x30 and then statically to T@0x50 with stack [b].
	// Expect returned value == b (0xBB).
	{
		it := NewMIRInterpreter(cfg)
		it.SetGasLimit(1_000_000)
		calldata := make([]byte, 64)
		calldata[31] = 0x01 // flag bit0 = 1 => JUMPI to P1
		calldata[63] = 0x50 // dest for P0 (unused in this run)
		it.SetCallData(calldata)
		res := it.Run()
		if res.Err != nil {
			t.Fatalf("run1 error: %v", res.Err)
		}
		if res.HaltOp != MirRETURN {
			t.Fatalf("run1 expected RETURN, got %s", res.HaltOp.String())
		}
		if len(res.ReturnData) != 32 || res.ReturnData[31] != 0xBB {
			t.Fatalf("run1 expected return last byte 0xBB, got len=%d last=0x%02x", len(res.ReturnData), func() byte {
				if len(res.ReturnData) == 0 {
					return 0
				}
				return res.ReturnData[len(res.ReturnData)-1]
			}())
		}
	}
	dumpCFGForTest(t, "after Run1 (P1 path)", cfg)

	// Before run2, the entry stack is still len=1 (compiled for the P1 predecessor).
	if es := tgt.EntryStack(); es == nil || len(es) != 1 {
		t.Fatalf("expected T entry stack len=1 before run2, got %v", func() any {
			if es == nil {
				return nil
			}
			return len(es)
		}())
	}

	// Run 2: take P0 path (flag bit0 = 0) and dynamic jump to T, with stack [a,b] and dest from calldata[0x20].
	// Expect returned value == a (0xAA) after rebuild (because T begins with SWAP1).
	{
		it := NewMIRInterpreter(cfg)
		it.SetGasLimit(1_000_000)
		calldata := make([]byte, 64)
		calldata[31] = 0x00 // flag bit0 = 0 => fallthrough to P0
		calldata[63] = 0x50 // dest word at offset 0x20 => jump to T@0x50
		it.SetCallData(calldata)
		res := it.Run()
		if res.Err != nil {
			t.Fatalf("run2 error: %v", res.Err)
		}
		if res.HaltOp != MirRETURN {
			t.Fatalf("run2 expected RETURN, got %s", res.HaltOp.String())
		}
		if len(res.ReturnData) != 32 || res.ReturnData[31] != 0xAA {
			t.Fatalf("run2 expected return last byte 0xAA, got len=%d last=0x%02x", len(res.ReturnData), func() byte {
				if len(res.ReturnData) == 0 {
					return 0
				}
				return res.ReturnData[len(res.ReturnData)-1]
			}())
		}
	}
	dumpCFGForTest(t, "after Run2 (P0 path; dynamic edge + rebuild)", cfg)

	// After run2, we should have rebuilt T to match the P0 predecessor entry height 2.
	if es := tgt.EntryStack(); es == nil || len(es) != 2 {
		t.Fatalf("expected T entry stack len=2 after run2 rebuild, got %v", func() any {
			if es == nil {
				return nil
			}
			return len(es)
		}())
	}
}
