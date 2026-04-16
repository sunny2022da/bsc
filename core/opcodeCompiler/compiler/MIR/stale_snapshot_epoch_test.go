package MIR

// Tests for the snapshotEpoch / incomingSnapshotEpoch stale-detection mechanism.
//
// The mechanism detects when evalPhi's snapshot-fallback (step 2) would use a
// runtime-written incoming snapshot that belongs to a DIFFERENT execution context
// (i.e. a different calldata / state). This is the root cause of the bad-block
// divergence where a "simple" CFG (runtimeEpoch==0) reuses a previous execution's
// snapshot value in a PHI and takes the wrong branch.
//
// The fix introduces a separate snapshotEpoch counter (always-incrementing, does NOT
// trigger block rebuilds) and stores it in incomingSnapshotEpoch when connectEdge is
// called at runtime (parseDone=true). evalPhi step 2 checks this and returns
// ErrMIRInternal when a stale snapshot is detected → safe base-EVM fallback.

import (
	"errors"
	"testing"
)

// TestParseDone_SetAfterParse verifies that cfg.parseDone is true after a
// successful Parse() and false before.
func TestParseDone_SetAfterParse(t *testing.T) {
	// PUSH1 1; STOP
	code := []byte{0x60, 0x01, 0x00}
	cfg := NewCFG([32]byte{}, code)
	if cfg.parseDone {
		t.Fatal("parseDone should be false before Parse()")
	}
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !cfg.parseDone {
		t.Fatal("parseDone should be true after Parse()")
	}
}

// TestSnapshotEpoch_ParseDoneGate verifies that connectEdge does NOT set
// incomingSnapshotEpoch when parseDone=false (parse-time call), and DOES set it
// when parseDone=true (runtime call) with a changed snapshot.
func TestSnapshotEpoch_ParseDoneGate(t *testing.T) {
	// Use a JUMPI so we have two blocks with an edge.
	// PUSH1 1 (cond); PUSH1 5 (dest); JUMPI; STOP; JUMPDEST(pc=5); STOP
	code := []byte{
		0x60, 0x01, // PUSH1 1 (condition)
		0x60, 0x05, // PUSH1 5 (destination)
		0x57,       // JUMPI
		0x00,       // STOP  (fallthrough at pc=5 if cond==0, but cond=1 so never taken)
		0x5b,       // JUMPDEST at pc=6 — wait, need to match dest=5
		0x00,       // STOP
	}
	// Adjust: dest should be pc=6 (the JUMPDEST). Rebuild:
	// PUSH1 1; PUSH1 6; JUMPI; STOP; JUMPDEST(pc=6); STOP
	code = []byte{
		0x60, 0x01, // PUSH1 1 (cond=true)
		0x60, 0x06, // PUSH1 6 (dest)
		0x57,       // JUMPI (pc=4)
		0x00,       // STOP  (fallthrough, pc=5)
		0x5b,       // JUMPDEST at pc=6
		0x00,       // STOP
	}
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	entryBlock := cfg.pcToBlock[0]
	jumpTarget := cfg.pcToBlock[6]
	if entryBlock == nil || jumpTarget == nil {
		t.Fatalf("blocks not found: entry=%v target=%v", entryBlock, jumpTarget)
	}

	// After Parse(), parseDone=true. Check that no runtime snapshot epoch is set yet
	// (parse-time connectEdge calls should not set incomingSnapshotEpoch).
	if jumpTarget.incomingSnapshotEpoch != nil {
		if ep, ok := jumpTarget.incomingSnapshotEpoch[entryBlock]; ok {
			t.Fatalf("incomingSnapshotEpoch should not be set by parse-time connectEdge, got ep=%d", ep)
		}
	}

	// Now simulate a runtime connectEdge call (parseDone=true, snapshotEpoch=5).
	// Use a snapshot that differs from the parse-time one (add an extra Unknown element).
	cfg.snapshotEpoch = 5
	existingSnap, _ := jumpTarget.incomingStacks[entryBlock]
	differentSnap := make([]Value, len(existingSnap)+1) // guaranteed to differ (longer)
	cfg.connectEdge(entryBlock, jumpTarget, differentSnap)

	if jumpTarget.incomingSnapshotEpoch == nil {
		t.Fatal("incomingSnapshotEpoch not set after runtime connectEdge")
	}
	ep, ok := jumpTarget.incomingSnapshotEpoch[entryBlock]
	if !ok {
		t.Fatal("incomingSnapshotEpoch[entryBlock] not set")
	}
	if ep != 5 {
		t.Fatalf("expected incomingSnapshotEpoch=5, got %d", ep)
	}
}

// TestEvalPhi_StaleSnapshotEpoch_ErrMIRInternal verifies that evalPhi step 2
// (snapshot fallback) returns ErrMIRInternal when the snapshot was written in a
// different execution (different snapshotEpoch).
//
// This is the bug scenario: contract executed N times with the same cached CFG.
// Run N wrote incomingStacks[parent] with snapshotEpoch=N. Run N+1 (snapshotEpoch=N+1)
// would use that stale snapshot if the check were absent → wrong PHI value → bad block.
func TestEvalPhi_StaleSnapshotEpoch_ErrMIRInternal(t *testing.T) {
	// Build a minimal CFG: two blocks (parent → child) connected manually.
	// We do not need real bytecode; we manipulate internals directly.
	cfg := &CFG{
		snapshotEpoch: 2, // current execution is epoch 2
	}
	cfg.nextResIdx = 1

	parent := &MIRBasicBlock{blockNum: 0, firstPC: 0}
	child := &MIRBasicBlock{blockNum: 1, firstPC: 10}

	// Set up child's parents and incoming stacks as if connectEdge ran during epoch 1.
	child.parents = []*MIRBasicBlock{parent}
	child.incomingStacks = map[*MIRBasicBlock][]Value{
		parent: {{kind: Konst}}, // one-element snapshot from epoch 1
	}
	child.incomingSnapshotEpoch = map[*MIRBasicBlock]uint64{
		parent: 1, // written at epoch 1 — STALE for current epoch 2
	}

	// Create a PHI with no operands so evalPhi always falls to snapshot step 2.
	phi := &MIR{op: MirPHI, phiStackIndex: 0}

	it := NewMIRInterpreter(cfg)

	_, err := it.evalPhi(child, parent, phi)
	if err == nil {
		t.Fatal("expected ErrMIRInternal for stale snapshot, got nil")
	}
	if !errors.Is(err, ErrMIRInternal) {
		t.Fatalf("expected ErrMIRInternal, got: %v", err)
	}
}

// TestEvalPhi_FreshSnapshotEpoch_NoError verifies that evalPhi step 2 does NOT
// return ErrMIRInternal when the snapshot was written in the CURRENT execution
// (same snapshotEpoch).
func TestEvalPhi_FreshSnapshotEpoch_NoError(t *testing.T) {
	cfg := &CFG{
		snapshotEpoch: 2, // current execution is epoch 2
	}
	cfg.nextResIdx = 1

	parent := &MIRBasicBlock{blockNum: 0, firstPC: 0}
	child := &MIRBasicBlock{blockNum: 1, firstPC: 10}

	child.parents = []*MIRBasicBlock{parent}
	// Snapshot value: a constant 0x42
	constVal := Value{kind: Konst}
	child.incomingStacks = map[*MIRBasicBlock][]Value{
		parent: {constVal},
	}
	child.incomingSnapshotEpoch = map[*MIRBasicBlock]uint64{
		parent: 2, // written at epoch 2 — FRESH for current epoch 2
	}

	phi := &MIR{op: MirPHI, phiStackIndex: 0}

	it := NewMIRInterpreter(cfg)

	// evalPhi should not return ErrMIRInternal (snapshot is fresh).
	// It will proceed past the staleness check and may return a value or a different error.
	_, err := it.evalPhi(child, parent, phi)
	if errors.Is(err, ErrMIRInternal) {
		t.Fatalf("did not expect ErrMIRInternal for fresh snapshot, got: %v", err)
	}
}

// TestEvalPhi_ParseTimeSnapshot_NoError verifies that parse-time snapshots
// (no entry in incomingSnapshotEpoch) are never rejected as stale.
// This is critical for the performance of stable contracts like USDT/WBNB.
func TestEvalPhi_ParseTimeSnapshot_NoError(t *testing.T) {
	cfg := &CFG{
		snapshotEpoch: 99, // any epoch — parse-time snapshot has no epoch entry
	}
	cfg.nextResIdx = 1

	parent := &MIRBasicBlock{blockNum: 0, firstPC: 0}
	child := &MIRBasicBlock{blockNum: 1, firstPC: 10}

	child.parents = []*MIRBasicBlock{parent}
	constVal := Value{kind: Konst}
	child.incomingStacks = map[*MIRBasicBlock][]Value{
		parent: {constVal},
	}
	// incomingSnapshotEpoch is nil (parse-time snapshot, not runtime-written).
	// The staleness check must not fire.

	phi := &MIR{op: MirPHI, phiStackIndex: 0}

	it := NewMIRInterpreter(cfg)

	_, err := it.evalPhi(child, parent, phi)
	if errors.Is(err, ErrMIRInternal) {
		t.Fatalf("parse-time snapshot must not be rejected as stale: %v", err)
	}
}
