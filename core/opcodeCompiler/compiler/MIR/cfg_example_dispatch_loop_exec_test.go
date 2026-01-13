package MIR

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/holiman/uint256"
)

func loadHexFileFirstLine(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		t.Fatalf("read %s: %v", path, err)
	}
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "0x")
	if line == "" {
		t.Fatalf("%s: empty hex", path)
	}
	code, err := hex.DecodeString(line)
	if err != nil {
		t.Fatalf("%s: decode hex: %v", path, err)
	}
	return code
}

func TestCFGExampleDispatchLoop_ExecutesBlock3Phi(t *testing.T) {
	// This test is designed for debugging via breakpoints:
	// - build CFG from cfg_example_dispatch_loop.hex
	// - execute it with calldata that forces the loop path
	// - ensure block @0x40 (\"block3\" in mir_visualizer output) executes and its MirPHI nodes run
	code := loadHexFileFirstLine(t, "test_contact/cfg_example_dispatch_loop.hex")

	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("CFG.Parse: %v", err)
	}

	it := NewMIRInterpreter(cfg)
	it.SetGasLimit(1_000_000)

	// Dispatch logic:
	//   selector := (CALLDATALOAD(0) >> 224)
	//   if selector == 0x11111111 => jump to 0x20 (return 42)
	// We want the loop path (fallthrough to pc=0x0f), so choose a different selector (0x00000000).
	it.SetCallData(make([]byte, 32))

	// For breakpoint-driven debugging:
	// - set a breakpoint in evalPhi(...) to see how PHI picks an incoming value based on (cur,prev).
	// - this hook is optional and can help when you don't want to step through evalPhi.
	var phiHookCalls int
	it.SetDebugPhiHook(func(curFirstPC uint, prevFirstPC uint, phiPC uint, phiStackIndex int, incomingLen int, incomingIdx int, val uint256.Int) {
		phiHookCalls++
	})

	var phiExec int
	var enteredBody bool
	seenOps := make(map[MirOperation]int, 32)
	it.SetStepHook(func(evmPC uint, evmOp byte, op MirOperation) {
		// CurrentBlockFirstPC is set before the step hook fires.
		seenOps[op]++
		switch it.CurrentBlockFirstPC() {
		case 0x50:
			enteredBody = true
		}
		if op == MirPHI {
			phiExec++
		}
	})

	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if res.HaltOp != MirRETURN {
		t.Fatalf("expected RETURN, got %s", res.HaltOp.String())
	}
	if len(res.ReturnData) != 32 {
		t.Fatalf("expected 32-byte return, got %d bytes", len(res.ReturnData))
	}
	// Exit path stores `sum` to memory[0..32) and returns it. Loop sums 0+1+2 = 3.
	if u := uint256.NewInt(0).SetBytes(res.ReturnData); u.Uint64() != 3 {
		t.Fatalf("expected return word=3, got %s", u.String())
	}

	// Sanity: loop should execute its body at least once and the loop header should execute PHIs.
	if !enteredBody {
		t.Fatalf("expected loop body block @0x50 to execute at least once")
	}
	if phiExec == 0 {
		t.Fatalf("expected MirPHI ops to execute at least once; seenOps=%v", seenOps)
	}

	// Note: debugPhiHook is best-effort (it only fires on some evalPhi paths).
	_ = phiHookCalls
}


