package MIR

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Protect against non-terminating CFG build/fixpoint loops on a large real-world contract runtime.
func TestUSDT_RuntimeCFG_ParseTerminates(t *testing.T) {
	rawHex, err := os.ReadFile("test_contact/usdt_runtime_code.hex")
	if err != nil {
		t.Skipf("runtime bytecode fixture missing: %v", err)
	}
	codeStr := trimHex(string(rawHex))
	code, err := hex.DecodeString(codeStr)
	if err != nil {
		t.Fatalf("invalid runtime hex: %v", err)
	}

	cfg := NewCFG(common.Hash{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	// USDT runtime should produce many blocks; sanity-check it's not trivially small.
	if len(cfg.basicBlocks) < 10 {
		t.Fatalf("expected >=10 basic blocks, got %d", len(cfg.basicBlocks))
	}
}

func trimHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}


