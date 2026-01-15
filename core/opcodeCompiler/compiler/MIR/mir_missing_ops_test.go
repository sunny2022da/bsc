package MIR

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

func mustDecodeHexMissingOps(t *testing.T, s string) []byte {
	t.Helper()
	s = trim0xMissingOps(t, s)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func trim0xMissingOps(t *testing.T, s string) string {
	t.Helper()
	if len(s) >= 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}

func runCodeReturnWord(t *testing.T, code []byte, st StateBackend) [32]byte {
	t.Helper()
	cfg := NewCFG([32]byte{}, code)
	if err := cfg.Parse(); err != nil {
		t.Fatalf("CFG.Parse: %v", err)
	}
	it := NewMIRInterpreter(cfg)
	it.SetGasLimit(1_000_000)
	it.SetContractAddress(common.HexToAddress("0x00000000000000000000000000000000000000aa"))
	if st != nil {
		it.SetStateBackend(st)
	}
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
	var out [32]byte
	copy(out[:], res.ReturnData)
	return out
}

func TestMIR_MULMOD_Implemented(t *testing.T) {
	// (7 * 11) % 13 = 12
	// bytecode: PUSH1 0x0d; PUSH1 0x0b; PUSH1 0x07; MULMOD; PUSH1 0; MSTORE; PUSH1 0x20; PUSH1 0; RETURN
	code := mustDecodeHexMissingOps(t, "600d600b60070960005260206000f3")
	got := runCodeReturnWord(t, code, nil)
	if u := uint256.NewInt(0).SetBytes(got[:]); u.Uint64() != 12 {
		t.Fatalf("expected 12, got %s", u.String())
	}
}

func TestMIR_SIGNEXTEND_Implemented(t *testing.T) {
	// SIGNEXTEND 0x00, 0x80 => 0xffff..ff80
	// bytecode: PUSH1 0x80; PUSH1 0x00; SIGNEXTEND; PUSH1 0; MSTORE; PUSH1 0x20; PUSH1 0; RETURN
	code := mustDecodeHexMissingOps(t, "608060000b60005260206000f3")
	got := runCodeReturnWord(t, code, nil)
	// Expect top 31 bytes 0xff, last byte 0x80.
	for i := 0; i < 31; i++ {
		if got[i] != 0xff {
			t.Fatalf("expected got[%d]=0xff, got=0x%x", i, got[i])
		}
	}
	if got[31] != 0x80 {
		t.Fatalf("expected got[31]=0x80, got=0x%x", got[31])
	}
}

func TestMIR_TLOAD_TSTORE_Implemented(t *testing.T) {
	// Store then load transient slot 0 and return it.
	// value = 0xabcdef00000000000000abba000000000deaf000000c0de00100000000133700 (32 bytes)
	// bytecode:
	//   PUSH32 value
	//   PUSH1 0x00
	//   TSTORE
	//   PUSH1 0x00
	//   TLOAD
	//   PUSH1 0x00
	//   MSTORE
	//   PUSH1 0x20
	//   PUSH1 0x00
	//   RETURN
	code := mustDecodeHexMissingOps(t,
		"7fabcdef00000000000000abba000000000deaf000000c0de00100000000133700"+
			"60005d60005c60005260206000f3")
	st := NewInMemoryState()
	got := runCodeReturnWord(t, code, st)

	want := mustDecodeHexMissingOps(t, "abcdef00000000000000abba000000000deaf000000c0de00100000000133700")
	if len(want) != 32 {
		t.Fatalf("bad test vector length: %d", len(want))
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("expected %x, got %x", want, got)
	}
}


