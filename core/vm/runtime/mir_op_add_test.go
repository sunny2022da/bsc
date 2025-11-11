package runtime

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// makeCodeADD returns bytecode which computes (a+b), stores it at memory[0..32), and returns 32 bytes
// Layout:
//
//	PUSH1 a; PUSH1 b; ADD; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
func makeCodeADD(a, b byte) []byte {
	return []byte{
		0x60, a, // PUSH1 a
		0x60, b, // PUSH1 b
		0x01,       // ADD
		0x60, 0x00, // PUSH1 0 (offset)
		0x52,       // MSTORE (offset, value)
		0x60, 0x20, // PUSH1 32 (size)
		0x60, 0x00, // PUSH1 0 (offset)
		0xf3, // RETURN
	}
}

// runWithCfg executes given bytecode using a fresh runtime environment with provided VM config.
func runWithCfg(code []byte, cfg vm.Config) ([]byte, error) {
	ret, _, err := Execute(code, nil, &Config{
		ChainConfig: params.MainnetChainConfig,
		Origin:      common.Address{},
		BlockNumber: big.NewInt(1),
		GasLimit:    10_000_000,
		EVMConfig:   cfg,
	})
	return ret, err
}

func TestMIR_Op_ADD_Parity(t *testing.T) {
	// Ensure MIR opcode parsing is enabled for MIR-backed execution
	compiler.EnableOpcodeParse()

	code := makeCodeADD(0x03, 0x05) // 3 + 5 = 8

	baseCfg := vm.Config{EnableOpcodeOptimizations: false}
	mirCfg := vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true}

	rb, errB := runWithCfg(code, baseCfg)
	if errB != nil {
		t.Fatalf("base EVM err: %v", errB)
	}
	rm, errM := runWithCfg(code, mirCfg)
	if errM != nil {
		t.Fatalf("MIR EVM err: %v", errM)
	}

	if len(rb) != 32 || len(rm) != 32 {
		t.Fatalf("unexpected returndata size: base=%d mir=%d", len(rb), len(rm))
	}
	for i := 0; i < 31; i++ { // high 31 bytes should be 0
		if rb[i] != 0 || rm[i] != 0 {
			t.Fatalf("non-zero high bytes: base=%x mir=%x", rb, rm)
		}
	}
	if rb[31] != 0x08 || rm[31] != 0x08 {
		t.Fatalf("ADD result mismatch: base=%x mir=%x", rb, rm)
	}
}

func BenchmarkMIR_Op_ADD(b *testing.B) {
	compiler.EnableOpcodeParse()
	code := makeCodeADD(0x11, 0x22) // 17 + 34 = 51

	b.Run("Base", func(b *testing.B) {
		cfg := vm.Config{EnableOpcodeOptimizations: false}
		// Prime once
		if _, err := runWithCfg(code, cfg); err != nil {
			b.Fatalf("base priming err: %v", err)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := runWithCfg(code, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("MIR", func(b *testing.B) {
		cfg := vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true}
		// Prime once (also builds MIR CFG cache)
		if _, err := runWithCfg(code, cfg); err != nil {
			b.Fatalf("mir priming err: %v", err)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := runWithCfg(code, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// makeCodeManyADD returns bytecode that performs n additions with constant increment
// using an accumulator to keep stack height constant:
//
//	PUSH1 seed; repeat n times: (PUSH1 inc; ADD); MSTORE; RETURN
//
// This avoids growing the stack beyond limit.
func makeCodeManyADD(n int, seed, inc byte) []byte {
	if n < 1 {
		n = 1
	}
	code := make([]byte, 0, 2+n*2+6) // PUSH1 seed + n*(PUSH1,ADD) + trailer
	// seed
	code = append(code, 0x60, seed) // PUSH1 seed
	for i := 0; i < n; i++ {
		code = append(code,
			0x60, inc, // PUSH1 inc
			0x01, // ADD
		)
	}
	// MSTORE and RETURN
	code = append(code,
		0x60, 0x00, // PUSH1 0 (offset)
		0x52,       // MSTORE (offset, value)
		0x60, 0x20, // PUSH1 32 (size)
		0x60, 0x00, // PUSH1 0 (offset)
		0xf3, // RETURN
	)
	return code
}

// Benchmark many ADDs to amortize MIR setup overhead
func BenchmarkMIR_Op_ADD_Many(b *testing.B) {
	compiler.EnableOpcodeParse()
	code := makeCodeManyADD(2000, 0x00, 0x01) // 2000 ADDs of +1 starting from 0

	b.Run("BaseMany", func(b *testing.B) {
		cfg := vm.Config{EnableOpcodeOptimizations: false}
		if _, err := runWithCfg(code, cfg); err != nil {
			b.Fatalf("base priming err: %v", err)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := runWithCfg(code, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("MIRMany", func(b *testing.B) {
		cfg := vm.Config{EnableOpcodeOptimizations: true, EnableMIR: true, EnableMIRInitcode: true}
		if _, err := runWithCfg(code, cfg); err != nil {
			b.Fatalf("mir priming err: %v", err)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := runWithCfg(code, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}
