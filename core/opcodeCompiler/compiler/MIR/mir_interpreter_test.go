package MIR

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
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
	if res.GasUsed == 0 {
		t.Fatalf("expected non-zero gas used")
	}
}

func TestGas_SLoadEIP2929_WarmCold(t *testing.T) {
	it := NewMIRInterpreter(nil)
	it.SetChainRules(params.Rules{IsBerlin: true, IsEIP2929: true})
	it.SetContractAddress(common.HexToAddress("0x0000000000000000000000000000000000000001"))
	st := NewInMemoryState()
	it.SetStateBackend(st)

	var slot common.Hash
	slot[31] = 0x01

	if err := it.chargeSLoadGas(slot); err != nil {
		t.Fatalf("chargeSLoadGas(cold): %v", err)
	}
	if it.gasUsed != params.ColdSloadCostEIP2929 {
		t.Fatalf("expected cold sload gas %d, got %d", params.ColdSloadCostEIP2929, it.gasUsed)
	}
	if err := it.chargeSLoadGas(slot); err != nil {
		t.Fatalf("chargeSLoadGas(warm): %v", err)
	}
	want := params.ColdSloadCostEIP2929 + params.WarmStorageReadCostEIP2929
	if it.gasUsed != want {
		t.Fatalf("expected cold+warm sload gas %d, got %d", want, it.gasUsed)
	}
}

func TestGas_LogCharges_NoExtraMemOnSecondCall(t *testing.T) {
	it := NewMIRInterpreter(nil)
	// Keep rules empty; LOG constant gas is 0 and dynamic gas doesn't depend on forks here.

	newConstU := func(x *uint256.Int) *Value {
		v := newValue(Konst, nil, nil, nil)
		v.u = uint256.NewInt(0).Set(x)
		return v
	}

	off := uint256.NewInt(0)
	sz := uint256.NewInt(32)

	// First LOG0: should include memory expansion + log base + data gas.
	m1 := &MIR{op: MirLOG0, operands: []*Value{newConstU(off), newConstU(sz)}}
	if err := it.chargeLogDynamicGas(m1); err != nil {
		t.Fatalf("chargeLogDynamicGas(1): %v", err)
	}
	first := it.gasUsed
	if first == 0 {
		t.Fatalf("expected non-zero gas for LOG")
	}
	// Second LOG0 with same mem range: memory expansion delta should be 0, so this call adds less.
	m2 := &MIR{op: MirLOG0, operands: []*Value{newConstU(off), newConstU(sz)}}
	if err := it.chargeLogDynamicGas(m2); err != nil {
		t.Fatalf("chargeLogDynamicGas(2): %v", err)
	}
	secondDelta := it.gasUsed - first
	if secondDelta >= first {
		t.Fatalf("expected second LOG delta < first (no mem expansion), got first=%d secondDelta=%d", first, secondDelta)
	}
}

func TestGas_AccountAccessEIP2929_ColdWarmDelta(t *testing.T) {
	it := NewMIRInterpreter(nil)
	it.SetChainRules(params.Rules{IsBerlin: true, IsEIP2929: true})
	st := NewInMemoryState()
	it.SetStateBackend(st)

	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	start := it.gasUsed
	if err := it.chargeAccountAccessDelta(addr); err != nil {
		t.Fatalf("chargeAccountAccessDelta(cold): %v", err)
	}
	delta1 := it.gasUsed - start
	want := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
	if delta1 != want {
		t.Fatalf("expected cold-warm delta %d, got %d", want, delta1)
	}
	start2 := it.gasUsed
	if err := it.chargeAccountAccessDelta(addr); err != nil {
		t.Fatalf("chargeAccountAccessDelta(warm): %v", err)
	}
	delta2 := it.gasUsed - start2
	if delta2 != 0 {
		t.Fatalf("expected warm delta 0, got %d", delta2)
	}
}

func TestSemantics_ExtCodeCopy_UsesBackendCode(t *testing.T) {
	cfg := NewCFG([32]byte{}, []byte{0x00})
	it := NewMIRInterpreter(cfg)
	st := NewInMemoryState()

	addr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	// NOTE: InMemoryState doesn't expose setters; populate directly for this unit test.
	st.code[addrKey(addr)] = []byte{0x11, 0x22, 0x33, 0x44}
	it.SetStateBackend(st)
	it.SetChainRules(params.Rules{IsBerlin: true, IsEIP2929: true})

	// Copy 3 bytes from code offset 1 into memory dest 0.
	m := &MIR{
		op: MirEXTCODECOPY,
		operands: []*Value{
			newValue(Konst, nil, nil, addr.Bytes()), // addr
			newValue(Konst, nil, nil, []byte{0x00}), // dest
			newValue(Konst, nil, nil, []byte{0x01}), // codeOffset
			newValue(Konst, nil, nil, []byte{0x03}), // size
		},
	}
	// Ensure the address operand is treated like EVM (20 bytes); we passed addr.Bytes() already.
	// Execute the opcode directly by running a tiny block containing it.
	b := NewMIRBasicBlock(0, 0)
	b.instructions = []*MIR{m, {op: MirSTOP}}
	b.built = true
	it.cfg = &CFG{pcToBlock: map[uint]*MIRBasicBlock{0: b}, rawCode: []byte{0x00}}
	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if len(it.mem) < 3 || it.mem[0] != 0x22 || it.mem[1] != 0x33 || it.mem[2] != 0x44 {
		t.Fatalf("expected mem[0..3]=22 33 44, got %x %x %x", it.mem[0], it.mem[1], it.mem[2])
	}
}

type stubCallBackend struct {
	lastGas uint64
	ret     []byte
	err     error
}

func (s *stubCallBackend) Call(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	s.lastGas = gas
	// refund most of it
	if gas > 5 {
		return s.ret, gas - 5, s.err
	}
	return s.ret, 0, s.err
}
func (s *stubCallBackend) CallCode(caller, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return s.Call(caller, to, input, gas, value)
}
func (s *stubCallBackend) DelegateCall(caller, addr, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	return s.Call(addr, to, input, gas, value)
}
func (s *stubCallBackend) StaticCall(caller, to common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	s.lastGas = gas
	if gas > 5 {
		return s.ret, gas - 5, s.err
	}
	return s.ret, 0, s.err
}
func (s *stubCallBackend) Create(caller common.Address, initCode []byte, gas uint64, value *uint256.Int) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, nil
}
func (s *stubCallBackend) Create2(caller common.Address, initCode []byte, gas uint64, value *uint256.Int, salt *uint256.Int) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, nil
}

func TestSemantics_Call_WritesOutputAndSetsReturnData(t *testing.T) {
	// Build a tiny "CFG" with a single block containing CALL + STOP.
	callMir := &MIR{
		op: MirCALL,
		operands: []*Value{
			newValue(Konst, nil, nil, []byte{0x64}),                        // gas req = 100
			newValue(Konst, nil, nil, common.HexToAddress("0xaa").Bytes()), // to
			newValue(Konst, nil, nil, []byte{0x00}),                        // value = 0
			newValue(Konst, nil, nil, []byte{0x00}),                        // inOff
			newValue(Konst, nil, nil, []byte{0x00}),                        // inSize
			newValue(Konst, nil, nil, []byte{0x00}),                        // outOff
			newValue(Konst, nil, nil, []byte{0x02}),                        // outSize
		},
	}
	b := NewMIRBasicBlock(0, 0)
	b.instructions = []*MIR{callMir, {op: MirSTOP}}
	b.built = true

	it := NewMIRInterpreter(&CFG{pcToBlock: map[uint]*MIRBasicBlock{0: b}, rawCode: []byte{0x00}})
	it.SetGasLimit(10_000)
	stub := &stubCallBackend{ret: []byte{0xaa, 0xbb, 0xcc}}
	it.SetCallCreateBackend(stub)

	res := it.Run()
	if res.Err != nil {
		t.Fatalf("Run error: %v", res.Err)
	}
	if it.results[callMir] == nil || it.results[callMir].Uint64() != 1 {
		t.Fatalf("expected CALL success=1, got %v", it.results[callMir])
	}
	if len(it.returnData) != 3 || it.returnData[0] != 0xaa || it.returnData[1] != 0xbb || it.returnData[2] != 0xcc {
		t.Fatalf("unexpected returnData: %x", it.returnData)
	}
	if len(it.mem) < 2 || it.mem[0] != 0xaa || it.mem[1] != 0xbb {
		t.Fatalf("expected mem[0..2]=aa bb, got %x %x", it.mem[0], it.mem[1])
	}
}
