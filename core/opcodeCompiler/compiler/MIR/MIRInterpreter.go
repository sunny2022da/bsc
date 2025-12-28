package MIR

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// ExecResult is the outcome of executing MIR.
type ExecResult struct {
	HaltOp     MirOperation
	ReturnData []byte
	Err        error
}

// MIRInterpreter executes MIRBasicBlocks produced by CFG.Parse().
// This is a "minimal" interpreter: enough to validate CFG/PHI/control-flow and core arithmetic.
type MIRInterpreter struct {
	cfg *CFG

	// results stores computed values for MIR definitions.
	results map[*MIR]*uint256.Int

	// simple linear memory model
	mem []byte

	validJumpDests map[uint]bool
}

func NewMIRInterpreter(cfg *CFG) *MIRInterpreter {
	it := &MIRInterpreter{
		cfg:            cfg,
		results:        make(map[*MIR]*uint256.Int, 4096),
		mem:            nil,
		validJumpDests: nil,
	}
	if cfg != nil {
		it.validJumpDests = cfg.JumpDests()
	}
	return it
}

// Run executes from the standard EVM entrypoint PC=0.
func (it *MIRInterpreter) Run() ExecResult {
	return it.RunFrom(0)
}

// RunFrom executes starting at an explicit PC. Useful for debugging/resume.
func (it *MIRInterpreter) RunFrom(entryPC uint) ExecResult {
	if it.cfg == nil {
		return ExecResult{Err: errors.New("nil CFG")}
	}
	cur := it.cfg.pcToBlock[entryPC]
	if cur == nil {
		return ExecResult{Err: fmt.Errorf("no block at pc %d", entryPC)}
	}

	var prev *MIRBasicBlock
	for {
		// Reset instruction cursor for this block execution
		cur.pos = 0

		for {
			m := cur.GetNextOp()
			if m == nil {
				// No explicit terminator MIR in this block: fallthrough if any child exists.
				children := cur.Children()
				if len(children) == 0 {
					return ExecResult{HaltOp: MirSTOP}
				}
				// Deterministic: fallthrough to the first child (for non-terminator blocks).
				prev, cur = cur, children[0]
				break
			}

			switch m.op {
			case MirPHI:
				v, err := it.evalPhi(cur, prev, m)
				if err != nil {
					return ExecResult{Err: err}
				}
				it.results[m] = v

			case MirPOP:
				// effect already modeled by IR; no runtime action needed here

			case MirADD, MirMUL, MirSUB, MirDIV, MirSDIV, MirMOD, MirSMOD, MirEXP,
				MirAND, MirOR, MirXOR, MirBYTE, MirSHL, MirSHR, MirSAR,
				MirLT, MirGT, MirSLT, MirSGT, MirEQ:
				a, b, err := it.eval2(m)
				if err != nil {
					return ExecResult{Err: err}
				}
				out := uint256.NewInt(0)
				switch m.op {
				case MirADD:
					out.Add(a, b)
				case MirMUL:
					out.Mul(a, b)
				case MirSUB:
					out.Sub(a, b)
				case MirDIV:
					out.Div(a, b)
				case MirSDIV:
					out.SDiv(a, b)
				case MirMOD:
					out.Mod(a, b)
				case MirSMOD:
					out.SMod(a, b)
				case MirEXP:
					out.Exp(a, b)
				case MirAND:
					out.And(a, b)
				case MirOR:
					out.Or(a, b)
				case MirXOR:
					out.Xor(a, b)
				case MirBYTE:
					// EVM: BYTE(n, x) => nth byte of x (0=most significant)
					out = b.Byte(a)
				case MirSHL:
					out = b.Lsh(b, uint(a.Uint64()))
				case MirSHR:
					out = b.Rsh(b, uint(a.Uint64()))
				case MirSAR:
					out = b.SRsh(b, uint(a.Uint64()))
				case MirLT:
					if a.Lt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirGT:
					if a.Gt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirSLT:
					if a.Slt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirSGT:
					if a.Sgt(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				case MirEQ:
					if a.Eq(b) {
						out.SetOne()
					} else {
						out.Clear()
					}
				}
				it.results[m] = out

			case MirNOT, MirISZERO:
				a, err := it.eval1(m)
				if err != nil {
					return ExecResult{Err: err}
				}
				out := uint256.NewInt(0)
				switch m.op {
				case MirNOT:
					out.Not(a)
				case MirISZERO:
					if a.IsZero() {
						out.SetOne()
					} else {
						out.Clear()
					}
				}
				it.results[m] = out

			case MirMLOAD:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				word := it.mem[o : o+32]
				it.results[m] = uint256.NewInt(0).SetBytes(word)

			case MirMSTORE:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				it.ensureMem(o + 32)
				b := make([]byte, 32)
				vb := val.Bytes()
				copy(b[32-len(vb):], vb)
				copy(it.mem[o:o+32], b)

			case MirMSTORE8:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				val, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				it.ensureMem(o + 1)
				it.mem[o] = byte(val.Uint64() & 0xff)

			case MirMSIZE:
				it.results[m] = uint256.NewInt(0).SetUint64(uint64(len(it.mem)))

			case MirKECCAK256:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				if n < 0 {
					n = 0
				}
				it.ensureMem(o + n)
				h := crypto.Keccak256(it.mem[o : o+n])
				it.results[m] = uint256.NewInt(0).SetBytes(h)

			case MirJUMP:
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				target := uint(dest.Uint64())
				if it.validJumpDests != nil && !it.validJumpDests[target] {
					return ExecResult{Err: fmt.Errorf("invalid jumpdest 0x%x", target)}
				}
				nb := it.cfg.pcToBlock[target]
				if nb == nil {
					// on-demand build (minimal backfill)
					nb = it.cfg.getOrCreateBlock(target)
					if !nb.built {
						if err := it.cfg.buildBasicBlock(nb, it.validJumpDests); err != nil {
							return ExecResult{Err: err}
						}
					}
				}
				prev, cur = cur, nb
				break

			case MirJUMPI:
				dest, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				cond, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				if !cond.IsZero() {
					target := uint(dest.Uint64())
					if it.validJumpDests != nil && !it.validJumpDests[target] {
						return ExecResult{Err: fmt.Errorf("invalid jumpdest 0x%x", target)}
					}
					nb := it.cfg.pcToBlock[target]
					if nb == nil {
						nb = it.cfg.getOrCreateBlock(target)
						if !nb.built {
							if err := it.cfg.buildBasicBlock(nb, it.validJumpDests); err != nil {
								return ExecResult{Err: err}
							}
						}
					}
					prev, cur = cur, nb
					break
				}
				// fallthrough: prefer a child whose firstPC == evmPC+1, else first child
				ftPC := m.evmPC + 1
				var ft *MIRBasicBlock
				for _, ch := range cur.Children() {
					if ch != nil && ch.firstPC == ftPC {
						ft = ch
						break
					}
				}
				if ft == nil {
					children := cur.Children()
					if len(children) == 0 {
						return ExecResult{HaltOp: MirSTOP}
					}
					ft = children[0]
				}
				prev, cur = cur, ft
				break

			case MirSTOP:
				return ExecResult{HaltOp: MirSTOP}
			case MirRETURN:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				it.ensureMem(o + n)
				out := make([]byte, n)
				copy(out, it.mem[o:o+n])
				return ExecResult{HaltOp: MirRETURN, ReturnData: out}
			case MirREVERT:
				off, err := it.evalOperand(m, 0)
				if err != nil {
					return ExecResult{Err: err}
				}
				sz, err := it.evalOperand(m, 1)
				if err != nil {
					return ExecResult{Err: err}
				}
				o := int(off.Uint64())
				n := int(sz.Uint64())
				it.ensureMem(o + n)
				out := make([]byte, n)
				copy(out, it.mem[o:o+n])
				return ExecResult{HaltOp: MirREVERT, ReturnData: out}

			default:
				return ExecResult{Err: fmt.Errorf("unimplemented MIR op: %s", m.op.String())}
			}

			// If we performed a control transfer (JUMP/JUMPI), restart loop with new block.
			if cur != nil && cur.pos == 0 && prev != nil && prev != cur {
				// We jumped and reset cur.pos above at top of outer loop.
				break
			}
		}
	}
}

func (it *MIRInterpreter) ensureMem(n int) {
	if n <= 0 {
		return
	}
	if len(it.mem) >= n {
		return
	}
	// grow to n
	newMem := make([]byte, n)
	copy(newMem, it.mem)
	it.mem = newMem
}

func (it *MIRInterpreter) evalPhi(cur, prev *MIRBasicBlock, phi *MIR) (*uint256.Int, error) {
	if cur == nil || phi == nil {
		return nil, errors.New("nil phi context")
	}
	if prev == nil {
		// Entry block should not have PHI; treat as zero.
		return uint256.NewInt(0), nil
	}
	in := cur.incomingStacks[prev]
	if in == nil {
		// Unknown predecessor: fallback to first operand
		if len(phi.operands) == 0 {
			return uint256.NewInt(0), nil
		}
		return it.evalValue(phi.operands[0])
	}
	if len(in) == 0 {
		return uint256.NewInt(0), nil
	}
	// Map stack slot index from top to slice index (bottom->top)
	idx := (len(in) - 1) - phi.phiStackIndex
	if idx < 0 || idx >= len(in) {
		return uint256.NewInt(0), nil
	}
	v := in[idx]
	v.liveIn = true
	return it.evalValue(&v)
}

func (it *MIRInterpreter) evalValue(v *Value) (*uint256.Int, error) {
	if v == nil {
		return uint256.NewInt(0), nil
	}
	switch v.kind {
	case Konst:
		if v.u != nil {
			return uint256.NewInt(0).Set(v.u), nil
		}
		return uint256.NewInt(0).SetBytes(v.payload), nil
	case Variable, Arguments:
		if v.def == nil {
			return uint256.NewInt(0), nil
		}
		if r, ok := it.results[v.def]; ok && r != nil {
			return uint256.NewInt(0).Set(r), nil
		}
		return nil, fmt.Errorf("missing result for def op=%s pc=%d", v.def.op.String(), v.def.evmPC)
	default:
		return uint256.NewInt(0), nil
	}
}

func (it *MIRInterpreter) evalOperand(m *MIR, idx int) (*uint256.Int, error) {
	if m == nil || idx < 0 || idx >= len(m.operands) {
		return nil, errors.New("bad operand index")
	}
	return it.evalValue(m.operands[idx])
}

func (it *MIRInterpreter) eval1(m *MIR) (*uint256.Int, error) {
	return it.evalOperand(m, 0)
}

func (it *MIRInterpreter) eval2(m *MIR) (*uint256.Int, *uint256.Int, error) {
	a, err := it.evalOperand(m, 0)
	if err != nil {
		return nil, nil, err
	}
	b, err := it.evalOperand(m, 1)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}
