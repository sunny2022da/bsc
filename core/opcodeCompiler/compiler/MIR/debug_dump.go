package MIR

import (
	"fmt"
	"sort"
	"strings"
)

// DebugDumpMIRForEvmPCRange dumps MIR instructions whose originating EVM PC is within [start,end]
// (inclusive). This is intended for debugging consensus divergences and should not be used in
// hot production paths.
func DebugDumpMIRForEvmPCRange(cfg *CFG, start, end uint) string {
	if cfg == nil {
		return "<nil cfg>\n"
	}
	type row struct {
		evmPC uint
		evmOp byte
		op    MirOperation
		line  string
	}
	rows := make([]row, 0, 256)

	for _, b := range cfg.basicBlocks {
		if b == nil {
			continue
		}
		for _, m := range b.instructions {
			if m == nil {
				continue
			}
			if m.evmPC < start || m.evmPC > end {
				continue
			}
			ops := make([]string, 0, len(m.operands))
			for i := range m.operands {
				v := m.operands[i]
				if v == nil {
					ops = append(ops, fmt.Sprintf("op%d=<nil>", i))
					continue
				}
				switch v.kind {
				case Konst:
					hex := "0x0"
					if v.u != nil {
						hex = "0x" + v.u.Hex()
					}
					ops = append(ops, fmt.Sprintf("op%d=K(%s)", i, hex))
				case Variable:
					if v.def != nil {
						ops = append(ops, fmt.Sprintf("op%d=V(defPC=%d defOp=%s defResIdx=%d)", i, v.def.evmPC, v.def.op.String(), v.def.resIdx))
					} else {
						ops = append(ops, fmt.Sprintf("op%d=V(<nil def>)", i))
					}
				case Arguments:
					ops = append(ops, fmt.Sprintf("op%d=ARG", i))
				default:
					ops = append(ops, fmt.Sprintf("op%d=UNK", i))
				}
			}
			rows = append(rows, row{
				evmPC: m.evmPC,
				evmOp: m.evmOp,
				op:    m.op,
				line:  fmt.Sprintf("evmPC=%d evmOp=0x%02x mirOp=%s | %s", m.evmPC, m.evmOp, m.op.String(), strings.Join(ops, " ")),
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].evmPC != rows[j].evmPC {
			return rows[i].evmPC < rows[j].evmPC
		}
		return rows[i].op < rows[j].op
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MIR dump for evmPC in [%d..%d] (codeHash=%s blocks=%d):\n", start, end, cfg.codeAddr, cfg.basicBlockCount))
	for _, r := range rows {
		sb.WriteString("  " + r.line + "\n")
	}
	if len(rows) == 0 {
		sb.WriteString("  <no MIR in range>\n")
	}
	return sb.String()
}


