package MIR

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// DumpMIRForCodeHash dumps MIR instructions around the given EVM PC. It first tries
// the cached CFG; if that misses (e.g. CFG was evicted due to runtimeBecameDynamic),
// it falls back to parsing a fresh throwaway CFG from the provided code bytes so the
// dump is still available. Intended for diagnostic use in receipt-mismatch replays.
func DumpMIRForCodeHash(codeHash common.Hash, code []byte, pc, window uint) string {
	start := uint(0)
	if pc > window {
		start = pc - window
	}
	end := pc + window

	globalCFGCacheMu.RLock()
	entry, ok := getGlobalCFGCache().Get(codeHash)
	globalCFGCacheMu.RUnlock()
	if ok && entry != nil && entry.cfg != nil {
		return DebugDumpMIRForEvmPCRange(entry.cfg, start, end)
	}

	// Cache miss: parse a throwaway CFG (not stored in cache) to produce the dump.
	if len(code) == 0 {
		return fmt.Sprintf("<no cached CFG for codeHash %s and no code provided>\n", codeHash.Hex())
	}
	tmp := NewCFG(codeHash, code)
	if err := tmp.Parse(); err != nil {
		return fmt.Sprintf("<cache miss and throwaway Parse failed for codeHash %s: %v>\n", codeHash.Hex(), err)
	}
	return "[throwaway CFG, cache miss]\n" + DebugDumpMIRForEvmPCRange(tmp, start, end)
}

// DebugDumpMIRForEvmPCRange dumps MIR instructions whose originating EVM PC is within [start,end]
// (inclusive). This is intended for debugging consensus divergences and should not be used in
// hot production paths.
func DebugDumpMIRForEvmPCRange(cfg *CFG, start, end uint) string {
	if cfg == nil {
		return "<nil cfg>\n"
	}
	type row struct {
		evmPC    uint
		evmOp    byte
		op       MirOperation
		blockPC  uint
		instrIdx int
		line     string
	}
	rows := make([]row, 0, 256)

	for _, b := range cfg.basicBlocks {
		if b == nil {
			continue
		}
		for idx, m := range b.instructions {
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
			nChildren := 0
			childPCs := ""
			if b.jumpTable != nil {
				for pc, ch := range b.jumpTable {
					if ch != nil {
						if nChildren > 0 {
							childPCs += ","
						}
						childPCs += fmt.Sprintf("%d", pc)
						nChildren++
					}
				}
			}
			blockInfo := fmt.Sprintf("[block@%d #%d/%d children=%s]", b.firstPC, idx, len(b.instructions), childPCs)
			rows = append(rows, row{
				evmPC:    m.evmPC,
				evmOp:    m.evmOp,
				op:       m.op,
				blockPC:  b.firstPC,
				instrIdx: idx,
				line:     fmt.Sprintf("%s evmPC=%d evmOp=0x%02x mirOp=%s | %s", blockInfo, m.evmPC, m.evmOp, m.op.String(), strings.Join(ops, " ")),
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


