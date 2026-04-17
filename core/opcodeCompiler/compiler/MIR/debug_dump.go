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

// addPCsOfMatchingMSTOREs scans all MSTORE instructions in cfg and appends the PCs
// of those that could write to the memory slot read by an MLOAD with offset `loadOff`.
//
// Matching rules (over-approximating on purpose — this is a diagnostic dump):
//   - If loadOff is Konst: match MSTOREs whose offset is Konst and equal. Also match
//     MSTOREs whose offset is a Variable (dynamic — may or may not alias).
//   - If loadOff is Variable: match all MSTOREs (can't resolve statically).
//
// We always accept a bounded number of matches to avoid dump-size explosions on
// contracts with hundreds of MSTOREs.
func addPCsOfMatchingMSTOREs(cfg *CFG, loadOff *Value, visited map[uint]bool, out *[]uint) {
	if cfg == nil || loadOff == nil {
		return
	}
	const maxMatches = 32
	matches := 0
	for _, b := range cfg.basicBlocks {
		if b == nil {
			continue
		}
		for _, m := range b.instructions {
			if m == nil || m.op != MirMSTORE || len(m.operands) == 0 || m.operands[0] == nil {
				continue
			}
			storeOff := m.operands[0]
			include := false
			switch {
			case loadOff.kind == Konst && storeOff.kind == Konst:
				if loadOff.u != nil && storeOff.u != nil && loadOff.u.Cmp(storeOff.u) == 0 {
					include = true
				}
			case loadOff.kind == Konst && storeOff.kind == Variable:
				// Dynamic MSTORE offset — might alias with the constant load offset.
				include = true
			case loadOff.kind == Variable:
				// Dynamic MLOAD offset — conservatively include any MSTORE.
				include = true
			}
			if include && !visited[m.evmPC] {
				*out = append(*out, m.evmPC)
				matches++
				if matches >= maxMatches {
					return
				}
			}
		}
	}
}

// DumpMIRWithOperandTraces dumps MIR instructions in a window around anchorPC and then
// recursively dumps windows around each operand's defPC (up to maxDepth levels), so the
// full data-flow feeding a diverging JUMPI can be inspected in one log entry.
//
// For PHI operands, the enclosing basic block's parents are also followed so we can see
// where the PHI's incoming values come from.
func DumpMIRWithOperandTraces(cfg *CFG, anchorPC uint, maxDepth int, window uint) string {
	if cfg == nil {
		return "<nil cfg>\n"
	}
	// Map evmPC -> instruction (take the first one we find; multiple PHIs at the same PC
	// will be covered by the range dump below).
	type pcWindow struct{ start, end uint }
	windows := make([]pcWindow, 0, 8)
	visited := make(map[uint]bool, 32)
	queue := []uint{anchorPC}
	level := 0

	addWindow := func(pc uint) {
		s := uint(0)
		if pc > window {
			s = pc - window
		}
		windows = append(windows, pcWindow{start: s, end: pc + window})
	}

	for level <= maxDepth && len(queue) > 0 {
		nextQueue := []uint{}
		for _, pc := range queue {
			if visited[pc] {
				continue
			}
			visited[pc] = true
			addWindow(pc)

			// Walk instructions at this PC and follow operand defPCs.
			for _, b := range cfg.basicBlocks {
				if b == nil {
					continue
				}
				for _, m := range b.instructions {
					if m == nil || m.evmPC != pc {
						continue
					}
					for _, v := range m.operands {
						if v == nil || v.kind != Variable || v.def == nil {
							continue
						}
						if !visited[v.def.evmPC] {
							nextQueue = append(nextQueue, v.def.evmPC)
						}
					}
					// PHI nodes: follow the parents' exit edges so we can see where the
					// incoming values come from (across block boundaries).
					if m.op == MirPHI {
						for _, parent := range b.parents {
							if parent == nil || len(parent.instructions) == 0 {
								continue
							}
							lastPC := parent.instructions[len(parent.instructions)-1].evmPC
							if !visited[lastPC] {
								nextQueue = append(nextQueue, lastPC)
							}
						}
					}
					// MLOAD: memory-flow dependency. Find MSTOREs that could write to the
					// same offset (direct Konst match, or dynamic offset we can't resolve
					// statically). Follow both so the upstream value chain appears in dump.
					if m.op == MirMLOAD && len(m.operands) > 0 && m.operands[0] != nil {
						loadOff := m.operands[0]
						addPCsOfMatchingMSTOREs(cfg, loadOff, visited, &nextQueue)
					}
				}
			}
		}
		queue = nextQueue
		level++
	}

	// Merge overlapping windows.
	sort.Slice(windows, func(i, j int) bool { return windows[i].start < windows[j].start })
	merged := make([]pcWindow, 0, len(windows))
	for _, w := range windows {
		if len(merged) > 0 && w.start <= merged[len(merged)-1].end+1 {
			if w.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = w.end
			}
			continue
		}
		merged = append(merged, w)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MIR operand-trace dump anchored at evmPC=%d (maxDepth=%d window=%d, %d windows):\n",
		anchorPC, maxDepth, window, len(merged)))
	for _, w := range merged {
		sb.WriteString(DebugDumpMIRForEvmPCRange(cfg, w.start, w.end))
	}
	return sb.String()
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


