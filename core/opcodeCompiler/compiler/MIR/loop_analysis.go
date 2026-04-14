package MIR

// ComputeLoopInfo performs Tarjan SCC analysis on the CFG and populates
// loop-related flags on every basic block:
//   - IsInLoop:     block participates in at least one cycle
//   - IsLoopHeader: block is the target of at least one back-edge
//   - LoopDepth:    nesting depth (0 = not in loop)
//   - backEdgeParents: set of parents whose edge is a back-edge
//
// Call this after Parse() reaches its fixpoint and whenever the CFG
// structure changes at runtime (checked via cfg.loopInfoValid).
func (c *CFG) ComputeLoopInfo() {
	// 1. Reset all loop flags.
	for _, b := range c.basicBlocks {
		if b == nil {
			continue
		}
		b.IsInLoop = false
		b.IsLoopHeader = false
		b.LoopDepth = 0
		b.backEdgeParents = nil
	}

	// 2. Collect all non-nil blocks for Tarjan traversal.
	blocks := make([]*MIRBasicBlock, 0, len(c.basicBlocks))
	for _, b := range c.basicBlocks {
		if b != nil {
			blocks = append(blocks, b)
		}
	}
	if len(blocks) == 0 {
		c.loopInfoValid = true
		return
	}

	// 3. Run iterative Tarjan SCC.
	sccs := tarjanSCC(blocks)

	// 4. For each non-trivial SCC (size > 1, or size == 1 with self-edge),
	//    mark members and identify headers.
	for _, scc := range sccs {
		if len(scc) == 0 {
			continue
		}
		trivial := len(scc) == 1 && !hasSelfLoop(scc[0])
		if trivial {
			continue
		}

		// Build a set for O(1) membership test.
		memberSet := make(map[*MIRBasicBlock]struct{}, len(scc))
		for _, b := range scc {
			memberSet[b] = struct{}{}
		}

		// Mark all members as in-loop.
		for _, b := range scc {
			b.IsInLoop = true
		}

		// Identify loop headers: members that have at least one predecessor
		// OUTSIDE the SCC (entry point to the loop), or self-loops.
		for _, b := range scc {
			for _, p := range b.Parents() {
				if p == nil {
					continue
				}
				if _, inSCC := memberSet[p]; !inSCC {
					b.IsLoopHeader = true
				}
			}
			if hasSelfLoop(b) {
				b.IsLoopHeader = true
			}
		}

		// Fallback: if no header found (entire SCC unreachable from outside),
		// pick the block with the lowest firstPC.
		hasHeader := false
		for _, b := range scc {
			if b.IsLoopHeader {
				hasHeader = true
				break
			}
		}
		if !hasHeader && len(scc) > 0 {
			best := scc[0]
			for _, b := range scc[1:] {
				if b.firstPC < best.firstPC {
					best = b
				}
			}
			best.IsLoopHeader = true
		}

		// Populate backEdgeParents for each header: any edge from a member
		// of this SCC to a header of this SCC is a back-edge.
		for _, b := range scc {
			if !b.IsLoopHeader {
				continue
			}
			for _, p := range b.Parents() {
				if p == nil {
					continue
				}
				if _, inSCC := memberSet[p]; inSCC {
					if b.backEdgeParents == nil {
						b.backEdgeParents = make(map[*MIRBasicBlock]struct{}, 4)
					}
					b.backEdgeParents[p] = struct{}{}
				}
			}
		}
	}

	// 5. Compute LoopDepth by counting how many non-trivial SCCs each block belongs to.
	for _, scc := range sccs {
		if len(scc) == 0 {
			continue
		}
		trivial := len(scc) == 1 && !hasSelfLoop(scc[0])
		if trivial {
			continue
		}
		for _, b := range scc {
			b.LoopDepth++
		}
	}

	c.loopInfoValid = true
}

// EnsureLoopInfo recomputes loop analysis if it has been invalidated
// (e.g. by runtime edge additions). Safe to call frequently; no-ops
// when the analysis is already valid.
func (c *CFG) EnsureLoopInfo() {
	if c == nil {
		return
	}
	if !c.loopInfoValid {
		c.ComputeLoopInfo()
	}
}

// hasSelfLoop returns true if b has itself as a direct child.
func hasSelfLoop(b *MIRBasicBlock) bool {
	for _, ch := range b.Children() {
		if ch == b {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Iterative Tarjan SCC
// ---------------------------------------------------------------------------

type tarjanState struct {
	index    int
	lowlink  int
	onStack  bool
	assigned bool // true once index/lowlink are set
}

func tarjanSCC(blocks []*MIRBasicBlock) [][]*MIRBasicBlock {
	state := make(map[*MIRBasicBlock]*tarjanState, len(blocks))
	for _, b := range blocks {
		state[b] = &tarjanState{}
	}

	var (
		index   int
		stack   []*MIRBasicBlock
		results [][]*MIRBasicBlock
	)

	// Iterative DFS using an explicit call stack to avoid Go stack overflow
	// on large CFGs (EVM contracts can have 200+ blocks).
	type frame struct {
		block    *MIRBasicBlock
		childIdx int // index into Children() for resumption
	}

	for _, root := range blocks {
		rs := state[root]
		if rs.assigned {
			continue
		}

		callStack := []frame{{block: root, childIdx: 0}}
		rs.index = index
		rs.lowlink = index
		rs.onStack = true
		rs.assigned = true
		index++
		stack = append(stack, root)

		for len(callStack) > 0 {
			top := &callStack[len(callStack)-1]
			children := top.block.Children()

			if top.childIdx < len(children) {
				ch := children[top.childIdx]
				top.childIdx++
				if ch == nil {
					continue
				}
				cs, ok := state[ch]
				if !ok {
					continue // block not in our set
				}
				if !cs.assigned {
					// Tree edge: recurse.
					cs.index = index
					cs.lowlink = index
					cs.onStack = true
					cs.assigned = true
					index++
					stack = append(stack, ch)
					callStack = append(callStack, frame{block: ch, childIdx: 0})
				} else if cs.onStack {
					// Back-edge: update lowlink.
					ts := state[top.block]
					if cs.index < ts.lowlink {
						ts.lowlink = cs.index
					}
				}
			} else {
				// All children processed; pop frame.
				ts := state[top.block]
				callStack = callStack[:len(callStack)-1]

				// Propagate lowlink to parent.
				if len(callStack) > 0 {
					parent := callStack[len(callStack)-1].block
					ps := state[parent]
					if ts.lowlink < ps.lowlink {
						ps.lowlink = ts.lowlink
					}
				}

				// If this is a root of an SCC, pop the SCC from the stack.
				if ts.lowlink == ts.index {
					var scc []*MIRBasicBlock
					for {
						w := stack[len(stack)-1]
						stack = stack[:len(stack)-1]
						state[w].onStack = false
						scc = append(scc, w)
						if w == top.block {
							break
						}
					}
					results = append(results, scc)
				}
			}
		}
	}

	return results
}
