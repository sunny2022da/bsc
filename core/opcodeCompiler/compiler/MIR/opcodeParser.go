package MIR

import (
	"fmt"
	"os"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

// cfgNonConvergentPrefix is used as a stable marker so higher-level callers (runner/tools)
// can identify a non-convergent CFG build without importing extra error types.
const cfgNonConvergentPrefix = "MIR CFG parse did not converge"

// buildMode controls how much work buildBasicBlock does.
type buildMode int

const (
	// skeletonBuild discovers block boundaries, connects edges, and tracks
	// abstract stack heights. No MIR instructions are emitted; PUSH constants
	// are preserved on the stack for jump-target resolution.
	skeletonBuild buildMode = iota
	// fullBuild generates PHIs via getEntryStackForBlock and emits all MIR
	// instructions. This is the original single-pass behavior.
	fullBuild
)

// CFGNonConvergentError reports that CFG.Parse exceeded its build bound and did not reach a fixpoint.
// This should be treated as a correctness/debugging failure that must be fixed (not silently ignored).
type CFGNonConvergentError struct {
	Builds    int
	MaxBuilds int
	CodeHash  common.Hash
	CodeLen   int
}

func (e *CFGNonConvergentError) Error() string {
	if e == nil {
		return cfgNonConvergentPrefix
	}
	return fmt.Sprintf("%s after %d block builds (max=%d) codeHash=%s codeLen=%d",
		cfgNonConvergentPrefix, e.Builds, e.MaxBuilds, e.CodeHash.Hex(), e.CodeLen)
}

// CFG is the IR record the control flow of the contract.
// It records not only the control flow info but also the state and memory accesses.
// CFG is mapping to <addr, code> pair, and there is no need to record CFG for every contract
// since it is just an IR, although the analyzing/compiling results are saved to the related cache.
type CFG struct {
	codeAddr        common.Hash
	rawCode         []byte
	basicBlocks     []*MIRBasicBlock
	basicBlockCount uint
	// runtimeEpoch is bumped per top-level execution when CFG is pulled from cache.
	// Runtime-recorded incoming snapshots are tagged with this epoch so we can ignore
	// stale snapshots from previous executions (different calldata).
	runtimeEpoch uint64
	// snapshotEpoch is always incremented every execution (unconditionally), used by
	// incomingSnapshotEpoch to detect stale PHI-fallback snapshots without triggering
	// the rebuild machinery tied to runtimeEpoch. See evalPhi in MIRInterpreter.go.
	snapshotEpoch uint64
	// nextResIdx allocates global MIR result slots for this CFG.
	// Index 0 is reserved for "unassigned".
	nextResIdx int
	// defKeyToResIdx maps stable MIR def identity -> latest allocated resIdx.
	// This is used to repair stale *MIR pointers captured in incoming stack snapshots
	// across block rebuilds during CFG construction.
	defKeyToResIdx map[mirDefKey]int

	// Mapping from EVM PC to the BasicBlock starting at that PC
	pcToBlock map[uint]*MIRBasicBlock

	// Cached valid JUMPDEST map (computed once from rawCode)
	jumpDests map[uint]bool

	// runtimeBecameDynamic is set when execution discovers control-flow beyond what Parse() built
	// (e.g. dynamic JUMP targets discovered at runtime). Such CFGs are unsafe to share globally
	// across blocks/transactions because runtime edge snapshots and partial CFG expansion can leak
	// path-dependent state and cause consensus divergence.
	runtimeBecameDynamic bool
	// hasUnresolvedJumpsFlag is set if any block in this CFG contains a dynamic jump target that cannot
	// be resolved at build time. This is a cheap flag used to select safer runtime snapshot seeding.
	hasUnresolvedJumpsFlag bool
	// needsRuntimeEpochFlag is set if the CFG contains merge points with differing incoming stack heights.
	// These contracts require runtime-epoch tagging to select the correct entry stack during cached runs.
	needsRuntimeEpochFlag bool

	// parseDone is set to true after Parse() completes successfully.
	// connectEdge uses this to distinguish parse-time calls (parseDone=false) from
	// runtime calls (parseDone=true): only runtime-written snapshots are tagged with
	// snapshotEpoch in incomingSnapshotEpoch, enabling stale detection in evalPhi.
	parseDone bool

	// skeletonMode is set during Parse() pass 1. When true, buildBasicBlock
	// skips MIR instruction emission (appendMIR becomes no-op) and only
	// discovers block boundaries, edges, and exit stack heights.
	// Thread safety: protected by mirBuildMu (held during all Parse/build calls).
	skeletonMode bool

	// loopInfoValid is true after ComputeLoopInfo has run. Reset to false when
	// the CFG structure changes (new blocks/edges added at runtime).
	loopInfoValid bool
}

func NewCFG(hash common.Hash, code []byte) (c *CFG) {
	c = &CFG{}
	c.codeAddr = hash
	c.rawCode = code
	c.basicBlocks = []*MIRBasicBlock{}
	c.basicBlockCount = 0
	c.nextResIdx = 1
	c.defKeyToResIdx = make(map[mirDefKey]int, 4096)

	c.pcToBlock = make(map[uint]*MIRBasicBlock)
	c.jumpDests = nil
	return c
}

func (c *CFG) needsRuntimeEpoch() bool {
	if c == nil {
		return false
	}
	return c.needsRuntimeEpochFlag || c.runtimeBecameDynamic || c.hasUnresolvedJumpsFlag
}

func (c *CFG) allocResIdx() int {
	if c == nil {
		return 0
	}
	idx := c.nextResIdx
	c.nextResIdx++
	return idx
}

// JumpDests returns the cached map of valid JUMPDEST PCs, computing it once if needed.
func (c *CFG) JumpDests() map[uint]bool {
	if c == nil {
		return nil
	}
	if c.jumpDests == nil {
		c.jumpDests = c.scanJumpDests()
	}
	return c.jumpDests
}

func (c *CFG) addBlock(block *MIRBasicBlock) {
	c.basicBlocks = append(c.basicBlocks, block)
	c.basicBlockCount++
	c.pcToBlock[block.firstPC] = block
}

func (c *CFG) hasUnresolvedJumps() bool {
	if c == nil {
		return false
	}
	if c.hasUnresolvedJumpsFlag {
		return true
	}
	for _, b := range c.basicBlocks {
		if b != nil && b.unresolvedJump {
			return true
		}
	}
	return false
}

// getOrCreateBlock returns the block starting at the given PC, creating it if it doesn't exist.
func (c *CFG) getOrCreateBlock(pc uint) *MIRBasicBlock {
	// Check if we've already created a block for this PC
	if block, exists := c.pcToBlock[pc]; exists {
		return block
	}

	// Create new block (now without the parent argument)
	newBlock := NewMIRBasicBlock(c.basicBlockCount, pc)

	// Use addBlock helper to register it
	c.addBlock(newBlock)

	return newBlock
}

// scanJumpDests identifies all valid JUMPDEST locations in the bytecode.
func (c *CFG) scanJumpDests() map[uint]bool {
	dests := make(map[uint]bool)
	pc := uint(0)
	codeLen := uint(len(c.rawCode))

	for pc < codeLen {
		// cast byte to ByteCode type from compiler package
		op := compiler.ByteCode(c.rawCode[pc])

		// 1. Is it a JUMPDEST?
		if op == compiler.JUMPDEST {
			dests[pc] = true
			pc++
			continue
		}

		// 2. Is it a PUSH instruction?
		if op >= compiler.PUSH1 && op <= compiler.PUSH32 {
			// Calculate how many data bytes follow
			// PUSH1 is 0x60. if op is PUSH1, size is 1.
			dataSize := uint(op - compiler.PUSH1 + 1)

			// Skip the data bytes
			pc += 1 + dataSize
			continue
		}

		// 3. Any other instruction
		pc++
	}

	return dests
}

// Parse builds the Control Flow Graph from the raw EVM code.
// It runs in two passes:
//   - Pass 1 (skeleton): discover block boundaries, edges, and exit stack heights.
//     No MIR instructions are emitted. Tarjan SCC loop analysis runs after this pass.
//   - Pass 2 (full): on the now-stable CFG, build entry stacks with PHIs and emit
//     all MIR instructions. Instructions generated here should not need rebuild.
func (c *CFG) Parse() error {
	// CFG building uses package-level globals; serialize builds across goroutines.
	mirBuildMu.Lock()
	defer mirBuildMu.Unlock()

	// Set current CFG build context for MIR resIdx allocation.
	currentCFGBuild = c
	defer func() { currentCFGBuild = nil }()

	log.Info("[MIR B2] Parse() ENTER", "codeAddr", c.codeAddr, "codeLen", len(c.rawCode))

	validJumpDests := c.JumpDests()
	entryBlock := c.getOrCreateBlock(0)

	maxBuilds := 1024 + 64*len(c.rawCode)
	const maxBuildsPerBlock = 64

	// ── Pass 1: Skeleton ─────────────────────────────────────────────
	// Discover all basic blocks, edges, and abstract stack heights.
	// appendMIR is a no-op; no MIR instructions are generated.
	c.skeletonMode = true
	{
		builds := 0
		blockBuilds := make(map[*MIRBasicBlock]int, 64)
		queue := []*MIRBasicBlock{entryBlock}
		for len(queue) > 0 {
			block := queue[0]
			queue = queue[1:]
			if block.built {
				continue
			}
			if len(block.instructions) > 0 {
				block.ResetForRebuild(false)
			}
			builds++
			blockBuilds[block]++
			if builds > maxBuilds || blockBuilds[block] > maxBuildsPerBlock {
				c.skeletonMode = false
				return &CFGNonConvergentError{Builds: builds, MaxBuilds: maxBuilds, CodeHash: c.codeAddr, CodeLen: len(c.rawCode)}
			}
			if err := c.buildBasicBlock(block, validJumpDests); err != nil {
				c.skeletonMode = false
				return err
			}
			// Force built=true: skeleton build may have set built=false via
			// self-loop detection in JUMP/JUMPI handlers. In skeleton mode each
			// block should be built exactly once.
			block.built = true
			for _, child := range block.children {
				if !child.built {
					queue = append(queue, child)
				}
			}
		}
	}
	c.skeletonMode = false

	// CFG structure is now stable. Compute loop analysis before full build
	// so that getEntryStackForBlock can use accurate IsLoopHeader/IsInLoop.
	c.ComputeLoopInfo()

	// ── Pass 2: Full build ───────────────────────────────────────────
	// Reset block build state while preserving CFG topology and incomingStacks.
	// incomingStacks from skeleton mode have correct heights (even though values
	// are Unknown); full build's connectEdge will overwrite them with proper
	// symbolic snapshots as blocks are built.
	for _, b := range c.basicBlocks {
		if b == nil {
			continue
		}
		b.ResetForRebuild(false)
		b.built = false
	}
	{
		builds := 0
		blockBuilds := make(map[*MIRBasicBlock]int, len(c.basicBlocks)+16)
		queue := []*MIRBasicBlock{entryBlock}
		for len(queue) > 0 {
			block := queue[0]
			queue = queue[1:]
			if block.built {
				continue
			}
			if len(block.instructions) > 0 {
				block.ResetForRebuild(false)
			}
			builds++
			blockBuilds[block]++
			if builds > maxBuilds || blockBuilds[block] > maxBuildsPerBlock {
				return &CFGNonConvergentError{Builds: builds, MaxBuilds: maxBuilds, CodeHash: c.codeAddr, CodeLen: len(c.rawCode)}
			}
			if err := c.buildBasicBlock(block, validJumpDests); err != nil {
				return err
			}
			for _, child := range block.children {
				queue = append(queue, child)
			}
		}
	}
	// After reaching a parse-time fixpoint, detect whether this CFG needs runtime epoch tagging.
	// If any merge point has incoming snapshots with differing heights, cached runs must avoid
	// using a parse-time entry stack specialized to the wrong predecessor height.
	c.parseDone = false // reset until we finish the epoch analysis below
	c.needsRuntimeEpochFlag = false
	rtEpochReason := ""
	rtEpochBlockPC := uint(0)
	rtEpochParents := 0
	for _, b := range c.basicBlocks {
		if b == nil || len(b.parents) < 2 {
			continue
		}
		// If we don't have a snapshot for every predecessor, we *must* enable runtime epoch
		// so runtime edge tagging/repair can build a correct entry stack.
		if b.incomingStacks == nil || len(b.incomingStacks) != len(b.parents) {
			c.needsRuntimeEpochFlag = true
			rtEpochReason = "missing_snapshot"
			rtEpochBlockPC = b.firstPC
			rtEpochParents = len(b.parents)
			break
		}
		first := -1
		for _, p := range b.parents {
			if p == nil {
				continue
			}
			s, ok := b.incomingStacks[p]
			if !ok {
				c.needsRuntimeEpochFlag = true
				rtEpochReason = "parent_not_in_incoming"
				rtEpochBlockPC = b.firstPC
				rtEpochParents = len(b.parents)
				break
			}
			if first < 0 {
				first = len(s)
				continue
			}
			if len(s) != first {
				c.needsRuntimeEpochFlag = true
				rtEpochReason = fmt.Sprintf("height_mismatch(%d_vs_%d)", first, len(s))
				rtEpochBlockPC = b.firstPC
				rtEpochParents = len(b.parents)
				break
			}
		}
		if c.needsRuntimeEpochFlag {
			break
		}
	}
	if c.needsRuntimeEpochFlag && mirRunnerDebugLog {
		fmt.Fprintf(os.Stderr, "[MIR] needsRuntimeEpoch: codeHash=%s reason=%s blockPC=%d parents=%d\n",
			c.codeAddr, rtEpochReason, rtEpochBlockPC, rtEpochParents)
	}
	// Pre-warm jump tables for unresolvedJump blocks so that runtime resolveBB calls
	// find pre-created target blocks and can cache results in jumpTable immediately.
	c.preWarmJumpTables()
	// Mark parse as complete. connectEdge uses this to detect runtime snapshot changes
	// that occur without epoch protection and to enable epoch tracking for future runs.
	c.parseDone = true

	// One-shot dump of block@3754/3762/3793 instructions for shift-register debugging.
	// Only dump for the contract we're chasing (0x2E90F2eB46ee35Bb179C10513D3F7fE8b0693254
	// → codeHash 0xeb7764bd977fcb339cd6e661713f4aa19e5365c98c3ea788fcea59abca46e838).
	targetHash := common.HexToHash("0xeb7764bd977fcb339cd6e661713f4aa19e5365c98c3ea788fcea59abca46e838")
	log.Info("[MIR B2] BLOCK-DUMP filter check",
		"c.codeAddr", c.codeAddr,
		"target", targetHash,
		"match", c.codeAddr == targetHash)
	if c.codeAddr != targetHash {
		return nil
	}
	// Find and dump blocks containing PHIs with resIdx in [2804, 2809] (outer
	// PHIs that feed block@3762's entry-edge operands).
	for _, b := range c.basicBlocks {
		if b == nil {
			continue
		}
		hasTarget := false
		for _, m := range b.instructions {
			if m != nil && m.op == MirPHI && m.resIdx >= 2804 && m.resIdx <= 2809 {
				hasTarget = true
				break
			}
		}
		if !hasTarget {
			continue
		}
		parentPCs := make([]uint, 0, len(b.parents))
		for _, p := range b.parents {
			if p != nil {
				parentPCs = append(parentPCs, p.firstPC)
			}
		}
		log.Info("[MIR B2] OUTER-PHI BLOCK header",
			"firstPC", b.firstPC, "blockNum", b.blockNum,
			"instructions.len", len(b.instructions),
			"parents", fmt.Sprintf("%v", parentPCs))
		for i, m := range b.instructions {
			if m == nil {
				continue
			}
			opStr := ""
			for k, o := range m.operands {
				if o == nil {
					opStr += fmt.Sprintf(" op%d=nil", k)
					continue
				}
				switch o.kind {
				case Konst:
					opStr += fmt.Sprintf(" op%d=K(%x)", k, o.payload)
				case Variable:
					if o.def != nil {
						opStr += fmt.Sprintf(" op%d=V(defPC=%d defOp=%d defBlk=%d defResIdx=%d)",
							k, o.def.evmPC, o.def.op, o.def.defBlockNum, o.def.resIdx)
					} else {
						opStr += fmt.Sprintf(" op%d=V(nil)", k)
					}
				case Unknown:
					opStr += fmt.Sprintf(" op%d=UNK(liveInPos=%d)", k, o.liveInPos)
				case RuntimeVal:
					opStr += fmt.Sprintf(" op%d=RT(srcBlkPC=%d stackPos=%d)", k, o.rtSourceBlockPC, o.rtStackPos)
				default:
					opStr += fmt.Sprintf(" op%d=?", k)
				}
			}
			log.Info("[MIR B2] OUTER-PHI BLOCK",
				"firstPC", b.firstPC,
				"idx", i, "evmPC", m.evmPC,
				"mirOp", m.op, "resIdx", m.resIdx,
				"phiStackIndex", m.phiStackIndex,
				"ops", opStr)
		}
	}
	// Dump pcToBlock summary first.
	allPCs := make([]uint, 0, len(c.pcToBlock))
	for pc := range c.pcToBlock {
		allPCs = append(allPCs, pc)
	}
	log.Info("[MIR B2] BLOCK-DUMP pcToBlock summary",
		"pcToBlock.size", len(c.pcToBlock),
		"basicBlocks.size", len(c.basicBlocks))
	// Sort and print all firstPCs to see the actual block boundaries.
	sortedPCs := make([]int, 0, len(c.pcToBlock))
	for pc := range c.pcToBlock {
		sortedPCs = append(sortedPCs, int(pc))
	}
	sort.Ints(sortedPCs)
	for _, pc := range sortedPCs {
		if pc < 3500 || pc > 4000 {
			continue
		}
		b := c.pcToBlock[uint(pc)]
		log.Info("[MIR B2] BLOCK-DUMP nearby", "pc", pc, "blockNum", b.blockNum,
			"built", b.built, "instructions.len", len(b.instructions),
			"parents.len", len(b.parents))
	}
	_ = allPCs
	for _, pc := range []uint{3754, 3762, 3793} {
		b := c.pcToBlock[pc]
		if b == nil {
			log.Info("[MIR B2] BLOCK-DUMP missing", "codeAddr", c.codeAddr, "pc", pc)
			continue
		}
		parentPCs := make([]uint, 0, len(b.parents))
		for _, p := range b.parents {
			if p != nil {
				parentPCs = append(parentPCs, p.firstPC)
			}
		}
		childPCs := make([]uint, 0, len(b.Children()))
		for _, ch := range b.Children() {
			if ch != nil {
				childPCs = append(childPCs, ch.firstPC)
			}
		}
		log.Info("[MIR B2] BLOCK-DUMP header",
			"codeAddr", c.codeAddr,
			"firstPC", b.firstPC, "blockNum", b.blockNum,
			"instructions.len", len(b.instructions),
			"built", b.built,
			"entryStack.nil", b.entryStack == nil,
			"parents", fmt.Sprintf("%v", parentPCs),
			"children", fmt.Sprintf("%v", childPCs))
		for i, m := range b.instructions {
			if m == nil {
				continue
			}
			opStr := ""
			for k, o := range m.operands {
				if o == nil {
					opStr += fmt.Sprintf(" op%d=nil", k)
					continue
				}
				switch o.kind {
				case Konst:
					opStr += fmt.Sprintf(" op%d=K(%x)", k, o.payload)
				case Variable:
					if o.def != nil {
						opStr += fmt.Sprintf(" op%d=V(defPC=%d defOp=%d defBlk=%d defResIdx=%d)",
							k, o.def.evmPC, o.def.op, o.def.defBlockNum, o.def.resIdx)
					} else {
						opStr += fmt.Sprintf(" op%d=V(nil)", k)
					}
				case Unknown:
					opStr += fmt.Sprintf(" op%d=UNK(liveInPos=%d)", k, o.liveInPos)
				case RuntimeVal:
					opStr += fmt.Sprintf(" op%d=RT(srcBlkPC=%d stackPos=%d)", k, o.rtSourceBlockPC, o.rtStackPos)
				default:
					opStr += fmt.Sprintf(" op%d=?", k)
				}
			}
			log.Info("[MIR B2] BLOCK-DUMP",
				"block.firstPC", b.firstPC,
				"idx", i,
				"evmPC", m.evmPC,
				"mirOp", m.op,
				"resIdx", m.resIdx,
				"phiStackIndex", m.phiStackIndex,
				"ops", opStr)
		}
	}

	return nil
}

// preWarmJumpTables runs after Parse() reaches a fixpoint. For every block that ends in a
// dynamic JUMP/JUMPI (unresolvedJump==true) it scans the per-predecessor incoming-stack
// snapshots for constant values that are valid JUMPDEST addresses.  For each such constant
// it pre-creates the target MIRBasicBlock in pcToBlock (without connecting an edge) so that:
//
//  1. The first runtime resolveBB call finds a pre-existing block instead of allocating.
//  2. The first connectEdge call updates jumpTable; subsequent jumps to that target hit the
//     O(1) jumpTable fast path instead of the resolveBB slow path.
//
// Edges are intentionally NOT connected here (that would invalidate builds). Connection and
// jumpTable population happen on first execution via resolveBB → connectEdge.
func (c *CFG) preWarmJumpTables() {
	if c == nil {
		return
	}
	validDests := c.JumpDests()
	// Iterate over a copy of the slice length to avoid observing blocks created during this pass.
	n := len(c.basicBlocks)
	for i := 0; i < n; i++ {
		blk := c.basicBlocks[i]
		if blk == nil || !blk.unresolvedJump {
			continue
		}
		// Scan all per-predecessor incoming stack snapshots for constant JUMPDEST candidates.
		for _, snap := range blk.incomingStacks {
			for si := range snap {
				v := &snap[si]
				if v.kind != Konst {
					continue
				}
				target := constSnapToPC(v)
				if target == 0 || !validDests[target] {
					continue
				}
				if _, exists := c.pcToBlock[target]; !exists {
					c.getOrCreateBlock(target)
				}
			}
		}
		// Also scan the block's own entry stack.
		for si := range blk.entryStack {
			v := &blk.entryStack[si]
			if v.kind != Konst {
				continue
			}
			target := constSnapToPC(v)
			if target == 0 || !validDests[target] {
				continue
			}
			if _, exists := c.pcToBlock[target]; !exists {
				c.getOrCreateBlock(target)
			}
		}
	}
}

// constSnapToPC extracts a uint PC from a constant stack Value.
// Returns 0 if the Value is not constant or its integer value overflows uint.
func constSnapToPC(v *Value) uint {
	if v == nil || v.kind != Konst {
		return 0
	}
	if v.u != nil {
		u64, ov := v.u.Uint64WithOverflow()
		if ov {
			return 0
		}
		return uint(u64)
	}
	if len(v.payload) == 0 {
		return 0
	}
	u := new(uint256.Int).SetBytes(v.payload)
	u64, ov := u.Uint64WithOverflow()
	if ov {
		return 0
	}
	return uint(u64)
}

// getEntryStackForBlock determines the initial stack state for a block.
func (c *CFG) getEntryStackForBlock(block *MIRBasicBlock) *ValueStack {
	stack := new(ValueStack)

	if block != nil && block.firstPC == 3762 {
		epoch := uint64(0)
		if c != nil {
			epoch = c.runtimeEpoch
		}
		hasEntry := block.entryStack != nil
		log.Info("[MIR B2] block=3762 getEntryStackForBlock ENTER",
			"runtimeEpoch", epoch, "entryStack_nil", !hasEntry,
			"parents", len(block.parents), "incomingStacks", len(block.incomingStacks),
			"built", block.built)
	}

	// Case 1: Entry block (true entry, no predecessors).
	//
	// IMPORTANT: the entry block can still gain predecessors later (e.g. due to a back-edge/self-loop
	// discovered while building the CFG). In that case we must NOT early-return an empty stack,
	// otherwise CFG build can get stuck in a rebuild loop for self-loops. Only treat it as a "true"
	// entry when there are no recorded incomings at all.
	if block.blockNum == 0 && block.entryStack == nil && len(block.parents) == 0 && len(block.incomingStacks) == 0 {
		// Make the "known empty" entry snapshot explicit (non-nil) so later logic can distinguish
		// between "unknown/uncomputed" vs "computed empty".
		gen := uint64(0)
		// Tag runtime-built entry stacks with the current epoch so they won't leak across different
		// executions (calldata/gas/state). Parse-time stacks remain gen=0.
		if c != nil && c.runtimeEpoch != 0 {
			gen = c.runtimeEpoch
		}
		block.SetEntryStackWithGen([]Value{}, gen)
		return stack
	}

	// Case 2: First visit or invalidated entry (entryStack == nil)
	//
	// Build entry stack from recorded incomingStacks, inserting PHIs when values differ.
	if block.entryStack == nil {
		// Filter helper: incoming snapshots must never reference defs in the target block itself.
		// Such snapshots represent loop-carried runtime values and must be handled via PHIs, not by
		// embedding "future defs" in the entry stack (which later manifests as missing result errors).
		isValidIncoming := func(s []Value) bool {
			// Only enforce this during runtime execution of cached CFGs (epoch != 0).
			// During Parse() fixpoint construction we may temporarily observe self-defs before PHIs
			// converge; filtering them there can prevent convergence.
			if c == nil || c.runtimeEpoch == 0 {
				return true
			}
			if len(s) == 0 {
				return true
			}
			// NOTE: We intentionally do NOT filter out non-PHI self-defs here during runtime.
			// These can appear as loop-carried values in real contracts, and dropping the entire
			// incoming snapshot can freeze PHI construction (e.g. loop index stuck), ultimately
			// causing invalid jumpdest 0x0. Runtime execution can still evaluate these defs from
			// the interpreter result table (previous iteration) or repair via resIdx remapping.
			return true
		}
		// Gather incoming snapshots in deterministic parent order, but KEEP alignment to parents.
		//
		// IMPORTANT: PHI operands are later selected by indexing into `phi.operands` using the
		// predecessor's index in `block.parents` (see MIRInterpreter.evalPhi). If we drop a parent
		// here (missing/invalid snapshot), the operand indices shift and PHI resolution can select
		// a value from the wrong predecessor, causing "missing result for def" (consensus divergence).
		incomingsByParent := make([][]Value, len(block.parents))
		valid := make([][]Value, 0, len(block.parents))
		haveCurEpoch := false
		for i, p := range block.parents {
			if p == nil {
				continue
			}
			if s, ok := block.incomingStacks[p]; ok {
				// Filter stale runtime snapshots from previous executions when CFG is cached.
				if c != nil && c.runtimeEpoch != 0 && block.incomingStacksGen != nil {
					if g, okg := block.incomingStacksGen[p]; okg && g != 0 && g != c.runtimeEpoch {
						continue
					}
					if g, okg := block.incomingStacksGen[p]; okg && g == c.runtimeEpoch {
						haveCurEpoch = true
					}
				}
				if !isValidIncoming(s) {
					continue
				}
				incomingsByParent[i] = s
				valid = append(valid, s)
			}
		}
		// Fallback: if runtimeEpoch filtering dropped all incomings, re-include snapshots regardless of epoch.
		// This prevents rebuilding with an empty entry stack (which can cause SWAP/DUP underflow and
		// corrupt operand mapping). This is a best-effort correctness fallback for cached CFGs.
		if c != nil && c.runtimeEpoch != 0 && len(valid) == 0 && len(block.parents) > 0 {
			for i, p := range block.parents {
				if p == nil {
					continue
				}
				s, ok := block.incomingStacks[p]
				if !ok {
					continue
				}
				if !isValidIncoming(s) {
					continue
				}
				incomingsByParent[i] = s
				valid = append(valid, s)
			}
		}
		// Runtime preference: if we have incoming snapshots recorded for the *current* runtimeEpoch,
		// prefer building the entry stack from those (to avoid mixing calldatas/runs).
		//
		// However, if runtime requested a specific entry height (preferredEntryHeight), we must be careful:
		// blocks implementing "internal call/return" patterns often carry the return address on the stack,
		// and that value differs per predecessor. If we drop non-current-epoch incomings, PHIs won't be
		// created and we can bake the wrong return address as a constant, causing wrong JUMP targets.
		//
		// Therefore, when preferredEntryHeight is set, keep non-current-epoch incomings of that height
		// so PHI construction can reconcile them.
		if c != nil && c.runtimeEpoch != 0 && haveCurEpoch && block.incomingStacksGen != nil {
			useCurOnly := block.preferredEntryHeight < 0
			if block.preferredEntryHeight >= 0 {
				h := block.preferredEntryHeight
				for i, p := range block.parents {
					if p == nil {
						continue
					}
					s := incomingsByParent[i]
					if s == nil {
						continue
					}
					if g, okg := block.incomingStacksGen[p]; okg && g == c.runtimeEpoch && len(s) == h {
						useCurOnly = true
						break
					}
				}
			}
			if useCurOnly {
				valid = valid[:0]
				for i, p := range block.parents {
					if p == nil {
						continue
					}
					if s := incomingsByParent[i]; s != nil {
						if g, okg := block.incomingStacksGen[p]; okg && g == c.runtimeEpoch {
							valid = append(valid, s)
							continue
						}
						// Keep non-current-epoch incomings if runtime requested this height (PHI needed).
						if block.preferredEntryHeight >= 0 && len(s) == block.preferredEntryHeight {
							valid = append(valid, s)
							continue
						}
						incomingsByParent[i] = nil
					}
				}
			}
		}
		// Fallback: if parents list is empty but incomingStacks exists, use all snapshots.
		// (No parent alignment is possible here; PHI selection will fall back to snapshot indexing.)
		if len(valid) == 0 && len(block.parents) == 0 && len(block.incomingStacks) > 0 {
			incomingsByParent = nil
			for p, s := range block.incomingStacks {
				if c != nil && c.runtimeEpoch != 0 && block.incomingStacksGen != nil {
					if g, okg := block.incomingStacksGen[p]; okg && g != 0 && g != c.runtimeEpoch {
						continue
					}
				}
				if !isValidIncoming(s) {
					continue
				}
				valid = append(valid, s)
			}
		}
		if len(valid) == 0 {
			return stack
		}
		// EVM requires identical stack height at merge points. During dynamic CFG expansion we can
		// temporarily record infeasible edges with a different stack height; padding them with
		// Unknown values poisons PHI generation (and later leads to Unknown->0 at runtime).
		//
		// Strategy:
		// - If runtime asked for a specific height (preferredEntryHeight), rebuild from all incomings
		//   of that height (still inserting PHIs as needed).
		// - Otherwise, keep only the most common incoming stack height, breaking ties toward the
		//   smaller height (safer than assuming extra values exist).
		height := -1
		// If we know the parse-time entry height for this block and we're executing a cached CFG,
		// prefer sticking to that height. This prevents runtime rebuilds from accidentally selecting
		// an infeasible smaller height (which can make SWAP/DUP become no-ops and corrupt semantics).
		if c != nil && c.runtimeEpoch != 0 && block.fixedEntryHeight >= 0 && !c.hasUnresolvedJumps() {
			block.preferredEntryHeight = block.fixedEntryHeight
		}
		if block.preferredEntryHeight >= 0 {
			height = block.preferredEntryHeight
			filtered := make([][]Value, 0, len(valid))
			for _, s := range valid {
				if len(s) == height {
					filtered = append(filtered, s)
				}
			}
			if len(filtered) > 0 {
				valid = filtered
			} else {
				// No incomings with the preferred height; fall back to mode selection.
				height = -1
			}
			// One-shot hint: clear after use so future builds aren't biased.
			block.preferredEntryHeight = -1
		}
		if height < 0 {
			modeLen := len(valid[0])
			if len(valid) > 1 {
				counts := make(map[int]int, 4)
				for _, s := range valid {
					counts[len(s)]++
				}
				modeCnt := -1
				modeLen = -1
				for l, c := range counts {
					if c > modeCnt || (c == modeCnt && (modeLen < 0 || l < modeLen)) {
						modeLen = l
						modeCnt = c
					}
				}
				filtered := make([][]Value, 0, len(valid))
				for _, s := range valid {
					if len(s) == modeLen {
						filtered = append(filtered, s)
					}
				}
				if len(filtered) > 0 {
					valid = filtered
				}
			}
			height = modeLen
		}

		// Force PHI creation for loop headers and loop-internal merge points.
		// EnsureLoopInfo runs Tarjan SCC incrementally: it recomputes only when
		// the CFG structure changed (new edges via connectEdge). This is precise
		// enough to distinguish real cycles from internal-function call-return
		// patterns, which the old BFS heuristic could not.
		c.EnsureLoopInfo()
		hasBackEdge := block.IsLoopHeader || (block.IsInLoop && len(block.parents) > 1)
		if !hasBackEdge {
			for _, p := range block.parents {
				if p != nil && p.firstPC >= block.firstPC {
					hasBackEdge = true
					break
				}
			}
		}
		if block.firstPC == 3762 {
			parentPCs := make([]uint, 0, len(block.parents))
			for _, p := range block.parents {
				if p != nil {
					parentPCs = append(parentPCs, p.firstPC)
				} else {
					parentPCs = append(parentPCs, 0)
				}
			}
			log.Info("[MIR B2] block=3762 PHI-parse reached",
				"hasBackEdge", hasBackEdge, "IsLoopHeader", block.IsLoopHeader,
				"IsInLoop", block.IsInLoop, "height", height,
				"parents", fmt.Sprintf("%v", parentPCs), "valid_snapshots", len(valid))
		}

		for i := 0; i < height; i++ {
			base := valid[0][i]
			same := !hasBackEdge // force PHI creation for loop headers
			if same {
				for j := 1; j < len(valid); j++ {
					v := valid[j][i]
					if !equalValueForFlow(&base, &v) {
						same = false
						break
					}
				}
			}
			if same {
				valCopy := base
				valCopy.liveIn = true
				valCopy.liveInPos = i
				stack.push(&valCopy)
				continue
			}
			// Create PHI merging all incoming values at this stack slot.
			//
			// If we have parent alignment, we MUST emit one operand per parent (in the same index order),
			// even if an incoming snapshot is missing. Missing operands are filled with Unknown; they
			// should never be selected for real executed predecessors, but keep indices stable.
			var ops []*Value
			// distFromTop: 0 = topmost stack slot, 1 = second from top, etc.
			distFromTop := (height - 1) - i
			if incomingsByParent != nil && len(incomingsByParent) == len(block.parents) && len(block.parents) > 0 {
				ops = make([]*Value, len(block.parents))
				for j := range block.parents {
					s := incomingsByParent[j]
					// Align from stack TOP: index into this parent's stack at (len(s)-1-distFromTop).
					// Parents whose stacks are too short for this depth get Unknown.
					idx := -1
					if s != nil {
						idx = len(s) - 1 - distFromTop
					}
					if idx >= 0 && idx < len(s) {
						v := s[idx]
						v.liveIn = true
						vv := v
						ops[j] = &vv
					} else {
						// Parent's stack is too short for this depth. Instead of
						// Unknown (which would be unresolvable at runtime), create
						// a RuntimeVal that records where this value should come
						// from: the parent's exit stack at the requested depth.
						p := block.parents[j]
						rtPC := uint(0)
						if p != nil {
							rtPC = p.firstPC
						}
						vv := Value{
							kind:            RuntimeVal,
							liveIn:          true,
							liveInPos:       i,
							rtSourceBlockPC: rtPC,
							rtStackPos:      distFromTop,
						}
						ops[j] = &vv
					}
				}
			} else {
				ops = make([]*Value, 0, len(valid))
				for _, s := range valid {
					v := s[i]
					v.liveIn = true
					vv := v // heap allocate per-operand
					ops = append(ops, &vv)
				}
			}
			// phiStackIndex is 0 for top-of-stack.
			phiStackIndex := (height - 1) - i
			block.CreatePhiMIR(ops, stack, phiStackIndex)
		}

		// SSA loop-header fixup: rewrite back-edge PHI operands that reference an
		// OUTER-block PHI into same-block sibling-PHI references (standard SSA loop
		// form). Shift-register patterns encode the shift through the operand
		// resIdx: for slot N, op_back.resIdx matches some sibling slot M's
		// op_entry.resIdx, meaning "loop-back value at slot N" = "initial value at
		// slot M" — which in SSA is the sibling PHI's output.
		//
		// After this rewrite, evalPhi's parallel-copy snapshot (phiParallelSnap)
		// supplies the previous-iteration sibling value and the register shifts
		// correctly across iterations.
		//
		// We gate only on `hasBackEdge` (not block.IsLoopHeader) because IsLoopHeader
		// is set by Tarjan SCC which may not have run yet during this parse. Any
		// parent with firstPC >= block.firstPC is a textual back-edge and eligible
		// for the rewrite.
		if hasBackEdge {
			dbg3762 := block.firstPC == 3762
			// Build lookup from outer-PHI resIdx (as appears in op_entry) to the
			// sibling PHI that carries that value at block entry.
			entryDefToSibling := make(map[int]*MIR, height)
			for _, m := range block.instructions {
				if m == nil || m.op != MirPHI {
					continue
				}
				for j, p := range block.parents {
					if p == nil {
						continue
					}
					isBackEdgeParent := block.IsBackEdgeFrom(p) || p.firstPC >= block.firstPC
					if isBackEdgeParent {
						continue // only entry-edge operands
					}
					if j >= len(m.operands) || m.operands[j] == nil {
						continue
					}
					v := m.operands[j]
					if v.kind != Variable || v.def == nil || v.def.op != MirPHI {
						continue
					}
					// Only register the first entry-edge slot we find (simple case).
					if _, exists := entryDefToSibling[v.def.resIdx]; !exists {
						entryDefToSibling[v.def.resIdx] = m
					}
				}
			}
			if dbg3762 {
				log.Info("[MIR B2] block=3762 entryDefToSibling built",
					"size", len(entryDefToSibling), "parents", len(block.parents))
			}

			rewriteCount := 0
			skipSameBlock, skipNoSibling, skipSiblingSelf, skipNonPhiOperand := 0, 0, 0, 0
			for j, p := range block.parents {
				if p == nil {
					continue
				}
				isBackEdgeParent := block.IsBackEdgeFrom(p) || p.firstPC >= block.firstPC
				if !isBackEdgeParent {
					continue
				}
				for _, m := range block.instructions {
					if m == nil || m.op != MirPHI {
						continue
					}
					if j >= len(m.operands) || m.operands[j] == nil {
						continue
					}
					v := m.operands[j]
					if v.kind != Variable || v.def == nil || v.def.op != MirPHI {
						if dbg3762 {
							skipNonPhiOperand++
						}
						continue
					}
					// Skip if operand already references a same-block PHI (nothing to do).
					if v.def.defBlockNum == block.blockNum {
						if dbg3762 {
							skipSameBlock++
						}
						continue
					}
					// Look up the sibling PHI whose entry-edge operand references the
					// same outer PHI resIdx. That sibling IS the "previous-iteration
					// value" this back-edge operand wants (shift-register semantics).
					sibling, ok := entryDefToSibling[v.def.resIdx]
					if !ok {
						if dbg3762 {
							skipNoSibling++
							log.Info("[MIR B2] block=3762 NO_SIBLING",
								"phi.resIdx", m.resIdx,
								"op_back.def.resIdx", v.def.resIdx,
								"op_back.def.block", v.def.defBlockNum)
						}
						continue
					}
					if sibling == m {
						if dbg3762 {
							skipSiblingSelf++
						}
						continue
					}
					if dbg3762 {
						log.Info("[MIR B2] block=3762 REWRITE",
							"phi.resIdx", m.resIdx,
							"sibling.resIdx", sibling.resIdx,
							"was.op_back.def.resIdx", v.def.resIdx,
							"was.op_back.def.block", v.def.defBlockNum)
					}
					m.operands[j] = newValue(Variable, sibling, nil, nil)
					rewriteCount++
				}
			}
			if dbg3762 {
				log.Info("[MIR B2] block=3762 DONE",
					"rewrites", rewriteCount,
					"skip_same_block", skipSameBlock,
					"skip_no_sibling", skipNoSibling,
					"skip_sibling_self", skipSiblingSelf,
					"skip_non_phi_op", skipNonPhiOperand)
			}
		}

		// IMPORTANT: distinguish "computed empty entry stack" from "unknown/uncomputed".
		// ValueStack.data is nil for height=0, but we use nil entryStack as an invalidation marker.
		// Use an explicit empty slice so callers/tools (e.g., mir_visualizer) don't treat it as unknown.
		gen := uint64(0)
		if c != nil && c.runtimeEpoch != 0 {
			gen = c.runtimeEpoch
		}
		if stack.data == nil {
			block.SetEntryStackWithGen([]Value{}, gen)
		} else {
			block.SetEntryStackWithGen(stack.data, gen)
		}
		return stack
	}

	// Case 3: Re-visit (Block already has an entry stack snapshot)
	// We instantiate a working stack from the snapshot.
	if block.firstPC == 3762 {
		log.Info("[MIR B2] block=3762 Case3 REVISIT (PHI creation skipped)",
			"entryStack_len", len(block.entryStack))
	}
	for _, val := range block.entryStack {
		stack.push(&val)
	}
	return stack
}

// connectEdge links parent -> child and records the incoming stack snapshot for child.
// If the incoming snapshot for this (parent,child) pair changed, invalidate child's entry stack
// and mark it for rebuild (PHI may be required later).
func (c *CFG) connectEdge(parent, child *MIRBasicBlock, exitSnapshot []Value) {
	if parent == nil || child == nil {
		return
	}
	// Append edge (parent -> child) without clobbering existing edges.
	// Many real-world contracts (jump tables, loops) have multiple predecessors/successors.
	// Overwriting here corrupts CFG structure and PHI construction.
	{
		children := parent.Children()
		found := false
		for _, ch := range children {
			if ch == child {
				found = true
				break
			}
		}
		if !found {
			children = append(children, child)
			parent.SetChildren(children)
			// Maintain jumpTable in sync for O(1) runtime dispatch.
			if parent.jumpTable == nil {
				parent.jumpTable = make(map[uint]*MIRBasicBlock, 4)
			}
			parent.jumpTable[child.firstPC] = child
			// New edge may create or modify loops; invalidate loop analysis.
			if c != nil {
				c.loopInfoValid = false
			}
		}
	}
	newParent := false
	{
		parents := child.Parents()
		found := false
		for _, p := range parents {
			if p == parent {
				found = true
				break
			}
		}
		if !found {
			parents = append(parents, parent)
			child.SetParents(parents)
			newParent = true
		}
	}
	// Treat nil snapshot as an empty stack snapshot (important to record the predecessor).
	if exitSnapshot == nil {
		exitSnapshot = []Value{}
	}
	// Skeleton mode: only record the edge + snapshot. Never invalidate child
	// or mark descendants for rebuild. Skeleton's purpose is only to discover
	// block boundaries and edges; each block is built exactly once.
	if c != nil && c.skeletonMode {
		if child.incomingStacks == nil {
			child.incomingStacks = make(map[*MIRBasicBlock][]Value, 4)
		}
		if _, exists := child.incomingStacks[parent]; !exists {
			child.AddIncomingStack(parent, exitSnapshot)
		}
		return
	}
	// Only invalidate if this parent's incoming snapshot changed.
	if prev, ok := child.incomingStacks[parent]; ok {
		if stacksEqual(prev, exitSnapshot) {
			// Even when the snapshot contents are equal, tag it with the current runtime epoch so
			// cached CFG execution can correctly prefer "current run" incomings and avoid reusing
			// stale snapshots across different calldata/contexts.
			if c != nil && c.runtimeEpoch != 0 {
				if child.incomingStacksGen == nil {
					child.incomingStacksGen = make(map[*MIRBasicBlock]uint64, 8)
				}
				child.incomingStacksGen[parent] = c.runtimeEpoch
				// Also refresh the preferred entry height hint for this edge. This matters when a block
				// has multiple predecessors with differing stack heights: even if the snapshot for this
				// (parent,child) pair is unchanged, we still want rebuild logic to prefer the current
				// edge's height to avoid padding with Unknowns (which can corrupt return-address patterns
				// and lead to invalid jumpdest 0x0).
				child.preferredEntryHeight = len(exitSnapshot)
			}
			return
		}
	}
	child.AddIncomingStack(parent, exitSnapshot)
	if child.incomingStacksGen == nil {
		child.incomingStacksGen = make(map[*MIRBasicBlock]uint64, 8)
	}
	// Tag runtime snapshots with the current epoch; epoch==0 means "base/parse-time".
	child.incomingStacksGen[parent] = c.runtimeEpoch
	// Runtime hint: prefer rebuilding this block at the stack height observed on the edge we just
	// recorded. This avoids mode/tie heuristics picking an infeasible smaller height, which can
	// make SWAP/DUP become no-ops and corrupt semantics.
	if c != nil && c.runtimeEpoch != 0 {
		child.preferredEntryHeight = len(exitSnapshot)
	}
	// If this snapshot was written at runtime (after Parse() completed), record its snapshot epoch.
	// evalPhi uses incomingSnapshotEpoch to detect stale snapshots from a previous execution
	// without triggering the rebuild machinery used by runtimeEpoch.
	if c != nil && c.parseDone {
		if child.incomingSnapshotEpoch == nil {
			child.incomingSnapshotEpoch = make(map[*MIRBasicBlock]uint64, 4)
		}
		child.incomingSnapshotEpoch[parent] = c.snapshotEpoch
	}
	// At runtime, do NOT invalidate loop header blocks via existing back-edges.
	// The parse-time PHIs are correct, and invalidating at runtime triggers
	// rebuild → invalidateBlockResults → destroys loop-carried values.
	//
	// IMPORTANT: only skip for EXISTING back-edges (parent was already known).
	// A newly discovered back-edge (newParent=true) means the entry stack was
	// built without this parent's incoming snapshot, so PHIs have UNK operands
	// for this edge. We MUST invalidate and rebuild to add the new operand.
	//
	// Gate by c.parseDone (not runtimeEpoch != 0): simple CFGs (runtimeEpoch==0)
	// also rely on this skip when refreshEdgeIfNeeded materializes shift-register
	// snapshots for loop-back edges at runtime.
	if c != nil && c.parseDone && !newParent {
		c.EnsureLoopInfo()
		if child.IsLoopHeader && child.IsBackEdgeFrom(parent) {
			return
		}
	}
	child.SetEntryStack(nil)
	child.built = false
	// Conservative: when a block's incoming stack changes, its PHI set (and thus defs) can change,
	// which can invalidate downstream blocks that captured stale defs.
	//
	// During Parse() (runtimeEpoch==0), we aggressively mark descendants to reach a fixpoint.
	// During runtime execution, doing so is often overkill (and can trigger large rebuild cascades);
	// instead, rebuild is handled lazily as blocks are entered, except for dynamic-jump regions.
	if c != nil && (c.runtimeEpoch == 0 || parent.unresolvedJump || child.unresolvedJump) {
		c.markDescendantsForRebuild(child)
	}
}

func (c *CFG) markDescendantsForRebuild(start *MIRBasicBlock) {
	if start == nil {
		return
	}
	visited := make(map[*MIRBasicBlock]struct{}, 32)
	q := []*MIRBasicBlock{start}
	visited[start] = struct{}{}
	for len(q) > 0 {
		b := q[0]
		q = q[1:]
		// Force rebuild on next entry.
		b.built = false
		b.SetEntryStack(nil)
		for _, ch := range b.Children() {
			if ch == nil {
				continue
			}
			if _, ok := visited[ch]; ok {
				continue
			}
			visited[ch] = struct{}{}
			q = append(q, ch)
		}
	}
}

func (c *CFG) buildBasicBlock(block *MIRBasicBlock, validJumpDests map[uint]bool) error {
	bm := fullBuild
	if c.skeletonMode {
		bm = skeletonBuild
	}
	// CFG building uses package-level globals. Serialize builds across goroutines, but avoid
	// self-deadlock when called from CFG.Parse() (which already holds mirBuildMu).
	//
	// During Parse(), currentCFGBuild is set to `c` while the lock is held. Use that as a
	// signal that we're already in a serialized build context for this CFG.
	needLock := currentCFGBuild != c
	if needLock {
		mirBuildMu.Lock()
		defer mirBuildMu.Unlock()
	}

	// Set current CFG build context for MIR resIdx allocation.
	// This also covers dynamic backfill builds invoked at runtime.
	// IMPORTANT: if we're inside CFG.Parse(), currentCFGBuild is already set to `c` for the
	// whole parse pass. Do not clobber it back to nil per-block, otherwise subsequent block
	// builds in the same Parse() will incorrectly think they're outside the serialized build
	// context and attempt to re-lock mirBuildMu (deadlock).
	prevBuild := currentCFGBuild
	if prevBuild == nil {
		currentCFGBuild = c
	}
	defer func() { currentCFGBuild = prevBuild }()

	pc := block.firstPC
	codeLen := uint(len(c.rawCode))

	// Retry loop for cached/runtime rebuilds. See `errNeedEntryHeight`.
	retries := 0
retryBuild:
	// If retrying, clear prior build artifacts (partial MIR, opcode counts, etc).
	if retries > 0 && len(block.instructions) > 0 {
		block.ResetForRebuild(false)
	}
	// Per-build transient flags should be reset.
	block.unresolvedJump = false

	pc = block.firstPC
	codeLen = uint(len(c.rawCode))

	// 1. Initialize Stack
	// Ensure any PHIs created as part of entry stack construction get a stable EVM mapping
	// (otherwise they may inherit a stale currentEVMBuildPC/currentEVMBuildOp from a previous block).
	currentEVMBuildPC = pc
	if pc < codeLen {
		currentEVMBuildOp = c.rawCode[pc]
	} else {
		currentEVMBuildOp = 0
	}
	var stack *ValueStack
	if bm == skeletonBuild {
		// Skeleton mode: seed entry stack with Unknown values matching the
		// best-known height from predecessors. No PHI creation.
		stack = new(ValueStack)
		bestHeight := 0
		if block.entryStack != nil {
			bestHeight = len(block.entryStack)
		} else if block.blockNum == 0 {
			bestHeight = 0
		} else {
			// Use the most common incoming height.
			for _, s := range block.incomingStacks {
				if len(s) > bestHeight {
					bestHeight = len(s)
				}
			}
		}
		for i := 0; i < bestHeight; i++ {
			stack.push(&Value{kind: Unknown, liveIn: true, liveInPos: i})
		}
	} else {
		stack = c.getEntryStackForBlock(block)
	}
	initHeight := stack.size()

	traceStack := c.codeAddr == common.HexToHash("0xeb7764bd977fcb339cd6e661713f4aa19e5365c98c3ea788fcea59abca46e838") &&
		(block.firstPC == 3754 || block.firstPC == 3762 || block.firstPC == 3793)
	if traceStack {
		log.Info("[MIR B2] STACK-TRACE start",
			"block.firstPC", block.firstPC,
			"initHeight", initHeight,
			"bm", bm)
	}

	for pc < codeLen {
		op := compiler.ByteCode(c.rawCode[pc])

		// Global tracking for MIR generation
		currentEVMBuildPC = pc
		currentEVMBuildOp = byte(op)

		if traceStack {
			log.Info("[MIR B2] STACK-TRACE step",
				"block.firstPC", block.firstPC,
				"pc", pc,
				"op", fmt.Sprintf("0x%02x", byte(op)),
				"stackHeight.before", stack.size())
		}

		// 2. Check for Basic Block Boundaries (Implicit)
		// If we are NOT at the start of the block, but we hit a JUMPDEST,
		// then this block MUST end here (fallthrough to the next block).
		if pc != block.firstPC && op == compiler.JUMPDEST {
			// Record block end. This is a fallthrough edge, not an executed JUMP opcode.
			block.SetLastPC(pc)
			// Record exit stack snapshot (used by later PHI/merge logic)
			exitSnap := stack.clone()
			block.SetExitStack(exitSnap)
			if traceStack {
				for i, v := range exitSnap {
					var dStr string
					switch v.kind {
					case Konst:
						dStr = fmt.Sprintf("K(%x)", v.payload)
					case Variable:
						if v.def != nil {
							dStr = fmt.Sprintf("V(defPC=%d defOp=%d defBlk=%d defResIdx=%d)", v.def.evmPC, v.def.op, v.def.defBlockNum, v.def.resIdx)
						} else {
							dStr = "V(nil)"
						}
					case Unknown:
						dStr = fmt.Sprintf("UNK(liveInPos=%d)", v.liveInPos)
					default:
						dStr = "?"
					}
					log.Info("[MIR B2] STACK-TRACE exit-slot",
						"block.firstPC", block.firstPC,
						"slot", i, "val", dStr)
				}
			}
			// Link to next block and record incoming snapshot
			nextBlock := c.getOrCreateBlock(pc)
			c.connectEdge(block, nextBlock, exitSnap)

			block.built = true
			return nil
		}

		// Count every originating EVM opcode for gas parity bookkeeping.
		// IMPORTANT: this must happen *after* the boundary split check above, otherwise
		// we'd count a boundary JUMPDEST in the predecessor block and overcharge by 1 gas.
		if block.evmOpCounts != nil {
			block.evmOpCounts[byte(op)]++
		}
		// Also record the exact opcode stream (pc,op) for this block (used for GAS/call gas correctness).
		block.recordEVMOp(pc, byte(op))

		// 2.5 Handle no-op JUMPDEST (valid instruction, may only appear at block start here)
		if op == compiler.JUMPDEST {
			// We don't need to emit MIR for JUMPDEST; it is a marker.
			pc++
			continue
		}

		// 3. Dispatch Opcode Groups
		var err error
		switch {
		case isStackOp(op): // PUSH, DUP, SWAP, POP
			pc, err = c.handleStackOp(block, op, stack, pc)
			if err != nil && bm == skeletonBuild {
				// Skeleton mode: stack underflow on DUP/SWAP just means we don't
				// know the entry height yet. Pad and continue.
				if _, ok := err.(*errNeedEntryHeight); ok {
					break
				}
				if _, ok := err.(*errNeedPreferredEntryHeight); ok {
					break
				}
				return err
			}
			if err != nil {
				// If this is a runtime rebuild and we can satisfy the required entry height,
				// retry compilation of this block with the requested height.
				if need, ok := err.(*errNeedEntryHeight); ok && c != nil && c.runtimeEpoch != 0 {
					// Translate the observed underflow at the current PC into a minimum *entry* height.
					//
					// The stack height at this PC is: entryHeight + netDelta(prefixOps).
					// If the current build saw `have` but needs `need`, then increasing the entry height by
					// (need-have) is sufficient.
					wantEntry := initHeight + (need.need - need.have)
					if wantEntry < 0 {
						wantEntry = 0
					}
					block.preferredEntryHeight = wantEntry
					block.SetEntryStack(nil)
					block.built = false
					// Avoid spinning indefinitely.
					if retries < 2 {
						retries++
						goto retryBuild
					}
				}
				// Similar retry mechanism: prefer a specific entry height requested by runtime
				// control-flow validation (e.g. invalid constant JUMP dest due to missing deep items).
				if need, ok := err.(*errNeedPreferredEntryHeight); ok && c != nil && c.runtimeEpoch != 0 {
					block.preferredEntryHeight = need.want
					block.SetEntryStack(nil)
					block.built = false
					if retries < 2 {
						retries++
						goto retryBuild
					}
				}
				return err
			}
		case isUnaryOp(op):
			if bm == skeletonBuild {
				stack.pop()
				stack.push(&Value{kind: Unknown})
				pc++
				break
			}
			// Map EVM unary opcode to MIR op by meaning
			var mirOp MirOperation
			switch op {
			case compiler.NOT:
				mirOp = MirNOT
			case compiler.ISZERO:
				mirOp = MirISZERO
			default:
				return fmt.Errorf("unhandled unary opcode: %x at %d", op, pc)
			}
			block.CreateUnaryOpMIR(mirOp, stack)
			pc++
		case isTernaryOp(op):
			if bm == skeletonBuild {
				stack.pop(); stack.pop(); stack.pop()
				stack.push(&Value{kind: Unknown})
				pc++
				break
			}
			var mirOp MirOperation
			switch op {
			case compiler.ADDMOD:
				mirOp = MirADDMOD
			case compiler.MULMOD:
				mirOp = MirMULMOD
			default:
				return fmt.Errorf("unhandled ternary opcode: %x at %d", op, pc)
			}
			block.CreateTernaryOpMIR(mirOp, stack)
			pc++
		case isBinaryOp(op):
			if bm == skeletonBuild {
				stack.pop(); stack.pop()
				stack.push(&Value{kind: Unknown})
				pc++
				break
			}
			// Most binary ops share the same numeric encoding for MIR up to 0x5e.
			// Map explicitly for clarity and to avoid relying on enum alignment.
			var mirOp MirOperation
			switch op {
			case compiler.ADD:
				mirOp = MirADD
			case compiler.MUL:
				mirOp = MirMUL
			case compiler.SUB:
				mirOp = MirSUB
			case compiler.DIV:
				mirOp = MirDIV
			case compiler.SDIV:
				mirOp = MirSDIV
			case compiler.MOD:
				mirOp = MirMOD
			case compiler.SMOD:
				mirOp = MirSMOD
			case compiler.EXP:
				mirOp = MirEXP
			case compiler.SIGNEXTEND:
				mirOp = MirSIGNEXT
			case compiler.LT:
				mirOp = MirLT
			case compiler.GT:
				mirOp = MirGT
			case compiler.SLT:
				mirOp = MirSLT
			case compiler.SGT:
				mirOp = MirSGT
			case compiler.EQ:
				mirOp = MirEQ
			case compiler.AND:
				mirOp = MirAND
			case compiler.OR:
				mirOp = MirOR
			case compiler.XOR:
				mirOp = MirXOR
			case compiler.BYTE:
				mirOp = MirBYTE
			case compiler.SHL:
				mirOp = MirSHL
			case compiler.SHR:
				mirOp = MirSHR
			case compiler.SAR:
				mirOp = MirSAR
			case compiler.KECCAK256:
				mirOp = MirKECCAK256
			default:
				return fmt.Errorf("unhandled binary opcode: %x at %d", op, pc)
			}
			block.CreateBinOpMIR(mirOp, stack)
			pc++
		case isMemoryOp(op):
			if bm == skeletonBuild {
				switch op {
				case compiler.MLOAD: // pop 1, push 1
					stack.pop()
					stack.push(&Value{kind: Unknown})
				case compiler.MSTORE, compiler.MSTORE8: // pop 2, push 0
					stack.pop(); stack.pop()
				case compiler.MSIZE: // pop 0, push 1
					stack.push(&Value{kind: Unknown})
				case compiler.MCOPY: // pop 3, push 0
					stack.pop(); stack.pop(); stack.pop()
				}
				pc++
				break
			}
			switch op {
			case compiler.MLOAD:
				// MLOAD pops: offset, pushes: value
				offset := stack.pop()
				mir := new(MIR)
				mir.op = MirMLOAD
				mir.operands = []*Value{&offset}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSTORE:
				// MSTORE pops: offset(top), value. No return value.
				offset := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirMSTORE
				mir.operands = []*Value{&offset, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSTORE8:
				// MSTORE8 pops: offset(top), value. No return value.
				offset := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirMSTORE8
				mir.operands = []*Value{&offset, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MSIZE:
				// MSIZE pushes current memory size. No pops.
				mir := new(MIR)
				mir.op = MirMSIZE
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.MCOPY:
				// MCOPY pops: dst, src, size (EIP-5656). No return value.
				dst := stack.pop()
				src := stack.pop()
				sz := stack.pop()
				mir := new(MIR)
				mir.op = MirMCOPY
				mir.operands = []*Value{&dst, &src, &sz}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled memory opcode: %x at %d", op, pc)
			}
			pc++
		case isStorageOp(op):
			if bm == skeletonBuild {
				switch op {
				case compiler.SLOAD, compiler.TLOAD: // pop 1, push 1
					stack.pop()
					stack.push(&Value{kind: Unknown})
				case compiler.SSTORE, compiler.TSTORE: // pop 2, push 0
					stack.pop(); stack.pop()
				}
				pc++
				break
			}
			switch op {
			case compiler.SLOAD:
				// SLOAD pops: key, pushes: value
				key := stack.pop()
				mir := new(MIR)
				mir.op = MirSLOAD
				mir.operands = []*Value{&key}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.SSTORE:
				// SSTORE pops: key(top), value. No return value.
				key := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirSSTORE
				mir.operands = []*Value{&key, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.TLOAD:
				// TLOAD pops: key, pushes: value
				key := stack.pop()
				mir := new(MIR)
				mir.op = MirTLOAD
				mir.operands = []*Value{&key}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.TSTORE:
				// TSTORE pops: key(top), value. No return value.
				key := stack.pop()
				value := stack.pop()
				mir := new(MIR)
				mir.op = MirTSTORE
				mir.operands = []*Value{&key, &value}
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled storage opcode: %x at %d", op, pc)
			}
			pc++
		case isBlockInfoOp(op):
			if bm == skeletonBuild {
				// BlockInfo ops: all push 1 value, pop 0 (ADDRESS, CALLER, CALLVALUE, etc.)
				// Exception: EXTCODESIZE/EXTCODEHASH pop 1 push 1; BALANCE pop 1 push 1.
				switch op {
				case compiler.BALANCE, compiler.EXTCODESIZE, compiler.EXTCODEHASH:
					stack.pop()
				}
				stack.push(&Value{kind: Unknown})
				pc++
				break
			}
			// Closure/tx/env info ops handled by CreateBlockInfoMIR
			block.CreateBlockInfoMIR(MirOperation(byte(op)), stack)
			pc++
		case isBlockOp(op):
			if bm == skeletonBuild {
				// Block context ops: BLOCKHASH pops 1 pushes 1; others push 1 pop 0.
				if op == compiler.BLOCKHASH {
					stack.pop()
				}
				stack.push(&Value{kind: Unknown})
				pc++
				break
			}
			// Block ops handled by CreateBlockOpMIR
			block.CreateBlockOpMIR(MirOperation(byte(op)), stack)
			pc++
		case isLogOp(op):
			if bm == skeletonBuild {
				// LOGn pops: offset, size, + n topics. No return value.
				n := int(op - compiler.LOG0)
				stack.pop(); stack.pop() // offset, size
				for i := 0; i < n; i++ {
					stack.pop()
				}
				pc++
				break
			}
			block.CreateLogMIR(MirLOG0+MirOperation(op-compiler.LOG0), stack)
			pc++
		case isSystemCallOp(op):
			if bm == skeletonBuild {
				switch op {
				case compiler.CALL, compiler.CALLCODE: // pop 7, push 1
					for i := 0; i < 7; i++ { stack.pop() }
					stack.push(&Value{kind: Unknown})
				case compiler.DELEGATECALL, compiler.STATICCALL: // pop 6, push 1
					for i := 0; i < 6; i++ { stack.pop() }
					stack.push(&Value{kind: Unknown})
				case compiler.CREATE: // pop 3, push 1
					stack.pop(); stack.pop(); stack.pop()
					stack.push(&Value{kind: Unknown})
				case compiler.CREATE2: // pop 4, push 1
					for i := 0; i < 4; i++ { stack.pop() }
					stack.push(&Value{kind: Unknown})
				case compiler.SELFDESTRUCT: // pop 1, push 0
					stack.pop()
				case compiler.CALLDATALOAD: // pop 1, push 1
					stack.pop()
					stack.push(&Value{kind: Unknown})
				case compiler.CALLDATASIZE, compiler.RETURNDATASIZE, compiler.CODESIZE: // pop 0, push 1
					stack.push(&Value{kind: Unknown})
				case compiler.CALLDATACOPY, compiler.CODECOPY, compiler.RETURNDATACOPY: // pop 3, push 0
					stack.pop(); stack.pop(); stack.pop()
				case compiler.EXTCODECOPY: // pop 4, push 0
					for i := 0; i < 4; i++ { stack.pop() }
				}
				pc++
				break
			}
			// Implement core CALL/CREATE family with correct stack effects.
			// Note: opcode values in compiler package differ from MirOperation for some calls.
			switch op {
			case compiler.CALL:
				// EVM stack (top to bottom): gas, to, value, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				value := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirCALL
				mir.operands = []*Value{&gas, &to, &value, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CALLCODE:
				// EVM stack (top to bottom): gas, to, value, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				value := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirCALLCODE
				mir.operands = []*Value{&gas, &to, &value, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.DELEGATECALL:
				// EVM stack (top to bottom): gas, to, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirDELEGATECALL
				mir.operands = []*Value{&gas, &to, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.STATICCALL:
				// EVM stack (top to bottom): gas, to, inOff, inSize, outOff, outSize
				gas := stack.pop()
				to := stack.pop()
				inOff := stack.pop()
				inSize := stack.pop()
				outOff := stack.pop()
				outSize := stack.pop()
				mir := new(MIR)
				mir.op = MirSTATICCALL
				mir.operands = []*Value{&gas, &to, &inOff, &inSize, &outOff, &outSize}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CREATE:
				// EVM CREATE pops: value(top), offset, size.
				value := stack.pop()
				off := stack.pop()
				sz := stack.pop()
				mir := new(MIR)
				mir.op = MirCREATE
				mir.operands = []*Value{&value, &off, &sz}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.CREATE2:
				// EVM CREATE2 pops: value(top), offset, size, salt.
				value := stack.pop()
				off := stack.pop()
				sz := stack.pop()
				salt := stack.pop()
				mir := new(MIR)
				mir.op = MirCREATE2
				mir.operands = []*Value{&value, &off, &sz, &salt}
				stack.push(mir.Result())
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTCALL:
				// Treat as system op: stack semantics are chain-specific; placeholder to keep CFG build going.
				mir := new(MIR)
				mir.op = MirEXTCALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTDELEGATECALL:
				mir := new(MIR)
				mir.op = MirEXTDELEGATECALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			case compiler.EXTSTATICCALL:
				mir := new(MIR)
				mir.op = MirEXTSTATICCALL
				mir = block.appendMIR(mir)
				mir.genStackDepth = stack.size()
			default:
				return fmt.Errorf("unhandled system/call opcode: %x at %d", op, pc)
			}
			pc++
		// Terminators / control flow
		case op == compiler.STOP:
			// STOP: end execution, no operands
			mir := new(MIR)
			mir.op = MirSTOP
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.RETURN:
			// RETURN pops: offset, size
			offset := stack.pop()
			size := stack.pop()
			mir := new(MIR)
			mir.op = MirRETURN
			mir.operands = []*Value{&offset, &size}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.REVERT:
			// REVERT pops: offset, size
			offset := stack.pop()
			size := stack.pop()
			mir := new(MIR)
			mir.op = MirREVERT
			mir.operands = []*Value{&offset, &size}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.SELFDESTRUCT:
			// SELFDESTRUCT pops: address
			addr := stack.pop()
			mir := new(MIR)
			mir.op = MirSELFDESTRUCT
			mir.operands = []*Value{&addr}
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.INVALID:
			// INVALID: immediate exceptional halt
			mir := new(MIR)
			mir.op = MirINVALID
			block.appendMIR(mir)
			block.SetLastPC(pc + 1)
			block.SetExitStack(stack.clone())
			block.built = true
			return nil
		case op == compiler.JUMP:
			// JUMP pops: dest
			dest := stack.pop()
			mir := new(MIR)
			mir.op = MirJUMP
			mir.operands = []*Value{&dest}
			block.appendMIR(mir)

			// Resolve successor if constant; otherwise mark as unresolved for runtime backfill.
			exitSnap := stack.clone()
			if dest.kind == Konst {
				target := uint(0)
				if dest.u != nil {
					target = uint(dest.u.Uint64())
				} else {
					target = uint(dest.ConstValue())
				}
				if !validJumpDests[target] {
					// During runtime rebuilds (cached CFG execution), the stack model can be temporarily
					// specialized/stale for this edge, producing an incorrect constant jump target. Do not
					// fail the build here. Instead, request a rebuild preferring the maximum incoming
					// stack height so deep stack items (return addresses) are preserved.
					if c != nil && c.runtimeEpoch != 0 {
						if want := maxIncomingLenForBlock(block); want > 0 && want != initHeight {
							return &errNeedPreferredEntryHeight{pc: pc, op: op, want: want}
						}
						// Fallback: treat as unresolved and let runtime resolve based on actual values.
						block.unresolvedJump = true
						c.hasUnresolvedJumpsFlag = true
						block.SetLastPC(pc + 1)
						block.SetExitStack(exitSnap)
						block.built = true
						return nil
					}
					return fmt.Errorf("invalid jumpdest 0x%x at pc %d", target, pc)
				}
				targetBlock := c.getOrCreateBlock(target)
				c.connectEdge(block, targetBlock, exitSnap)
				// Self-loop may invalidate this block's entryStack; request rebuild by leaving built=false.
				if targetBlock == block && block.entryStack == nil {
					block.SetLastPC(pc + 1)
					block.SetExitStack(exitSnap)
					block.built = false
					return nil
				}
			} else {
				// Dynamic destination: attempt compile-time def-chain tracing.
				// Handles the common multi-caller internal-function return pattern where
				// dest is a MirPHI or a live-in constant from predecessor blocks.
				candidates, allResolved := traceJumpDestCandidates(&dest, block, validJumpDests)
				for _, target := range candidates {
					targetBlock := c.getOrCreateBlock(target)
					c.connectEdge(block, targetBlock, exitSnap)
					// Self-loop: entry stack invalidated; request rebuild.
					if targetBlock == block && block.entryStack == nil {
						block.SetLastPC(pc + 1)
						block.SetExitStack(exitSnap)
						block.built = false
						return nil
					}
				}
				if !allResolved {
					// At least one def-chain path was opaque; keep runtime backfill.
					block.unresolvedJump = true
					c.hasUnresolvedJumpsFlag = true
				}
				// allResolved==true: all successors statically known; no runtime backfill needed.
			}

			block.SetLastPC(pc + 1)
			block.SetExitStack(exitSnap)
			block.built = true
			return nil
		case op == compiler.JUMPI:
			// JUMPI pops: dest, cond (note: CreateJumpMIR in MIRBasicBlock.go pops dest then cond)
			dest := stack.pop()
			cond := stack.pop()
			mir := new(MIR)
			mir.op = MirJUMPI
			mir.operands = []*Value{&dest, &cond}
			block.appendMIR(mir)

			// Fallthrough successor (pc+1)
			exitSnap := stack.clone()
			fallthroughPC := pc + 1
			fallthroughBlock := c.getOrCreateBlock(fallthroughPC)
			c.connectEdge(block, fallthroughBlock, exitSnap)

			// Branch successor if constant dest
			if dest.kind == Konst {
				target := uint(0)
				if dest.u != nil {
					target = uint(dest.u.Uint64())
				} else {
					target = uint(dest.ConstValue())
				}
				if !validJumpDests[target] {
					if c != nil && c.runtimeEpoch != 0 {
						if want := maxIncomingLenForBlock(block); want > 0 && want != initHeight {
							return &errNeedPreferredEntryHeight{pc: pc, op: op, want: want}
						}
						// Fallback: treat as unresolved and keep only the fallthrough edge.
						block.unresolvedJump = true
						c.hasUnresolvedJumpsFlag = true
						block.SetLastPC(pc + 1)
						block.SetExitStack(exitSnap)
						block.built = true
						return nil
					}
					return fmt.Errorf("invalid jumpdest 0x%x at pc %d", target, pc)
				}
				targetBlock := c.getOrCreateBlock(target)
				c.connectEdge(block, targetBlock, exitSnap)
				if targetBlock == block && block.entryStack == nil {
					block.SetLastPC(pc + 1)
					block.SetExitStack(exitSnap)
					block.built = false
					return nil
				}
			} else {
				// Dynamic destination: attempt compile-time def-chain tracing.
				candidates, allResolved := traceJumpDestCandidates(&dest, block, validJumpDests)
				for _, target := range candidates {
					targetBlock := c.getOrCreateBlock(target)
					c.connectEdge(block, targetBlock, exitSnap)
					if targetBlock == block && block.entryStack == nil {
						block.SetLastPC(pc + 1)
						block.SetExitStack(exitSnap)
						block.built = false
						return nil
					}
				}
				if !allResolved {
					block.unresolvedJump = true
					c.hasUnresolvedJumpsFlag = true
				}
			}

			block.SetLastPC(pc + 1)
			block.SetExitStack(exitSnap)
			block.built = true
			return nil
		default:
			// Placeholder for now
			return fmt.Errorf("unsupported opcode: %x at %d", op, pc)
		}

		if err != nil {
			return err
		}
		// Detect parse-time stack underflow on the true EVM entry block.
		//
		// The EVM always starts execution with an empty stack. If the entry block
		// (blockNum==0, no predecessors, empty entry stack) pops from an empty stack,
		// the bytecode has an instruction that would unconditionally stack-underflow at
		// runtime. MIR silently returns Unknown operands for such pops, builds a CFG that
		// "succeeds", and diverges from the base EVM (which fails the tx and consumes all gas).
		//
		// We restrict this check to the true entry block (no parents) with a genuinely empty
		// entry stack (initHeight==0) to avoid false positives during the iterative Parse()
		// fixpoint: non-entry blocks may have an empty entry stack on their first visit
		// (predecessor edges not yet connected) and would be re-built correctly once those
		// edges are recorded. Firing an error there would abort Parse() for legitimate contracts.
		if stack.underflowed && c != nil && c.runtimeEpoch == 0 &&
			block.blockNum == 0 && len(block.parents) == 0 && initHeight == 0 {
			return fmt.Errorf("MIR CFG parse: stack underflow at pc=%d op=0x%02x (instruction requires stack items but entry stack was empty)", currentEVMBuildPC, currentEVMBuildOp)
		}
	}

	// End of code reached without explicit terminator
	block.CreateSystemOpMIR(MirSTOP, stack)
	block.SetLastPC(pc)
	block.SetExitStack(stack.clone())
	block.built = true
	return nil
}

// Helpers

const maxJumpTraceDepth = 6

// traceJumpDestCandidates walks the def-chain of a JUMP/JUMPI destination Value to enumerate
// all statically-known JUMPDEST target PCs reachable via compile-time constant propagation.
//
// It resolves:
//   - Direct Konst values
//   - MirPHI nodes (multi-caller return-address pattern)
//   - Live-in Variables/Unknowns with a known liveInPos (looks up incomingStacks)
//
// Returns (targets, allResolved).
// allResolved==true means every def-chain path terminated at a known constant (or a valid
// non-JUMPDEST constant), so the caller can clear unresolvedJump for this block.
func traceJumpDestCandidates(dest *Value, block *MIRBasicBlock, validJumpDests map[uint]bool) (targets []uint, allResolved bool) {
	if dest == nil {
		return nil, false
	}
	seenDef := make(map[*MIR]struct{}, 8)
	foundSet := make(map[uint]struct{}, 4)
	hitUnknown := false

	var walk func(v *Value, depth int)
	walk = func(v *Value, depth int) {
		if v == nil || depth > maxJumpTraceDepth {
			hitUnknown = true
			return
		}
		switch v.kind {
		case Konst:
			target := constSnapToPC(v)
			if target > 0 && validJumpDests[target] {
				foundSet[target] = struct{}{}
			}
			// Non-JUMPDEST constant is a fully-resolved leaf (not a valid target, but known).

		case Variable:
			if v.def == nil {
				// Def-less Variable that is a live-in: look up incomingStacks.
				if v.liveIn && v.liveInPos >= 0 && block != nil {
					// Iterate in deterministic parent order so that the connectEdge calls
					// driven by discovered candidates always append children in the same order,
					// regardless of Go map iteration randomness.
					for _, p := range block.parents {
						snap, ok := block.incomingStacks[p]
						if !ok {
							continue
						}
						if v.liveInPos < len(snap) {
							sv := snap[v.liveInPos]
							walk(&sv, depth+1)
						}
					}
					return
				}
				hitUnknown = true
				return
			}
			// Guard against PHI cycles.
			if _, ok := seenDef[v.def]; ok {
				return
			}
			seenDef[v.def] = struct{}{}
			if v.def.op == MirPHI {
				// Recurse into every PHI input: each operand is the value from one predecessor.
				for _, op := range v.def.operands {
					walk(op, depth+1)
				}
				return
			}
			// Any other computed Variable (arithmetic, CALLDATALOAD, etc.) is opaque.
			hitUnknown = true

		default: // Unknown
			// Live-in with a known position: resolve through all incoming snapshots.
			if v.liveIn && v.liveInPos >= 0 && block != nil {
				// Same deterministic parent-order iteration as the Variable case above.
				for _, p := range block.parents {
					snap, ok := block.incomingStacks[p]
					if !ok {
						continue
					}
					if v.liveInPos < len(snap) {
						sv := snap[v.liveInPos]
						walk(&sv, depth+1)
					}
				}
				return
			}
			hitUnknown = true
		}
	}
	walk(dest, 0)

	for t := range foundSet {
		targets = append(targets, t)
	}
	return targets, len(targets) > 0 && !hitUnknown
}

func isStackOp(op compiler.ByteCode) bool {
	return (op == compiler.PUSH0) ||
		(op >= compiler.PUSH1 && op <= compiler.PUSH32) ||
		(op >= compiler.DUP1 && op <= compiler.DUP16) ||
		(op >= compiler.SWAP1 && op <= compiler.SWAP16) ||
		(op == compiler.POP)
}

type errNeedEntryHeight struct {
	pc   uint
	op   compiler.ByteCode
	need int
	have int
}

func (e *errNeedEntryHeight) Error() string {
	return fmt.Sprintf("need entry stack height >= %d for op=0x%02x at pc=%d (have=%d)", e.need, byte(e.op), e.pc, e.have)
}

// errNeedPreferredEntryHeight is used when a runtime rebuild discovers that the block was built
// with an entry stack height that is inconsistent with the observed incoming stacks (even if no
// immediate underflow occurs). This typically manifests as invalid constant JUMP destinations
// (e.g. JUMP 0x0) due to missing deep stack items (return addresses).
type errNeedPreferredEntryHeight struct {
	pc   uint
	op   compiler.ByteCode
	want int
}

func (e *errNeedPreferredEntryHeight) Error() string {
	return fmt.Sprintf("need preferred entry height=%d for op=0x%02x at pc=%d", e.want, byte(e.op), e.pc)
}

func maxIncomingLenForBlock(b *MIRBasicBlock) int {
	if b == nil || b.incomingStacks == nil || len(b.incomingStacks) == 0 {
		return -1
	}
	maxLen := -1
	for _, s := range b.incomingStacks {
		if l := len(s); l > maxLen {
			maxLen = l
		}
	}
	return maxLen
}

func (c *CFG) handleStackOp(block *MIRBasicBlock, op compiler.ByteCode, stack *ValueStack, pc uint) (uint, error) {
	// PUSH0 pushes a single zero byte (EIP-3855)
	if op == compiler.PUSH0 {
		block.CreatePushMIR(0, []byte{0x00}, stack)
		return pc + 1, nil
	}

	// Handle PUSH specially because it has immediate data
	if op >= compiler.PUSH1 && op <= compiler.PUSH32 {
		size := uint(op - compiler.PUSH1 + 1)
		if pc+1+size > uint(len(c.rawCode)) {
			return pc, fmt.Errorf("truncated PUSH instruction at %d", pc)
		}
		data := c.rawCode[pc+1 : pc+1+size]
		block.CreatePushMIR(int(size), data, stack)
		return pc + 1 + size, nil
	}

	// Map EVM opcode to MIR Operation
	var mirOp MirOperation
	switch {
	case op == compiler.POP:
		// POP pops 1 element, produces no result
		v := stack.pop()
		mir := new(MIR)
		mir.op = MirPOP
		mir.operands = []*Value{&v}
		mir = block.appendMIR(mir)
		mir.genStackDepth = stack.size()
		return pc + 1, nil
	case op >= compiler.DUP1 && op <= compiler.DUP16:
		// DUPn requires at least n items on the stack.
		// If the builder observes an underflow, it means the current stack model doesn't have
		// enough live-ins for this block (common with dynamic control-flow / partial builds).
		// Silently treating DUP as a no-op corrupts operand mapping (e.g. wrong constant JUMP dest),
		// so during runtime rebuilds we must request a rebuild with a larger entry stack height.
		// For non-runtime builds (Parse-time), we can pad the *bottom* with Unknown live-ins as a
		// conservative approximation.
		n := int(op-compiler.DUP1) + 1
		if stack.size() < n {
			if c != nil && c.runtimeEpoch != 0 {
				return pc, &errNeedEntryHeight{pc: pc, op: op, need: n, have: stack.size()}
			}
			stack.padBottomTo(n)
		}
		mirOp = MirDUP1 + MirOperation(op-compiler.DUP1)
	case op >= compiler.SWAP1 && op <= compiler.SWAP16:
		// SWAPn requires at least n+1 items on the stack.
		n := int(op-compiler.SWAP1) + 1
		if stack.size() < n+1 {
			if c != nil && c.runtimeEpoch != 0 {
				return pc, &errNeedEntryHeight{pc: pc, op: op, need: n + 1, have: stack.size()}
			}
			stack.padBottomTo(n + 1)
		}
		mirOp = MirSWAP1 + MirOperation(op-compiler.SWAP1)
	}

	block.CreateStackOpMIR(mirOp, stack)
	return pc + 1, nil
}

func isLogOp(op compiler.ByteCode) bool {
	return op >= compiler.LOG0 && op <= compiler.LOG4
}

func isUnaryOp(op compiler.ByteCode) bool {
	return op == compiler.NOT || op == compiler.ISZERO
}

func isTernaryOp(op compiler.ByteCode) bool {
	return op == compiler.ADDMOD || op == compiler.MULMOD
}

func isBinaryOp(op compiler.ByteCode) bool {
	// Arithmetic & bitwise & compare & shifts & byte & signextend & keccak
	switch op {
	case compiler.ADD, compiler.MUL, compiler.SUB, compiler.DIV, compiler.SDIV, compiler.MOD, compiler.SMOD,
		compiler.EXP, compiler.SIGNEXTEND,
		compiler.LT, compiler.GT, compiler.SLT, compiler.SGT, compiler.EQ,
		compiler.AND, compiler.OR, compiler.XOR, compiler.BYTE, compiler.SHL, compiler.SHR, compiler.SAR,
		compiler.KECCAK256:
		return true
	default:
		return false
	}
}

func isMemoryOp(op compiler.ByteCode) bool {
	switch op {
	case compiler.MLOAD, compiler.MSTORE, compiler.MSTORE8, compiler.MSIZE, compiler.MCOPY:
		return true
	default:
		return false
	}
}

func isStorageOp(op compiler.ByteCode) bool {
	return op == compiler.SLOAD || op == compiler.SSTORE || op == compiler.TLOAD || op == compiler.TSTORE
}

func isBlockInfoOp(op compiler.ByteCode) bool {
	// closure state + a few misc producers/consumers handled by CreateBlockInfoMIR
	return (op >= compiler.ADDRESS && op <= compiler.EXTCODEHASH) ||
		op == compiler.PC || op == compiler.GAS
}

func isBlockOp(op compiler.ByteCode) bool {
	// block environment ops
	return op >= compiler.BLOCKHASH && op <= compiler.BLOBBASEFEE
}

func isSystemCallOp(op compiler.ByteCode) bool {
	// CALL-family + CREATE-family + STATICCALL (note: opcode values may differ from MIR op enum)
	switch op {
	case compiler.CREATE, compiler.CALL, compiler.CALLCODE, compiler.DELEGATECALL, compiler.CREATE2, compiler.STATICCALL,
		compiler.EXTCALL, compiler.EXTDELEGATECALL, compiler.EXTSTATICCALL:
		return true
	default:
		return false
	}
}
