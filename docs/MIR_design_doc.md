# MIR (Mid-level Intermediate Representation) Design Doc (BSC / geth fork)

**Scope**: This doc describes the MIR implementation and the rework done on branch `feat-MIR-rework` relative to `master`, including architecture, key components, correctness strategy, performance strategy, and the debugging workflow/tools used to resolve “bad blocks” and regressions.

**Status**: Strict MIR is used for **top-level contract execution** only; nested `CALL*/CREATE*` still execute via native geth EVM for correctness and to avoid recursion/complexity.

---

## Table of contents

- [MIR (Mid-level Intermediate Representation) Design Doc (BSC / geth fork)](#mir-mid-level-intermediate-representation-design-doc-bsc--geth-fork)
  - [Table of contents](#table-of-contents)
  - [1. Goals and non-goals](#1-goals-and-non-goals)
    - [Goals](#goals)
    - [Non-goals (current)](#non-goals-current)
  - [2. Glossary](#2-glossary)
  - [3. What is MIR and why do we want it?](#3-what-is-mir-and-why-do-we-want-it)
    - [3.1 Intuition](#31-intuition)
    - [3.2 How MIR “works” at runtime](#32-how-mir-works-at-runtime)
  - [4. High-level design](#4-high-level-design)
    - [4.1 Architecture diagram](#41-architecture-diagram)
    - [4.2 Key principles](#42-key-principles)
  - [5. MIR pipeline end-to-end](#5-mir-pipeline-end-to-end)
    - [5.1 Compilation (bytecode → CFG)](#51-compilation-bytecode--cfg)
    - [5.2 Execution (CFG → MIR interpreter)](#52-execution-cfg--mir-interpreter)
  - [6. Component deep dive (with file pointers)](#6-component-deep-dive-with-file-pointers)
    - [6.1 MIR IR types (`MIR`, `MirOperation`, values)](#61-mir-ir-types-mir-miroperation-values)
      - [6.1.1 `MirOperation` (opcode-sized MIR op enum)](#611-miroperation-opcode-sized-mir-op-enum)
      - [6.1.2 `Value` and the build-time stack machine](#612-value-and-the-build-time-stack-machine)
      - [6.1.3 Operand encoding for fast runtime `evalOperand`](#613-operand-encoding-for-fast-runtime-evaloperand)
    - [6.2 CFG builder (bytecode → basic blocks → MIR)](#62-cfg-builder-bytecode--basic-blocks--mir)
      - [6.2.1 What a `MIRBasicBlock` stores (compile-time + runtime)](#621-what-a-mirbasicblock-stores-compile-time--runtime)
      - [6.2.2 Why we record the per-block EVM opcode stream (`evmOps`)](#622-why-we-record-the-per-block-evm-opcode-stream-evmops)
      - [6.2.3 Constant folding (build-time only)](#623-constant-folding-build-time-only)
      - [6.2.4 Worked example: what CFG generation produces (and what `mir_visualizer` shows)](#624-worked-example-what-cfg-generation-produces-and-what-mir_visualizer-shows)
        - [(A) Pseudo EVM bytecode (PCs shown)](#a-pseudo-evm-bytecode-pcs-shown)
        - [(A.1) Actual bytecode (hex) you can paste into `mir_visualizer`](#a1-actual-bytecode-hex-you-can-paste-into-mir_visualizer)
        - [(B) Native EVM execution model (how it “works”)](#b-native-evm-execution-model-how-it-works)
        - [(C) MIR CFG generation output (basic blocks + edges)](#c-mir-cfg-generation-output-basic-blocks--edges)
        - [(D) Where PHIs appear (stack merge at the loop header)](#d-where-phis-appear-stack-merge-at-the-loop-header)
        - [(E) MIR execution model (how it differs from native)](#e-mir-execution-model-how-it-differs-from-native)
    - [6.3 PHI / stack-merge model](#63-phi--stack-merge-model)
      - [6.3.1 `phiStackIndex`: stable PHI addressing for EVM stack slots](#631-phistackindex-stable-phi-addressing-for-evm-stack-slots)
      - [6.3.2 Runtime PHI evaluation (`evalPhi`): how the chosen value is determined](#632-runtime-phi-evaluation-evalphi-how-the-chosen-value-is-determined)
    - [6.4 Dynamic CFG expansion/backfill](#64-dynamic-cfg-expansionbackfill)
      - [6.4.1 Example: “JUMP where destination is not a constant” (dispatcher/jump table)](#641-example-jump-where-destination-is-not-a-constant-dispatcherjump-table)
      - [6.4.2 Safety + correctness rules for dynamic backfill](#642-safety--correctness-rules-for-dynamic-backfill)
      - [6.4.3 Worked example (dynamic): partial CFG at compile time, expanded CFG at runtime](#643-worked-example-dynamic-partial-cfg-at-compile-time-expanded-cfg-at-runtime)
    - [6.5 MIR interpreter runtime](#65-mir-interpreter-runtime)
      - [6.5.1 Interpreter state layout (what’s “hot” vs “cold”)](#651-interpreter-state-layout-whats-hot-vs-cold)
    - [6.6 Gas parity model](#66-gas-parity-model)
      - [6.6.1 Constant gas “prefix/delta/tail” model (implementation notes)](#661-constant-gas-prefixdeltatail-model-implementation-notes)
      - [6.6.2 Dynamic gas (runtime-dependent) model (implementation notes)](#662-dynamic-gas-runtime-dependent-model-implementation-notes)
    - [6.7 Memory model](#67-memory-model)
    - [6.8 State backend + access list + refunds](#68-state-backend--access-list--refunds)
    - [6.9 LOG semantics](#69-log-semantics)
    - [6.10 Block/tx environment opcodes](#610-blocktx-environment-opcodes)
    - [6.11 EVM wiring + system contract policy](#611-evm-wiring--system-contract-policy)
  - [7. Debugging tools and workflow](#7-debugging-tools-and-workflow)
    - [7.1 `mir_block_replay` tool](#71-mir_block_replay-tool)
    - [7.2 `mir_visualizer` tool](#72-mir_visualizer-tool)
    - [7.3 How we solve “bad block” divergences](#73-how-we-solve-bad-block-divergences)
    - [7.4 How we solve performance regressions](#74-how-we-solve-performance-regressions)
  - [8. Benchmarks and performance notes](#8-benchmarks-and-performance-notes)
  - [9. Known limitations and future work](#9-known-limitations-and-future-work)
  - [10. Appendix: change inventory (branch vs master)](#10-appendix-change-inventory-branch-vs-master)
    - [10.1 Key new packages/tools](#101-key-new-packagestools)
    - [10.2 Core wiring changes](#102-core-wiring-changes)
    - [10.3 Test suite additions](#103-test-suite-additions)
    - [10.4 High-level file inventory (grouped)](#104-high-level-file-inventory-grouped)

---

## 1. Goals and non-goals

### Goals

- **Correctness vs native EVM** under block replay and fullnode sync:
  - Detect and fix divergences (“bad blocks”) by reproducing them deterministically.
  - Maintain strictness: avoid “papering over” MIR bugs by silently falling back.
- **Performance**: MIR should be competitive and ideally faster than native EVM on common contracts:
  - Focus on real-world calls (USDT/WBNB) and syncing workloads.
  - Remove avoidable allocations and reduce per-op overhead.
- **Tooling**: provide a fast feedback loop for:
  - pinpointing the first divergence (opcode/stack/log/state),
  - tracing dynamic jumps / PHIs,
  - profiling CPU/allocs.

### Non-goals (current)

- Replacing geth EVM for **nested calls** (`CALL`, `DELEGATECALL`, `STATICCALL`, `CALLCODE`, `CREATE`, `CREATE2`):
  - Nested calls remain in geth EVM; MIR is used only for **top-level** frames.
- Producing a global optimizing compiler (this MIR is primarily a structured IR + execution engine).

---

## 2. Glossary

- **EVM**: Ethereum Virtual Machine, the native interpreter in geth/BSC.
- **MIR**: Mid-level Intermediate Representation of EVM execution; structured basic blocks plus MIR ops.
- **CFG**: Control Flow Graph. Nodes are **basic blocks**, edges represent possible control transfers.
- **Basic block**: Straight-line instruction sequence with single entry and (conceptually) single exit.
- **PHI**: SSA-style merge node for values at a CFG join; used to model EVM stack merges.
- **Dynamic jump**: `JUMP`/`JUMPI` where destination is computed at runtime (common for dispatch/jump tables).
- **Back-edge / loop**: CFG edge `from → to` where `to.firstPC <= from.firstPC`.
- **“Bad block”**: during sync, a block where re-execution produces receipt/log/state divergence vs canonical.

---

## 3. What is MIR and why do we want it?

### 3.1 Intuition

Native EVM execution is:

1. a bytecode interpreter loop,
2. repeated stack shuffling (`PUSH/DUP/SWAP`) and per-op decoding,
3. heavy on branchy logic (opcode switch + gas rules),
4. difficult to optimize globally because control-flow is implicit.

MIR’s idea:

- Convert raw bytecode into a **structured CFG** of basic blocks.
- Within a basic block, represent “real work” as MIR ops with explicit operands and explicit results.
- Model stack flow between blocks with snapshots + PHIs, enabling:
  - deterministic analysis,
  - faster operand access (via `resIdx`),
  - better gas accounting,
  - better debugging (you can talk about blocks and edges, not just “pc”).

### 3.2 How MIR “works” at runtime

At a high level:

- When a top-level call is executed, MIR chooses the contract code (bytecode) and gets/creates a cached CFG.
- MIR executes starting at block PC=0:
  - runs MIR ops inside the current basic block,
  - follows CFG edges on fallthrough or jumps,
  - when it encounters a dynamic jump where target is not statically known, it resolves/creates the target block and records the discovered edge for later correctness.

---

## 4. High-level design

### 4.1 Architecture diagram

```
  vm.EVM (top-level CALL/CREATE)
            |
            | (if Config.EnableMIR && depth==0 && !system contract)
            v
       MIR EVMRunner
       - caches CFG per codeHash
       - pools MIRInterpreter instances
            |
            v
       MIRInterpreter.RunFrom(0)
       - executes MIRBasicBlocks
       - maintains results table, memory, gas, state backend
       - dynamic jump backfill -> updates CFG edges/snapshots
            |
            v
       ExecResult (ret, err, gasUsed/left)
            |
            v
    native state_transition receipt + StateDB finalization
```

### 4.2 Key principles

- **Top-level only**: MIR executes only when `evm.depth == 0`.
- **No system contracts**: MIR is disabled for BSC system contracts while validating sync.
- **CFG is cached** by code hash; interpreter instances are pooled for performance.
- **Correctness first**:
  - dynamic jump targets are validated against a precomputed JUMPDEST map,
  - PHI is used for stack merges; stack-height mismatches are treated as infeasible edges.

---

## 5. MIR pipeline end-to-end

### 5.1 Compilation (bytecode → CFG)

1. Scan bytecode once to compute a map of valid `JUMPDEST`s.
2. Create entry block at PC=0.
3. Worklist build:
   - build basic block `B` starting at `B.firstPC`
   - record `evmOps` (pc, op) stream for gas parity
   - translate EVM ops into MIR ops; push “Values” onto build-time stack
   - end block on terminators (JUMP/JUMPI/STOP/RETURN/REVERT/SELFDESTRUCT/INVALID) or boundaries (JUMPDEST) 
   - connect edges and record incoming stack snapshots
4. Iterate until all reachable blocks are built, or error if non-convergent.

### 5.2 Execution (CFG → MIR interpreter)

1. Initialize interpreter state for this run:
   - gas limit, memory, results generation, call data, state backend, callcreate backend
2. Start at `entryPC=0`, find block `cfg.pcToBlock[0]`.
3. For each block:
   - ensure block is built
   - run MIR ops sequentially
   - charge constant gas incrementally (prefix-delta model)
   - on terminator:
     - `JUMP/JUMPI`: resolve edge; dynamic jump backfill if necessary
     - `STOP/RETURN/REVERT/SELFDESTRUCT`: produce ExecResult

---

## 6. Component deep dive (with file pointers)

### 6.1 MIR IR types (`MIR`, `MirOperation`, values)

**Files**

- `core/opcodeCompiler/compiler/MIR/MIR.go`
- `core/opcodeCompiler/compiler/MIR/MIROperations.go`
- `core/opcodeCompiler/compiler/MIR/ValueStack.go`

**Highlights**

- MIR op nodes (`type MIR struct`) carry:
  - `op` (MirOperation)
  - operands (`[]*Value`)
  - mapping back to the original EVM op: `evmPC`, `evmOp`, plus `evmOpIndex` for gas charging
  - `resIdx` result slot id (global, dense)
  - optional operand-kind encodings to speed up runtime `evalOperand`

#### 6.1.1 `MirOperation` (opcode-sized MIR op enum)

MIR operations are defined in `MIROperations.go`. Some are 1:1 with EVM opcodes (e.g. `MirADD`), while others are MIR-only helpers for structure and analysis (e.g. `MirPHI`).

Design constraints:

- **Deterministic**: MIR op identity should be stable enough across rebuilds for debugging and fixpoint comparison.
- **Gas-aware**: a MIR op may correspond to a *range* of EVM ops, because MIR can optimize away PUSH/DUP/SWAP at runtime. This is why we also track `m.evmOpIndex` and the full per-block EVM opcode stream.

#### 6.1.2 `Value` and the build-time stack machine

During CFG construction we run a symbolic stack machine (`ValueStack`) to translate EVM ops into MIR ops.

Each `Value` is either:

- **`Konst`**: a constant literal (canonicalized so that different encodings of the same value compare equal)
- **`Variable`**: a value defined by a MIR op (`Value.def != nil`)
- **`Unknown` / live-in**: used during merges; later becomes a PHI or resolves to a runtime stack snapshot value

Important correctness detail:

- `Value.Equal` compares constants by numeric value (so `PUSH0` and `PUSH1 0x00` are equal). This prevents spurious PHIs and stabilizes CFG merges.

#### 6.1.3 Operand encoding for fast runtime `evalOperand`

To reduce interpreter overhead, we encode operand kinds on each MIR op during block construction:

- `opKinds[i]`: const vs def vs fallback
- `opConst[i]`: direct pointer to decoded constant (`*uint256.Int`)
- `opDefIdx[i]`: direct `resIdx` (dense index) for fast lookup in `it.results`

**Why `resIdx` matters**

- Without `resIdx`, reading a value produced by another MIR op requires pointer chasing and/or map lookup.
- With `resIdx`, interpreter uses an array `results[resIdx]` and a generation array `resultsGen[resIdx]` to avoid clearing.

---

### 6.2 CFG builder (bytecode → basic blocks → MIR)

**Files**

- `core/opcodeCompiler/compiler/MIR/opcodeParser.go`
- `core/opcodeCompiler/compiler/MIR/MIRBasicBlock.go`

**CFG data structure**: `type CFG struct` (`opcodeParser.go`)

- `basicBlocks`, `pcToBlock`
- `jumpDests` cache
- `defKeyToResIdx` mapping (rebuild-safe mapping for stale `*MIR` pointers)

**Non-convergence safety valve**

- `CFG.Parse()` has a bounded rebuild loop and returns `CFGNonConvergentError` if it doesn’t converge.

**Edge construction**

- `CFG.connectEdge(parent, child, exitSnapshot)`:
  - appends child/parent without clobbering existing edges (important for jump tables),
  - records `incomingStacks[parent] = exitSnapshot`,
  - invalidates entryStack and marks descendants for rebuild if snapshot changes.

#### 6.2.1 What a `MIRBasicBlock` stores (compile-time + runtime)

**File**: `core/opcodeCompiler/compiler/MIR/MIRBasicBlock.go`

`MIRBasicBlock` is both a compilation artifact and a runtime state machine. Key responsibilities:

- **CFG shape**: `parents` / `children` slices.
- **Opcode mapping for gas/debug**:
  - `evmOps`: the exact EVM opcode stream for the block as `(pc, op)` pairs.
  - `evmPCToOpIndex`: mapping from `evmPC -> index in evmOps` used to set `m.evmOpIndex` during MIR emission.
- **MIR execution**:
  - `instructions []*MIR`
  - `pos int` instruction cursor (must be reset every time the block is re-entered).
- **Stack flow**:
  - `incomingStacks[parent] = []Value` snapshots
  - `entryStack []Value`, `exitStack []Value`
- **Dynamic jumps**:
  - `unresolvedJump` marks that this block ends with a jump whose destination wasn't statically known.

#### 6.2.2 Why we record the per-block EVM opcode stream (`evmOps`)

MIR can “optimize away” some bytecode ops at runtime (notably `PUSH/DUP/SWAP`). But gas parity still requires charging their fixed cost.

So the builder records the original opcode stream per block and the interpreter charges constant gas based on EVM ops, not MIR ops.

#### 6.2.3 Constant folding (build-time only)

**File**: `core/opcodeCompiler/compiler/MIR/MIRBasicBlock.go`

We perform conservative constant folding during CFG build:

- Unary: `NOT`, `ISZERO`
- Binary: arithmetic/bitwise/compare/shift plus `SIGNEXT`, `BYTE`
- Ternary: `ADDMOD`, `MULMOD`

**Explicit exclusion**:

- `EXP` is **not** constant-folded because its gas depends on exponent size; folding would break gas parity.

---

#### 6.2.4 Worked example: what CFG generation produces (and what `mir_visualizer` shows)

This is a “not short, not long” bytecode-shaped example with:

- a **dispatcher** (`JUMPI`) and
- a **loop** (a back-edge `JUMP`).

It is *not* exact Solidity output, but it is structurally representative and is ideal for understanding CFG/PHI/back-edge behavior.

##### (A) Pseudo EVM bytecode (PCs shown)

```
; --- block @0: entry / selector dispatch ---
0:   PUSH1 0x00
2:   CALLDATALOAD              ; [selWord]
3:   PUSH1 0xE0
5:   SHR                       ; [selector]
6:   PUSH4 0x11111111
11:  EQ                        ; [cond]
12:  PUSH1 0x20                ; dest_then = 0x20
14:  JUMPI                     ; if cond jump to 0x20 else fallthrough

; NOTE: this sample uses JUMPDEST (0x5b) as padding, so the fallthrough
; lands on a 1-byte JUMPDEST at pc=0x0f.

; --- block @0x0f: else branch landing pad, init loop vars ---
15:  JUMPDEST
16:  PUSH1 0x00                ; sum=0
18:  PUSH1 0x00                ; i=0
20:  PUSH1 0x40                ; loop_head = 0x40
22:  JUMP

; --- block @32: then branch ---
32:  JUMPDEST
33:  PUSH1 0x2a                ; 42
35:  PUSH1 0x00
37:  MSTORE
38:  PUSH1 0x20
40:  PUSH1 0x00
42:  RETURN

; --- block @0x40: loop header (back-edge target) ---
64:  JUMPDEST                  ; stack: [sum, i]
65:  DUP1
66:  PUSH1 0x03
68:  GT                        ; 3>i (i<3)
69:  PUSH1 0x50                ; dest_body = 0x50
71:  JUMPI                     ; if i<3 jump to 0x50
72:  PUSH1 0x70                ; else: dest_exit = 0x70
74:  JUMP

; --- block @0x50: loop body ---
80:  JUMPDEST                  ; [sum, i]
81:  DUP2
82:  DUP2
83:  ADD                       ; sum = sum + i
84:  SWAP2
85:  POP
86:  PUSH1 0x01
88:  ADD                       ; i = i + 1
89:  PUSH1 0x40
91:  JUMP                      ; back-edge to loop head

; --- block @0x70: loop exit ---
112: JUMPDEST                  ; [sum, i]
113: POP                       ; drop i
114: PUSH1 0x00
116: MSTORE                    ; store sum
117: PUSH1 0x20
119: PUSH1 0x00
121: RETURN
```

##### (A.1) Actual bytecode (hex) you can paste into `mir_visualizer`

Saved in-repo as:

- `core/opcodeCompiler/compiler/MIR/test_contact/cfg_example_dispatch_loop.hex`

Hex (single line):

```
60003560e01c6311111111146020575b600060006040565b5b5b5b5b5b5b5b5b5b602a60005260206000f35b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b806003106050576070565b5b5b5b5b5b81810191506001016040565b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5060005260206000f3
```

Notes:

- This hand-assembled bytecode uses `JUMPDEST` (`0x5b`) as padding to align block start PCs cleanly.
- Key block entry PCs (hex):
  - `0x00`: dispatch
  - `0x0f`: else/init (fallthrough after the initial `JUMPI` lands on a 1-byte `JUMPDEST`)
  - `0x20`: then/return 42
  - `0x40`: loop header
  - `0x50`: loop body
  - `0x70`: loop exit/return sum

##### (B) Native EVM execution model (how it “works”)

Native EVM is essentially:

- a `pc` walking the bytecode,
- a stack + memory + gas counter,
- a big interpreter loop `switch(opcode)` that mutates stack/memory and changes `pc` on `JUMP/JUMPI/RETURN/...`.

In this snippet:

- The dispatcher at `pc=14 (JUMPI)` chooses between:
  - `pc=0x20` (then-return path), or
  - fallthrough to `pc=0x0f` (else-loop path; a 1-byte `JUMPDEST` padding).
- The loop is driven by explicit `JUMP` instructions:
  - init block does `JUMP 0x40`,
  - loop body ends with `JUMP 0x40` (back-edge),
  - loop header does `JUMPI 0x50` (body) and otherwise `JUMP 0x70` (exit).

Important: the native EVM does **not** build a CFG; it discovers control flow purely by executing and changing `pc`.

##### (C) MIR CFG generation output (basic blocks + edges)

During `CFG.Parse()` we build basic blocks starting at JUMPDESTs and fallthrough/jump targets.

This example yields blocks (by start PC):

- `B0 @0`   (dispatch)        → successors: `B_then @32`, `B_else @16`
- `B_else @0x0f` (init)       → successor:  `B_loop @0x40`
- `B_then @32` (return 42)    → terminates
- `B_loop @0x40` (loop header)→ successors: `B_body @0x50`, `B_exit @0x70`
- `B_body @0x50` (loop body)  → successor:  `B_loop @0x40` (back-edge)
- `B_exit @0x70` (return sum) → terminates

ASCII CFG (what you’d expect to see in `mir_visualizer`):

```
           +-------------------+
           |     B0 @0         |
           | dispatch (JUMPI)  |
           +----+---------+----+
                |         |
             cond=true  cond=false (fallthrough)
                |         |
        +-------v--+   +--v----------------+
        | B_then@32|   |   B_else @0x0f    |
        | RETURN42 |   | init sum=0,i=0    |
        +----------+   | JUMP -> 0x40      |
                       +---------+---------+
                                 |
                                 v
                         +-------+--------+
                         |  B_loop @0x40  |
                         | loop header    |
                         | if (i<3) ...   |
                         +---+--------+---+
                             |        |
                          i<3 |        | i>=3
                             |        |
                     +-------v--+   +--v--------+
                     |B_body@0x50|  |B_exit@0x70|
                     | sum+=i   |   | RETURNsum |
                     | i++      |   +-----------+
                     | JUMP0x40 |
                     +----+-----+
                          |
                          +------------- back-edge ------------+
```

##### (D) Where PHIs appear (stack merge at the loop header)

`B_loop @0x40` has two predecessors:

- first iteration: from `B_else @0x0f` (incoming stack `[sum0, i0]`)
- subsequent iterations: from `B_body @0x50` (incoming stack `[sum_next, i_next]`)

At the top of `B_loop`, MIR constructs an entry stack that represents these merges:

- `sum_in = PHI(sum0, sum_next)`
- `i_in   = PHI(i0,   i_next)`

These PHIs are indexed by `phiStackIndex`:

- for a 2-item stack `[sum_in, i_in]`, the top-of-stack is `i_in`, so:
  - `phiStackIndex(i_in) = 0`
  - `phiStackIndex(sum_in) = 1`

This is why correct per-edge incoming snapshots and stable PHI indexing are critical for loop correctness.

##### (E) MIR execution model (how it differs from native)

At runtime, MIR executes:

- block-by-block (not byte-by-byte),
- resolves branches by choosing CFG edges,
- evaluates PHIs based on the actual predecessor edge,
- and records edge snapshots for dynamic correctness (especially on back-edges and unresolved jumps).

For this example, the runtime “path” is:

- `B0` → either:
  - `B_then` (terminate), or
  - `B_else` → `B_loop` → (`B_body` → `B_loop`)* → `B_exit` (terminate).


### 6.3 PHI / stack-merge model

**Key idea**: EVM stack is implicit; MIR makes it explicit with `Value`s.

During CFG build:

- Each block has:
  - `entryStack []Value`
  - `incomingStacks map[parent][]Value` snapshots
  - `exitStack []Value`
- When building a block:
  - If `entryStack` is unknown, compute it from `incomingStacks`.
  - If multiple incomings differ at a stack slot, create a `MirPHI`.

Important correctness policy in `CFG.getEntryStackForBlock`:

- Incoming stacks must have the **same height** at merge points in real EVM.
- During dynamic CFG expansion, we may temporarily record infeasible edges with wrong height.
- Strategy: keep only the **mode** (most common) incoming height; ties break toward smaller height.

#### 6.3.1 `phiStackIndex`: stable PHI addressing for EVM stack slots

PHIs represent values at specific EVM stack slots. We store this as:

- `phiStackIndex = 0`: top-of-stack
- `phiStackIndex = 1`: second from top
- etc.

At runtime, given an incoming stack snapshot `in` for the chosen predecessor edge, the value is selected by:

```
idx := (len(in)-1) - phiStackIndex
```

This avoids ambiguous ordering based on “operand list ordering” and makes PHI resolution depend on the actual predecessor edge and snapshot shape.

---

#### 6.3.2 Runtime PHI evaluation (`evalPhi`): how the chosen value is determined

**Where it runs**: at runtime, when executing `MirPHI` in `MIRInterpreter.RunFrom`, the interpreter calls:

- `evalPhi(cur, prev, phi)` in `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go`

**Goal**: select the value for a specific EVM stack slot at a CFG join point, based on the **actual predecessor edge** taken (`prev → cur`).

**How `evalPhi` decides (high-level)**

1. **Require a predecessor**:
   - If `prev == nil`, we are at the true entry; PHI should not occur there, so return 0 (defensive).

2. **Primary source (best for correctness): per-edge incoming stack snapshot**
   - Prefer `cur.incomingStacks[prev]`, which is the stack snapshot recorded specifically for the edge we actually took.
   - Use `phi.phiStackIndex` to pick the correct slot from that snapshot:
     - `idx := (len(in) - 1) - phi.phiStackIndex`
   - If the slot exists and is not `Unknown`, return `evalValue(&in[idx])`.

   Why this is preferred:
   - It directly reflects the runtime stack at the join for that edge.
   - It avoids depending on any “operand list ordering” heuristics.

3. **Secondary source: PHI operand list (prebuilt at CFG build time)**
   - If the incoming snapshot is missing/incomplete or the slot is `Unknown/out-of-range`, fall back to `phi.operands`.
   - Choose the operand corresponding to the predecessor **identity** in `cur.parents` (the same ordering used when PHIs were created during CFG build).

   Why this fallback exists:
   - During dynamic CFG expansion/backfill, snapshots may be temporarily missing or inconsistent.
   - Selecting by predecessor identity is more stable than selecting by snapshot length in those transient states.

4. **Defensive fallback**
   - If nothing matches, return 0 (`u256Zero`) rather than panicking or returning garbage.

**Debugging tip**

- `MIRInterpreter` supports `SetDebugPhiHook(...)`. When enabled, `evalPhi` emits a trace including:
  - `curFirstPC`, `prevFirstPC`, `phiPC`, `phiStackIndex`,
  - the incoming snapshot length and selected index (when applicable),
  - the resolved 256-bit value.

This is the fastest way to confirm “which predecessor did we come from?” and “which stack slot did the PHI read?” while stepping through a bad-block divergence.

---

### 6.4 Dynamic CFG expansion/backfill

**Problem**: Jump tables / dispatchers compute destinations from calldata or memory. Build-time CFG cannot know which target blocks are reachable.

**Solution**:

- Builder marks block as `unresolvedJump` when it can’t statically resolve a `JUMP/JUMPI`.
- Interpreter resolves at runtime:
  - validates jumpdest using precomputed `validJumpDests`
  - creates/builds the target block if missing
  - records the edge and an incoming snapshot so PHIs can be correct

#### 6.4.1 Example: “JUMP where destination is not a constant” (dispatcher/jump table)

This is the canonical Solidity pattern:

1. Load a selector from calldata (runtime-dependent).
2. Compute an offset/label from that selector.
3. Jump to that label.

In EVM terms, the jump destination may come from a stack value computed by:

- `CALLDATALOAD`
- `SHR` / `AND`
- arithmetic (`MUL`, `ADD`) to index a jump table
- `MLOAD` in some variants

So MIR cannot statically know the destination just by scanning for `PUSHxx <dest>` immediately before `JUMP`.

#### 6.4.2 Safety + correctness rules for dynamic backfill

When resolving a dynamic target at runtime, MIR must:

- **Validate**: target PC must be a valid `JUMPDEST` in the original bytecode.
- **Update CFG**: add the edge and record an incoming stack snapshot for that edge.
- **Handle loops**: for back-edges/unresolved jumps, snapshots are often materialized to constants to avoid leaking symbolic defs across iterations.

**Key file**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go` (runtime `resolveBB`)

---

#### 6.4.3 Worked example (dynamic): partial CFG at compile time, expanded CFG at runtime

Saved in-repo as:

- `core/opcodeCompiler/compiler/MIR/test_contact/cfg_example_dynamic_jump_table.hex`

Bytecode idea:

- Entry computes a jump destination from calldata and jumps there:
  - \(dest = 0x20 + ((CALLDATALOAD(0) \& 1) * 0x10)\)
  - So the runtime target is either `0x20` or `0x30` depending on calldata bit 0.
- Both `0x20` and `0x30` are valid `JUMPDEST`s and return different constants (`0xAA` vs `0xBB`).

Pseudo EVM bytecode (PCs shown, corresponds 1:1 to `cfg_example_dynamic_jump_table.hex`):

```
; --- block @0x00: compute dynamic jump destination ---
0x00: PUSH1 0x00
0x02: CALLDATALOAD              ; pop offset=0, push w (32-byte word) => stack: [w]
0x03: PUSH1 0x01
0x05: AND                       ; stack: [w & 1] (keep bit0)
0x06: PUSH1 0x10
0x08: MUL                       ; stack: [(w & 1) * 0x10] => 0x00 or 0x10
0x09: PUSH1 0x20
0x0b: ADD                       ; stack: [0x20 + ((w & 1) * 0x10)] => 0x20 or 0x30
0x0c: JUMP                      ; dynamic: jump to 0x20 or 0x30 (both are JUMPDESTs)

; --- padding: a run of JUMPDESTs to make targets land on clean PCs ---
0x0d..0x1f: JUMPDEST ...         ; filler

; --- block @0x20: target0 (return 0xAA) ---
0x20: JUMPDEST
0x21: PUSH1 0xaa
0x23: PUSH1 0x00
0x25: MSTORE
0x26: PUSH1 0x20
0x28: PUSH1 0x00
0x2a: RETURN

; --- padding ---
0x2b..0x30: JUMPDEST ...

; --- block @0x30: target1 (return 0xBB) ---
0x30: JUMPDEST
0x31: PUSH1 0xbb
0x33: PUSH1 0x00
0x35: MSTORE
0x36: PUSH1 0x20
0x38: PUSH1 0x00
0x3a: RETURN
```

What happens:

- **Compile time (`CFG.Parse`)**:
  - Destination depends on `CALLDATALOAD`, so the builder cannot know it statically.
  - The block is marked `unresolvedJump` and has **no connected successors** after parse.
  - Result: **partial CFG** (only entry is reachable/known).
- **Runtime (MIRInterpreter)**:
  - On first execution, the interpreter evaluates the dest and calls `resolveBB`, which creates/builds the target block and connects the edge.
  - If you execute again with different calldata, it discovers the other target too.
  - Result: CFG becomes “more complete” over time.

How to see it concretely:

- Run `TestDynamicCFGExpansion_Example_TwoTargets` in `core/opcodeCompiler/compiler/MIR/dynamic_cfg_expand_example_test.go`.
  - It asserts: after `Parse`, `entry.Children()==0`; after two runs (calldata bit 0 = 0 then 1), `entry.Children()=={0x20,0x30}`.

### 6.5 MIR interpreter runtime

**File**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go`

**Core loop**

- `RunFrom(entryPC uint)`:
  - ensures blocks are built
  - executes MIR ops
  - handles control-flow, dynamic jumps
  - handles state snapshots for REVERT (when enabled)

#### 6.5.1 Interpreter state layout (what’s “hot” vs “cold”)

The interpreter is designed to minimize per-op allocations:

- **Hot path state**
  - `results []uint256.Int` and `resultsGen []uint32` indexed by `resIdx`
  - `mem []byte` linear memory
  - `gasLeft/gasUsed` and refund counter
  - per-block cached constant gas tables (prefix/delta/tail)
- **Cold path state**
  - CFG build/rebuild machinery
  - dynamic jump backfill (allocations here are OK but must be bounded)
- **Debug-only hooks**
  - `SetStepHook`, `SetResolveHook`
  - `SetDebugOperandHook`/`Ex`, `SetDebugPhiHook`, `SetDebugKeccakHook`, `SetDebugCallArgsHook`

In production/fullnode, hooks should remain nil.

**Important correctness fixes included on this branch**

- Reset per-block instruction cursor (`cur.pos = 0`) on each entry to avoid “execute block once” bugs in loops.
- PHI evaluation correctness fixes: use incoming snapshot (when present) and robust fallback rules.
- Edge snapshot computation hardened for loops/back-edges:
  - `computeExitSnapshotForEdgeTo` materializes snapshots for back-edges and unresolved jumps to avoid carrying “future defs”.

---

### 6.6 Gas parity model

**Goal**: match geth gas usage exactly (including subtle rules like CALL gas forwarding and SSTORE net metering).

**Key strategies**

1. **Constant gas**: precompute constant gas per opcode for the active fork rules (`vm.ConstantGasForOp`).
2. **Per-block opcode stream**: record `evmOps` in each block during CFG build.
3. **Incremental charging**:
   - Instead of “charge whole block upfront” (breaks CALL gas forwarding), charge *delta* constant gas aligned to emitted MIR ops.
   - Use `evmOpIndex` on MIR ops to charge in O(1) (slice math) rather than scanning.
4. **Dynamic gas**:
   - Implement dynamic gas logic for memory expansion, copy, logs, SLOAD/SSTORE, SELFDESTRUCT, etc.

**Files**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go`
- `core/opcodeCompiler/compiler/MIR/MIRBasicBlock.go` (evmOps recording)
- `core/vm/gas_export.go` (fork-aware gas helpers exported as needed)

#### 6.6.1 Constant gas “prefix/delta/tail” model (implementation notes)

At runtime, we need constant gas for:

- EVM ops that were optimized away in MIR (PUSH/DUP/SWAP),
- and any EVM ops that map to MIR ops 1:1.

We do this by:

- recording `block.evmOps` as `(pc, op)` at build time,
- computing `prefix[i]` = total const gas for `evmOps[:i]`,
- charging per MIR op using `m.evmOpIndex`:
  - `delta = prefix[m.evmOpIndex+1] - prefix[lastCharged]`
- charging `tail = prefix[len(evmOps)] - prefix[lastCharged]` once at block end.

This preserves CALL gas semantics because gas is charged at the right point in the stream, not “upfront”.

---

#### 6.6.2 Dynamic gas (runtime-dependent) model (implementation notes)

**Dynamic gas** is any gas component that depends on runtime values (stack operands, memory size, warm/cold access state, fork rules, etc.). In MIR, dynamic gas is computed **during execution**, inside the opcode semantics, and is charged via `it.chargeGas(...)`.

High-level pattern (mirrors geth):

1. **Charge constant gas** incrementally (prefix/delta model) for the originating EVM opcode stream.
2. **Evaluate operands** needed to decide the dynamic cost (e.g., memory offset/size, storage slot).
3. **Charge dynamic gas** via a dedicated helper (fork-aware, state-aware).
4. Perform the opcode’s state/memory effects.

**Key dynamic gas families**

- **Memory expansion (quadratic)**:
  - Charged whenever an opcode touches memory \([off, off+size)\).
  - Implemented by `chargeMemoryExpansion(off, size)` which tracks `it.memLastGasFee` and charges only the delta as memory grows (same formula as geth `vm.memoryGasCost`).
  - Used by: `MLOAD/MSTORE/MSTORE8`, `*COPY`, `RETURN/REVERT`, `KECCAK256`, `LOGn`, `CALL*` (via argument memory regions), etc.
  - Code: `MIRInterpreter.chargeMemoryExpansion`, plus callers like `chargeKeccakDynamicGas`, `chargeLogDynamicGas`, `chargeCopyGas`, `chargeMcopyDynamicGas`.

- **Storage access + net metering (SLOAD/SSTORE)**:
  - Fork-dependent (EIP-2200/2929/3529) and depends on access list warm/cold status and original/current/new slot values.
  - Charged via `chargeSLoadGas(slot)` and `chargeSStoreGas(slot, newVal)` and called from the `MirSLOAD` / `MirSSTORE` execution cases before performing the state update.
  - Code: `MIRInterpreter.chargeSLoadGas`, `chargeSStoreGas` (and helpers `chargeSStoreEIP2200`, `chargeSStoreEIP2929`).

- **LOGs**:
  - Dynamic cost depends on memory expansion, data byte length, and number of topics.
  - Charged via `chargeLogDynamicGas(m)` before copying topics/data and emitting the log.

- **KECCAK256**:
  - Dynamic cost depends on memory expansion and number of 32-byte words hashed.
  - Charged via `chargeKeccakDynamicGas(off, size)`.

- **EXP**:
  - Dynamic cost depends on the exponent byte-length (fork-dependent ExpByte cost).
  - Charged via `chargeExpDynamicGas(m)` inside the `MirEXP` execution case.

- **SELFDESTRUCT**:
  - Dynamic cost depends on warm/cold beneficiary access and (fork-dependent) account creation rules; refunds are fork-dependent.
  - Charged via `chargeSelfdestructDynamicGas(beneficiary)` before applying the state effect.

**Where to look in code**

- Dynamic gas helpers live in `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go` (functions named `charge*`).
- They are invoked from the main execution switch (`switch m.op`) immediately before the corresponding opcode semantics, so gas is charged at the same “time” as geth would charge it.

### 6.7 Memory model

**File**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go`

Highlights:

- `ensureMem(n)` aligns memory growth to 32-byte words.
- memory copy/zero paths optimized using `copy(...)` and zeroing loops (compat-friendly).

---

### 6.8 State backend + access list + refunds

**Files**

- `core/opcodeCompiler/compiler/MIR/state_backend.go` (minimal interface + InMemoryState for tests)
- `core/opcodeCompiler/compiler/MIR/statedb_backend.go` (adapter to geth `vm.StateDB`)

Highlights:

- Implements EIP-2929 warm/cold accounting for SLOAD/SSTORE via access list.
- Refund handling:
  - MIR interpreter can apply refund cap, but in fullnode wiring we disable internal cap because geth applies it at the tx layer.

---

### 6.9 LOG semantics

**Files**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go` (MirLOG0..MirLOG4)
- `core/opcodeCompiler/compiler/MIR/statedb_backend.go` (AddLog adapter)

Highlights:

- Topics + data copied from MIR memory slice.
- Removed any “duplicate log” guard because duplicate logs are legal EVM behavior.

---

### 6.10 Block/tx environment opcodes

**Files**

- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go` (MirNUMBER, MirTIMESTAMP, …, MirCODESIZE, etc.)
- `core/opcodeCompiler/compiler/MIR/evm_runner.go` (wires block/tx context from `vm.EVM`)

Highlights:

- Block context is cached in runner and installed into each interpreter run.
- Cancun-related opcodes (BLOBHASH/BLOBBASEFEE) included with guard checks.

---

### 6.11 EVM wiring + system contract policy

**Files**

- `core/vm/evm.go`
- `core/vm/interpreter.go`
- `core/vm/mir_runner.go`
- `core/opcodeCompiler/compiler/MIR/evm_runner.go`

Policy:

- MIR enabled if:
  - `vm.Config.EnableMIR == true`,
  - `evm.depth == 0`,
  - MIR runner set (`evm.SetMIRRunner(...)`),
  - and **not** a Parlia system contract address.

Instrumentation:

- Low overhead counters in `core/vm/evm.go` logged periodically (`MIR counters`).

---

## 7. Debugging tools and workflow

### 7.1 `mir_block_replay` tool

**File**

- `tools/mir_block_replay/main.go`

Purpose:

- replay historical blocks from a datadir and compare:
  - receipts (status/gasUsed/cumGas/log count),
  - state roots,
  - selected opcode streams.

Key features:

- `--from/--to` scan mode is O(N) (build state once and advance), not O(N²).
- `--faststate` bootstraps from parent state root to debug late blocks quickly.
- Debug hooks for:
  - JUMP/JUMPI operands,
  - SSTORE keys/values,
  - PHI resolution trace,
  - STATICCALL args, MLOAD/MSTORE windows (for allocator-related divergences).

Workflow:

1. Identify first mismatching tx (receipt or root).
2. Run `debugOneTx` output for that tx.
3. Inspect:
   - first opcode divergence window,
   - jump operands tail,
   - MIR operand provenance (`defPC/defOp`),
   - state changes/logs tail.

---

### 7.2 `mir_visualizer` tool

**Files**

- `tools/mir_visualizer/main.go`
- `tools/mir_visualizer/index.html`
- `core/opcodeCompiler/compiler/MIR/cfg_viz.go`

Purpose:

- visualize basic blocks, edges, stack-in/out, and unresolved jumps for a bytecode sample.

Used for:

- explaining why USDT creation code initially showed “unresolved jump” (fixed via constant folding).

---

### 7.3 How we solve “bad block” divergences

General recipe (repeatable):

1. **Reproduce**:
   - fullnode reports bad block `N`
   - run `mir_block_replay --block N --full --faststate`
2. **Minimize**:
   - find mismatching tx index
   - rerun just common txs vs full processing to isolate system tx/finalize vs EVM execution
3. **Localize**:
   - use debug hooks: jump operands, PHIs, SSTORE keys/values, memory windows
4. **Fix root cause**:
   - typically in:
     - CFG edge connection correctness (parents/children overwrite bugs),
     - PHI selection/entry stack computation,
     - dynamic jump backfill snapshot shape,
     - block re-entry cursor handling (`pos` reset),
     - missing op implementations (NUMBER/CODESIZE/etc),
     - gas accounting parity.
5. **Verify**:
   - rerun block replay
   - run parity tests and key benches
   - resume sync and wait for next bad block

---

### 7.4 How we solve performance regressions

General recipe:

1. **Benchmark** (USDT/WBNB suite):
   - watch ns/op and allocs/op
2. **Profile**:
   - `go test -cpuprofile ... -memprofile ...`
   - compare MIR vs EVM hotspots
3. **Fix high alloc/CPU hotspots**:
   - typical offenders:
     - edge snapshot computation/materialization (alloc-heavy),
     - operand evaluation slow path,
     - constant gas charging table rebuilds,
     - memory expansion and copying loops.
4. **Guard correctness**:
   - keep correctness rules on loops/back-edges and unresolved jumps
   - avoid “disable MIR / fallback” workarounds

---

## 8. Benchmarks and performance notes

Reality check:

- MIR is not automatically faster than EVM for tiny calls if MIR adds overhead (e.g., snapshotting).
- MIR wins when:
  - it avoids repeated decoding/dispatch overhead,
  - it amortizes CFG build over many calls,
  - it reduces allocations (especially in memory/gas paths).

This branch includes multiple targeted optimizations:

- pooled interpreter instances (`sync.Pool`)
- cached CFG per codeHash
- O(1) constant gas charging per MIR op using `evmOpIndex` + delta tables
- memory growth reuse (append zero bytes when capacity allows)
- avoid recomputing edge snapshots on steady-state forward edges (but still do it for unsafe edges)

---

## 9. Known limitations and future work

- Nested call execution is still geth EVM.
- More opcode coverage and thorough fork-edge testing will be needed for mainnet-level confidence.
- Further perf work:
  - reduce allocations in edge snapshots/materialization,
  - tighten operand encoding to eliminate slow `evalOperand` cases,
  - more aggressive constant folding where gas parity permits (avoid EXP).

---

## 10. Appendix: change inventory (branch vs master)

### 10.1 Key new packages/tools

- `core/opcodeCompiler/compiler/MIR/*` (CFG, MIR ops, interpreter, backends, tests)
- `tools/mir_block_replay/*` (block replay + diff)
- `tools/mir_visualizer/*` (CFG visualization)

### 10.2 Core wiring changes

- `core/vm/evm.go`:
  - top-level MIR dispatch
  - system contract exclusion list (Parlia)
  - MIR counters logging
- `core/vm/interpreter.go`:
  - `EnableMIR` config
- `core/state_processor.go`:
  - enable MIR runner when cfg.EnableMIR

### 10.3 Test suite additions

- parity tests + real-world contract benches under `core/opcodeCompiler/compiler/MIR/evm_parity_test/*`
- dynamic jump backfill tests
- CFG fixpoint / PHI tests

### 10.4 High-level file inventory (grouped)

**MIR engine (core)**

- `core/opcodeCompiler/compiler/MIR/MIR.go`
- `core/opcodeCompiler/compiler/MIR/MIROperations.go`
- `core/opcodeCompiler/compiler/MIR/MIRBasicBlock.go`
- `core/opcodeCompiler/compiler/MIR/MIRInterpreter.go`
- `core/opcodeCompiler/compiler/MIR/ValueStack.go`
- `core/opcodeCompiler/compiler/MIR/opcodeParser.go`
- `core/opcodeCompiler/compiler/MIR/cfg_viz.go`

**Backends**

- `core/opcodeCompiler/compiler/MIR/state_backend.go`
- `core/opcodeCompiler/compiler/MIR/statedb_backend.go`
- `core/opcodeCompiler/compiler/MIR/evm_callcreate_backend.go`
- `core/opcodeCompiler/compiler/MIR/call_create_backend.go`

**EVM wiring**

- `core/vm/mir_runner.go`
- `core/vm/evm.go`
- `core/vm/interpreter.go`
- `core/state_processor.go`
- `eth/ethconfig/config.go`, `eth/ethconfig/gen_config.go` (config plumbing)

**Tools**

- `tools/mir_block_replay/main.go`
- `tools/mir_visualizer/main.go`, `tools/mir_visualizer/index.html`

**Tests/benches**

- `core/opcodeCompiler/compiler/MIR/evm_parity_test/*`
- `core/opcodeCompiler/compiler/MIR/*_test.go`


