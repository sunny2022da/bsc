# MIR CFG 设计文档

## 目录

1. [整体架构](#1-整体架构)
2. [核心数据结构](#2-核心数据结构)
3. [CFG 静态构建（Parse 阶段）](#3-cfg-静态构建parse-阶段)
4. [PHI 节点与入口栈合并](#4-phi-节点与入口栈合并)
5. [JUMP 处理：静态 vs 动态](#5-jump-处理静态-vs-动态)
6. [反向边与循环处理](#6-反向边与循环处理)
7. [运行时执行流程](#7-运行时执行流程)
8. [两类关键 CFG 模式的正确性分析](#8-两类关键-cfg-模式的正确性分析)
9. [静态分析收敛保证](#9-静态分析收敛保证)
10. [已修复的问题清单](#10-已修复的问题清单)

---

## 1. 整体架构

MIR（Medium-level Intermediate Representation）是一个将 EVM 字节码翻译为**寄存器形式 CFG**（控制流图）的编译器层。其目标是：

- 把 EVM 基于栈的指令序列提升为基本块（BasicBlock）+ PHI 节点的 SSA 风格 IR
- 在静态构建阶段尽可能解析 JUMP 目标，建立确定的边
- 对无法静态解析的 JUMP（动态目标），在运行时按需回填 CFG 边
- 缓存 CFG 供同一合约的后续调用复用，通过 epoch 标记区分不同执行上下文

```
EVM 字节码
    │
    ▼
CFG.Parse()          ← 静态构建：遍历字节码、建 BasicBlock、连边、插 PHI
    │
    ▼
CFG（已缓存）
    │
    ▼
MIRInterpreter.Run() ← 运行时执行：按 CFG 拓扑执行、遇到动态 JUMP 时回填
```

---

## 2. 核心数据结构

### 2.1 CFG

```go
type CFG struct {
    rawCode                []byte
    basicBlocks            []*MIRBasicBlock
    pcToBlock              map[uint]*MIRBasicBlock   // PC → 块
    jumpDests              map[uint]bool             // 合法 JUMPDEST 集合
    nextResIdx             int                       // 全局 resIdx 分配器
    defKeyToResIdx         map[mirDefKey]int         // 稳定 def 标识 → resIdx
    runtimeEpoch           uint64                    // 每次顶层执行自增
    runtimeBecameDynamic   bool                      // 运行时发现新边时置 true
    hasUnresolvedJumpsFlag bool                      // 有无法静态解析的 JUMP
    needsRuntimeEpochFlag  bool                      // 合并点栈高不一致时需要 epoch
}
```

### 2.2 MIRBasicBlock

| 字段 | 说明 |
|------|------|
| `firstPC` / `lastPC` | 块在字节码中的 PC 范围 |
| `parents` / `children` | CFG 边（有序切片，PHI 对齐依赖此顺序） |
| `incomingStacks` | `map[parent] → []Value`，每条入边的出口快照 |
| `incomingStacksGen` | 每条入边快照对应的 runtimeEpoch |
| `entryStack` | 合并后的块入口符号栈（nil 表示需要重建） |
| `exitStack` | 块出口符号栈 |
| `jumpTable` | `map[targetPC] → *MIRBasicBlock`，O(1) 跳转派发 |
| `unresolvedJump` | 块末尾 JUMP 目标无法静态确定 |
| `built` | 是否已完成构建 |
| `fixedEntryHeight` | Parse 阶段确定的入口栈高度（-1 表示未知） |
| `preferredEntryHeight` | 运行时重建时希望使用的栈高度（-1 表示无偏好）|
| `blockNum` | 全局唯一块编号，用于 `mirDefKey` |

### 2.3 Value（符号栈元素）

```
kind = Konst    → 编译期常数（payload 为大端字节）
kind = Variable → 指向某条 MIR 指令的结果（def 指针 + resIdx）
kind = Unknown  → 未知值（PHI 缺少某分支时的占位）
```

`liveIn = true` 表示该值是从入口栈（PHI 或透传）继承的，`liveInPos` 是在 entryStack 中的位置。

### 2.4 MIR 指令

```go
type MIR struct {
    op            MirOperation  // 操作码（MirADD、MirJUMP、MirPHI …）
    operands      []*Value      // 输入操作数
    resIdx        int           // 全局结果槽（0 = 未分配）
    defBlockNum   uint          // 所在块编号（用于 mirDefKey）
    evmPC         uint          // 来源 EVM PC
    phiStackIndex int           // PHI 专用：代表栈的第几个槽
}
```

**`mirDefKey`** = `(defBlockNum, evmPC, op, phiStackIndex)`：跨重建稳定标识，通过 `defKeyToResIdx` 映射保证同一逻辑 def 始终复用相同 `resIdx`，使 `equalValueForFlow` 能正确判断收敛。

---

## 3. CFG 静态构建（Parse 阶段）

### 3.1 主流程

```
Parse()
 ├─ 计算合法 JUMPDEST 集合
 ├─ 创建 pc=0 的入口块，入队
 └─ 工作表循环（worklist）
     ├─ 取出块 B
     ├─ 若 B.built=true，跳过
     ├─ ResetForRebuild（清空旧 MIR，entryStack=nil）
     ├─ buildBasicBlock(B)
     │    ├─ 计算 entryStack（从 incomingStacks 合并，插 PHI）
     │    ├─ 逐条翻译 EVM 指令 → MIR
     │    └─ 遇到 JUMP/JUMPI → connectEdge(B, child, exitSnapshot)
     └─ 子块入队
 ├─ 检测是否需要 needsRuntimeEpochFlag
 └─ preWarmJumpTables()（为 unresolvedJump 块预建 jumpTable 条目）
```

**安全上限**：`maxBuilds = 1024 + 64 × len(code)`，超出返回 `CFGNonConvergentError`。

### 3.2 connectEdge

```
connectEdge(parent, child, exitSnapshot):
  1. 若 child.incomingStacks[parent] == exitSnapshot（stacksEqual）→ 提前返回，不触发重建
  2. child.incomingStacks[parent] = exitSnapshot
  3. child.entryStack = nil，child.built = false
  4. Parse 阶段（runtimeEpoch==0）：markDescendantsForRebuild(child)
                                   （向下传播失效，保证所有依赖块被重建）
```

`stacksEqual` 使用 `equalValueForFlow` 按稳定 resIdx 比较，而非指针——这是收敛性的关键。

---

## 4. PHI 节点与入口栈合并

### 4.1 合并算法（buildBasicBlock 内）

```
valid = 按 parents 顺序收集 incomingStacks（deterministic）
height = mode(len(valid[i]))    ← 取最高频的栈高度
for i in 0..height-1:
    values = [valid[j][i] for j in 0..len(valid)-1]
    if all equal（equalValueForFlow）:
        entryStack[i] = liveIn copy of values[0]
    else:
        entryStack[i] = new MirPHI(operands=[values[0], values[1], ...])
```

PHI 操作数顺序 **严格对齐 `block.parents` 下标**，这是 `evalPhi` 在运行时通过 `prev` 在 `parents` 中的位置选取操作数的前提。

### 4.2 PHI 求值（运行时）

```go
func (it *MIRInterpreter) evalPhi(cur *MIRBasicBlock, phi *MIR) Value {
    for i, p := range cur.parents {
        if p == it.prev { // 找到当前来源块的下标 i
            return eval(phi.operands[i])
        }
    }
    // 兜底：用 Unknown
}
```

### 4.3 跨重建的稳定性

重建时 `defKeyToResIdx` 保证：
- 同一逻辑 PHI（相同 `defBlockNum + evmPC + phiStackIndex`）复用同一 `resIdx`
- 旧快照中残留的 `Variable{def: 旧*MIR, resIdx: old}` 通过 `resIdx` 查 `defKeyToResIdx` 重映射到最新 resIdx

---

## 5. JUMP 处理：静态 vs 动态

### 5.1 静态 JUMP（目标为编译期常数）

```
PUSH1 0x10; JUMP
→ 构建时直接 connectEdge(cur, block@0x10, exitSnap)
→ block@0x10 加入 cur.jumpTable[0x10]
→ unresolvedJump = false
```

运行时命中 `jumpTable[targetPC]`，O(1) 派发。

### 5.2 动态 JUMP（目标为 PHI 或运行时值）

**静态阶段的 PHI 追踪（`traceJumpDestCandidates`）**：

```
JUMP 的目标来自栈顶 → 若栈顶是 MirPHI：
    遍历 PHI 每个操作数：
        Konst(pc) → 创建 block@pc，connectEdge，clear unresolvedJump
        Variable  → 递归追踪到其 def block 的入口快照中对应位置
    迭代顺序：for _, p := range block.parents（确定性，而非 map iteration）
```

**运行时回填（`resolveBB`）**：

```
运行时发现新目标 targetPC：
    1. 若 jumpTable[targetPC] 已有 → 直接返回
    2. getOrCreateBlock(targetPC)
    3. connectEdge(from, nb, snap)
    4. cfg.runtimeBecameDynamic = true
    5. 正向边（nb.firstPC > from.firstPC）→ materializeSnapshotTopK(snap, 64)
```

### 5.3 jumpTable O(1) 派发

```go
// JUMPI 的 fallthrough 查找
if ch, ok := cur.jumpTable[ftPC]; ok && ch != nil {
    ft = ch   // O(1)
} else {
    // 线性扫描兜底
    for _, ch := range cur.Children() { ... }
}
```

> **注意**：当 `traceJumpDestCandidates` 解析出 N 个目标时，块有 N+1 个 children（N 个 JUMP 目标 + 1 个 fallthrough）。旧代码的 `len(children)==2` 快速路径此时失效，必须用 jumpTable 查找。

---

## 6. 反向边与循环处理

### 6.1 反向边定义

`to.firstPC <= from.firstPC` 即为反向边（循环跳转）。

### 6.2 物化（materialization）与反向边守卫

**问题**：在动态 CFG 场景（`runtimeBecameDynamic=true`）中，对循环反向边的出口快照调用 `materializeSnapshotTopK` 会将当前迭代的循环计数器值烤成常数（`Konst`），导致下一次迭代 PHI 操作数陈旧，引发错误的 JUMP 目标。

**三处守卫**（缺一不可）：

| 调用位置 | 守卫条件 | 含义 |
|---------|---------|------|
| `resolveBB`（运行时回填）| `nb.firstPC > from.firstPC` | 只对正向边物化 |
| 块入口刷新（`MIRInterpreter` 块入口处）| `isBackEdge := cur.firstPC <= prev.firstPC; if isBackEdge { fresh = ex }` | 反向边不物化 |
| `refreshEdgeIfNeeded` | `to.firstPC > from.firstPC` | 只对正向边物化 |

### 6.3 `computeExitSnapshotForEdgeTo` 的静态反向边处理

对于**静态循环**（`runtimeBecameDynamic=false`、无 `unresolvedJump`），该函数调用 `materializeSnapshotProducedOnly`：

- **只**将"块内产生的值（非 liveIn）"固化为常数
- liveIn 值保持符号化，PHI 仍可随迭代更新
- 目的：防止 "future def" 问题（当前迭代在 block C 产生的 `Variable` 指针会变成下一轮 entry-stack 里的悬空 def）

对于**动态 CFG**，直接 `return snap`（不物化），避免路径相关值被跨路径共享。

---

## 7. 运行时执行流程

```
MIRInterpreter.Run():
  cur = entry block
  loop:
    if cur.built == false 或 entryStack 陈旧:
        重建 cur（buildBasicBlock）
    if 需要刷新入边快照（refreshEdgeIfNeeded）:
        更新 cur.incomingStacks[prev]，重建 cur
    执行 cur.instructions 逐条 MIR：
        结果写入 results[resIdx]
    根据末尾指令决定下一块：
        MirJUMP  → 查 jumpTable[target] 或 resolveBB
        MirJUMPI → 查 jumpTable[target/fallthrough]
        MirSTOP / MirRETURN → 退出
    prev = cur; cur = next
```

### 7.1 runtimeEpoch

每次顶层调用递增 `cfg.runtimeEpoch`，用于：
- 过滤 `incomingStacks` 中来自上一次调用的陈旧快照
- 区分"当前运行"和"缓存构建时"的入口栈，避免不同 calldata 互相干扰

### 7.2 needsRuntimeEpoch

```go
func (c *CFG) needsRuntimeEpoch() bool {
    return c.needsRuntimeEpochFlag || c.runtimeBecameDynamic || c.hasUnresolvedJumpsFlag
}
```

只有需要时才启用 epoch 过滤，避免静态合约的无谓开销。

---

## 8. 两类关键 CFG 模式的正确性分析

### 8.1 N→1→M（跳转表）模式

```
Caller A ──┐
Caller B ──┤→ Dispatcher D ──→ Target X
Caller C ──┘               └──→ Target Y
                           └──→ Target Z
```

**关键点**：

1. **PHI 对齐**：D 的 `parents` 顺序决定 PHI 操作数下标；`parents` 在 `connectEdge` 时按首次遇到顺序追加，并保持稳定。
2. **resIdx 跨重建稳定**：D 因新 parent 加入而重建时，旧快照通过 `defKeyToResIdx` 重映射，PHI 操作数不会失效。
3. **jumpTable O(1) 派发**：D 的多目标通过 `traceJumpDestCandidates` 静态解析后均写入 D.jumpTable，运行时派发无需线性扫描。
4. **JUMPI fallthrough**：当 D 有 N+1 个 children 时，fallthrough 通过 `jumpTable[ftPC]` 直接获取（Fix 1）。
5. **traceJumpDestCandidates 确定性**：live-in 追踪按 `block.parents` 顺序而非 map 迭代顺序进行（Fix 2）。

### 8.2 A→B→C→B→...→A→B→D（外层上下文循环）模式

```
A ──→ B ──→ C
      ↑     │  (C→B 反向边，循环)
      └─────┘
      │
      └──→ D  (循环退出)
```

**关键点**：

1. **反向边物化守卫（Fix 3、Fix 5）**：C→B 的出口快照在三处物化入口均有 `firstPC` 守卫，不会把循环计数器烤成陈旧常数。
2. **PHI 收敛**：B 的入口 PHI 在第一次循环迭代后稳定（A 给常数、C 给 PHI-based 值），后续迭代 `stacksEqual` 返回 true，不再触发重建。
3. **外层 A 再次进入 B**：A 再次执行时，B 的 `incomingStacks[A]` 被更新（若 calldata 不同），B 重建，C 随之重建；但 C→B 反向边快照不物化，新迭代的计数器值正确传播。
4. **静态阶段**：`materializeSnapshotProducedOnly` 仅固化块内产生值，保护 liveIn 符号不被污染。

---

## 9. 静态分析收敛保证

**为什么 Parse 阶段栈不会无限量增长？**

| 约束 | 原因 |
|------|------|
| `incomingStacks` 条目数有界 | key = `*MIRBasicBlock`，最多 `len(parents)` 个，`connectEdge` 是覆写而非 append |
| 每条快照的高度有界 | EVM 每条指令 arity 固定，循环头的栈高由字节码结构决定，上限 1024 |
| 内容收敛 | `connectEdge` 用 `stacksEqual`（`equalValueForFlow`）检测 fixpoint；PHI 通过 `defKeyToResIdx` 稳定 resIdx 保证跨重建等价 |
| 硬性上限 | `maxBuilds = 1024 + 64 × len(code)`，超出返回 `CFGNonConvergentError` |

**典型收敛轮次（A→B→C→B）**：

```
Round 1: B 从 A 建立 → 连边到 C
Round 2: C 从 B 建立 → C 出口快照 → connectEdge(C,B) → B 入队
Round 3: B 从 A+C 重建 → 产生 PHI → B 出口变化 → C 入队
Round 4: C 从新 B 重建 → C 出口新快照 → connectEdge(C,B) →
         stacksEqual(旧快照, 新快照) = true → B 不再入队 ✓ 收敛
```

---

## 10. 已修复的问题清单

### Fix 1：JUMPI fallthrough 的 O(1) 查找

**文件**：`MIRInterpreter.go`

**问题**：旧代码用 `len(children)==2` 判断是否走快速路径，当 `traceJumpDestCandidates` 解析出 N 个 JUMP 目标时 children 有 N+1 个，快速路径被完全跳过，退化为 O(N) 扫描，且在某些边情况下可能取到错误的 fallthrough 块。

**修复**：优先用 `cur.jumpTable[ftPC]` 做 O(1) 查找，fallback 才线性扫描：

```go
if cur != nil {
    if ch, ok := cur.jumpTable[ftPC]; ok && ch != nil {
        ft = ch
    }
}
if ft == nil {
    for _, ch := range cur.Children() {
        if ch != nil && ch.firstPC == ftPC { ft = ch; break }
    }
    ...
}
```

---

### Fix 2：`traceJumpDestCandidates` 的确定性迭代

**文件**：`opcodeParser.go`

**问题**：live-in 追踪的两处循环用 `for _, snap := range block.incomingStacks`（map 迭代，Go 不保证顺序），导致 PHI 操作数顺序非确定，每次 Parse 可能产生不同的 CFG，与 `parents` 顺序不一致。

**修复**：改为按 `block.parents` 顺序迭代：

```go
for _, p := range block.parents {
    snap, ok := block.incomingStacks[p]
    if !ok { continue }
    if v.liveInPos < len(snap) {
        sv := snap[v.liveInPos]
        walk(&sv, depth+1)
    }
}
```

---

### Fix 3：块入口刷新的反向边物化守卫

**文件**：`MIRInterpreter.go`（块入口处的 entryStack 刷新路径）

**问题**：当 `runtimeBecameDynamic=true` 时，对所有入边一律调用 `materializeSnapshotTopK`，包括循环反向边（C→B）。这会将当前迭代的循环变量值烤成常数，下一次迭代 PHI 从 C 获取到过期的 Konst，导致跳转目标错误。

**修复**：加 `isBackEdge` 守卫：

```go
isBackEdge := cur.firstPC <= prev.firstPC
if isBackEdge {
    fresh = ex  // 反向边：不物化，保持符号值
} else {
    k := 64
    if len(ex) < k { k = len(ex) }
    fresh = it.materializeSnapshotTopK(ex, k)
}
```

---

### Fix 4（已有，确认正确）：`resolveBB` 的反向边守卫

**文件**：`MIRInterpreter.go`（`resolveBB` 函数）

存量代码已有 `if nb.firstPC > from.firstPC` 守卫，正确。无需修改。

---

### Fix 5：`refreshEdgeIfNeeded` 的反向边物化守卫

**文件**：`MIRInterpreter.go`（`refreshEdgeIfNeeded` 函数）

**问题**：`runtimeBecameDynamic=true` 时，`refreshEdgeIfNeeded` 对所有边（包括 C→B 反向边）调用 `materializeSnapshotTopK`，与 Fix 3 存在相同的陈旧 Konst 问题，且这是一条独立的代码路径（Fix 3 不覆盖）。

**修复**：加 `to.firstPC > from.firstPC` 守卫：

```go
if it.cfg.runtimeEpoch != 0 && it.cfg.runtimeBecameDynamic {
    snap = it.computeExitSnapshotForEdgeTo(prev, from, to)
    // 反向边不物化：循环携带值每次迭代变化，烤成常数会导致 PHI 陈旧
    if to.firstPC > from.firstPC {
        snap = it.materializeSnapshotTopK(snap, 16)
    }
    ...
}
```

---

## 附：关键函数速查

| 函数 | 文件 | 职责 |
|------|------|------|
| `CFG.Parse()` | opcodeParser.go | 静态 CFG 构建主入口，worklist 驱动 |
| `buildBasicBlock()` | opcodeParser.go | 构建单个块：计算 entryStack、翻译 EVM→MIR |
| `connectEdge()` | opcodeParser.go | 连接 parent→child 边，更新 incomingStacks 和 jumpTable |
| `markDescendantsForRebuild()` | opcodeParser.go | 广度优先标记下游块为 built=false |
| `traceJumpDestCandidates()` | opcodeParser.go | 静态追踪动态 JUMP 的 PHI 操作数，解析 N→M 跳转表 |
| `preWarmJumpTables()` | opcodeParser.go | Parse 后为 unresolvedJump 块预建 jumpTable |
| `MIRInterpreter.Run()` | MIRInterpreter.go | 运行时执行主循环 |
| `refreshEdgeIfNeeded()` | MIRInterpreter.go | 动态 CFG 下刷新入边快照 |
| `resolveBB()` | MIRInterpreter.go | 运行时发现新 JUMP 目标，回填 CFG 边 |
| `computeExitSnapshotForEdgeTo()` | MIRInterpreter.go | 计算 parent→child 出口快照，含反向边处理 |
| `materializeSnapshotTopK()` | MIRInterpreter.go | 将符号栈顶 K 个值固化为运行时常数 |
| `materializeSnapshotProducedOnly()` | MIRInterpreter.go | 仅固化块内产生值（非 liveIn），用于静态反向边 |
| `evalPhi()` | MIRInterpreter.go | 运行时按 prev 在 parents 中的下标选取 PHI 操作数 |
| `equalValueForFlow()` | opcodeParser.go | 按稳定 resIdx/payload 比较两个 Value，用于 fixpoint 检测 |
| `stacksEqual()` | opcodeParser.go | 比较两个快照切片是否相等 |
