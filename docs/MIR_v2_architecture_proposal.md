# MIR v2 架构提案

基于 v1 追块暴露的问题，提出以下架构改进。

## 核心问题

MIR v1 的 Parse 是单遍 worklist + fixpoint：一边建 CFG 一边生成 MIR instructions。这导致：

1. **Rebuild 代价大**：新 edge 被发现后，整个 block 的 instructions 全部丢弃重建（因为 entry stack 变了，所有 operand 的 def 引用都失效）
2. **Loop 和 dataflow 耦合**：循环检测依赖 CFG 结构，但 CFG 结构在 Parse 中动态变化
3. **Unknown 是死胡同**：Parse 时不知道的值标记为 Unknown，到运行时只能猜或报错
4. **Result table 被 rebuild 破坏**：rebuild 清除 instructions → 清除 resIdx → loop-carried 值丢失

## 提案：多遍 Parse + 稳定 instructions + RuntimeValue 节点

### Pass 1: CFG 骨架 + 循环分析

只扫描 bytecode 确定：
- Basic block 边界（JUMPDEST、JUMP、JUMPI、STOP、RETURN、REVERT）
- 静态 edges（常量 JUMP/JUMPI 目标）
- 动态 edges 标记（非常量 JUMP 目标 → `unresolvedJump`）
- **Tarjan SCC 循环检测**（此时 CFG 结构已完整）

**不生成 MIR instructions，不做栈模拟。**

### Pass 2: 栈分析 + PHI 构建

在稳定的 CFG 上做 fixpoint iteration：
- 对每个 block 做**抽象栈模拟**（只追踪栈高度和 value identity，不生成 MIR）
- 在合并点创建 PHI 节点
- 确定每个 block 的 entry/exit 栈高度和 value 映射

对于**无法静态确定**的值：
- 创建 `RuntimeValue` 节点（新的 Value kind）
- 记录：`{sourceBlock, stackPosition}` — "这个值在运行时来自 block X 的栈位置 Y"

**Entry stack 在此 pass 完成后不再改变。**

### Pass 3: MIR 指令生成

在稳定的 entry stack 上，对每个 block 生成 MIR instructions：
- 从 entry stack pop/push 构建 def-use 图
- 常量折叠、peephole 优化
- 分配 resIdx

**Instructions 一次生成，永不 rebuild。** PHI 和 RuntimeValue 已经在 entry stack 中了。

### 运行时执行

执行 MIR 指令时：
- 遇到 PHI：和现在一样，按 predecessor 索引选 operand
- 遇到 RuntimeValue：查询执行历史
  ```go
  case RuntimeValue:
    return it.resolveRuntimeValue(v.sourceBlock, v.stackPosition)
  ```
  这就是现在 `resolveViaHistory` 的逻辑，但不需要遍历 block 链——直接记录。

### 运行时新 edge（dynamic JUMP）

当 `resolveBB` 发现新 edge 时：
- **不 rebuild block instructions**
- 只更新合并点的 PHI operand 列表（添加新 parent 的 operand）
- 如果新 parent 的 incoming snapshot 和现有的高度一致，PHI 直接加一个 operand
- 如果高度不一致，标记为 RuntimeValue fallback

## 和 v1 的关键区别

| | v1 (现在) | v2 (提案) |
|---|---|---|
| Parse 遍数 | 1 遍 (worklist fixpoint) | 3 遍 (CFG → 栈分析 → 指令生成) |
| Rebuild 影响范围 | 整个 block 的 instructions | 只有 PHI operands |
| Unknown 处理 | 猜 0 或报错 | RuntimeValue 节点，运行时查询 |
| Loop 检测时机 | Parse 后 / Parse 中(增量) | Pass 1 完成后（CFG 稳定） |
| Instructions 稳定性 | 随 rebuild 丢弃重建 | 一次生成，永不变 |
| resIdx 稳定性 | rebuild 后 resIdx 变化 | 固定，不因 PHI 变化而改变 |
| 运行时新 edge | invalidate + rebuild + save/restore | 只加 PHI operand |

## 增量迁移路径

从 v1 到 v2 不需要一步到位。可以分阶段：

### 阶段 1: 分离 PHI rebuild 和 instruction rebuild（最大收益）

改造 `ResetForRebuild`：只清除 PHI instructions，保留非 PHI instructions。新 edge 来了只更新 PHI 列表。这消除了大部分 rebuild cascade 和 resIdx 不稳定问题。

**前提**：entry stack 的非 PHI 部分不变（同一个 block 对 non-PHI 指令的 pop/push 序列是 bytecode 确定的）。

### 阶段 2: 引入 RuntimeValue 节点

在 `getEntryStackForBlock` 中，当 incoming snapshot 缺失或高度不匹配时，不填 Unknown，而填 `RuntimeValue{sourceBlock, stackPos}`。evalValue 遇到 RuntimeValue 时直接查执行历史。

### 阶段 3: 多遍 Parse

将 CFG 构建和指令生成分离为独立的 pass。这是最大的重构，但之后 MIR 的 correctness 和 maintainability 都会大幅提升。
