# MIR Parse 静态分析的局限性

本文档总结了 MIR 编译器在 Parse 阶段（CFG 构建 + fixpoint 迭代）无法静态确定值的所有情况，以及运行时的处理策略。

## 一、根本不可能静态确定的值

### 1. 运行时计算的 JUMP 目标

- **场景**：JUMP/JUMPI 的目标是 `CALLDATALOAD`、`ADD`、`SLOAD` 等运行时才能确定的值
- **典型例子**：Solidity internal function pointer — 从 calldata 读取的函数选择器经过计算后跳转
- **代码标记**：`block.unresolvedJump = true`（opcodeParser.go）
- **运行时处理**：`resolveBB` 动态发现目标，`connectEdge` 回填 CFG，`jumpTable` 缓存后续 O(1) dispatch
- **相关函数**：`traceJumpDestCandidates`（尝试沿 def-chain 追踪所有可能的跳转目标）

### 2. 路径相关的栈值

- **场景**：同一个 JUMPDEST 被多个不同路径到达，每条路径压入的返回地址不同
- **典型例子**：内部函数 `f()` 被 `a()` 和 `b()` 调用，返回地址分别是 `0x100` 和 `0x200`
- **结果**：PHI 节点有多个 operand，有些可能在 Parse 时还没有 incoming snapshot
- **运行时处理**：runtime epoch tagging + incoming snapshot refresh

## 二、Parse 迭代可收敛但暂时缺失的值

### 3. PHI 的 Unknown operand（snapshot 缺失）

- **场景**：block 有多个父节点，但 Parse fixpoint 迭代还没处理到某个父节点
- **代码来源**：`getEntryStackForBlock` 中，当父节点的 snapshot 不存在或高度不匹配时填充 `Value{kind: Unknown, liveIn: true}`
- **正常情况**：下一轮 fixpoint 迭代会补上，Unknown 被替换为实际值
- **异常情况**：如果循环导致不收敛，或运行时才发现的边，Unknown 会保留到运行时

### 4. 栈高度不够（padBottomTo）

- **场景**：SWAP15 需要 16 个栈元素，但 entry stack 只有 4 个
- **代码来源**：`ValueStack.padBottomTo()` 用 Unknown 填充底部
- **运行时处理**：触发 `errNeedEntryHeight` → 用更大高度 rebuild → 通常可收敛
- **相关机制**：`preferredEntryHeight`、`fixedEntryHeight`

## 三、运行时新发现导致的缺失

### 5. 新 back-edge 导致的 PHI 不完整

- **场景**：Parse 时循环只有 1 个入口，运行时发现了第 2 个入口（新的 back-edge）
- **结果**：PHI 只有 1 个有效 operand，第 2 个是 Unknown
- **运行时处理**：`connectEdge(newParent=true)` → invalidate entry stack → rebuild PHI 添加新 operand
- **关键保护**：只对已存在的 back-edge 跳过 invalidation，新发现的 back-edge 必须触发 rebuild

### 6. 运行时栈高度变化

- **场景**：同一个 block 在不同 calldata/路径下被到达，栈高度不同
- **结果**：Parse 时的 entry stack 高度不匹配运行时实际情况
- **运行时处理**：`preferredEntryHeight` 机制 + rebuild；`needsRuntimeEpoch` 标记需要运行时 epoch tagging 的 CFG

## 四、def-chain 追踪失败

### 7. traceJumpDestCandidates 遇到不透明节点

- **场景**：追踪 JUMP 的 def-chain 时，遇到 `CALLDATALOAD`、`SLOAD`、`CALL` 等副作用指令
- **结果**：`allResolved = false` → `unresolvedJump = true`
- **限制**：追踪深度上限（`maxJumpTraceDepth`），超过就放弃
- **能追踪的情况**：
  - `Konst`：常量，直接解析
  - `MirPHI`：递归追踪所有 operand，全部是常量才成功
  - `Variable(liveIn)`：查找 `incomingStacks[parent]` 对应位置的值

### 8. runtimeEpoch 过滤丢弃所有 snapshot

- **场景**：cached CFG 跨不同执行复用时，epoch 过滤认为所有 incoming snapshot 都是 stale
- **结果**：rebuild 出空的 entry stack → PHI 全是 Unknown
- **保护机制**：fallback 逻辑（`getEntryStackForBlock` 第 482-497 行）重新包含被过滤的 snapshot

## 五、总结表

| 类别 | 能否在 Parse 收敛 | 能否在运行时修复 | 当前处理方式 |
|------|:---:|:---:|------|
| 动态 JUMP 目标 | 否 | 是 | `resolveBB` runtime backfill |
| PHI snapshot 缺失 | 通常能 | 能 | fixpoint 迭代 + runtime rebuild |
| 栈高度不足 | 能 (retry) | 能 | `errNeedEntryHeight` + rebuild |
| 新 back-edge | 否 | 能 | `connectEdge` invalidate + rebuild |
| def-chain 不透明 | 否 | 部分 | `unresolvedJump` + `jumpTable` preWarm |
| epoch 过滤过严 | N/A | 有 fallback | re-include stale snapshots |
| PHI operand = Unknown | 否 | **能（新）** | exit stack 物化 + history 回溯 |
| PHI def resIdx stale | 否 | **能（新）** | 扫描 block instructions 找 actual resIdx |
| 循环中途 rebuild 清除结果 | N/A | **能（新）** | 按 def key 保存/恢复 loop-carried 值 |

## 六、设计原则与恢复策略

**核心原则**：Parse 时分析不出来的值 **大多不代表值不存在**——只是 MIR 静态分析没建立完整的 def-use 链。运行时 EVM 栈是确定的，值真实存在，只需要以正确的方式找到它。

### 6.1 值解析的 5 层 fallback 链（evalPhi）

evalPhi 按以下顺序尝试解析一个 PHI 值，任何一层成功即返回：

1. **Operand 直接路径**：按当前前驱索引选择 `phi.operands[opIdx]` → `evalValue`
2. **Incoming snapshot 路径**：用 `cur.incomingStacks[prev]` 按 `phiStackIndex` 定位
3. **Snapshot Unknown 替换**：若 snapshot 位置是 Unknown，用 prev 的 runtime exit stack 替换该位置
4. **Prev exit 物化**：从 prev 的实际 exit stack 按 `phiStackIndex` 取值
5. **History 回溯**：沿 block 执行历史向前遍历，映射 live-in 位置直到找到 concrete def

### 6.2 History 回溯机制（af9a419fd）

interpreter 维护一个 ring buffer（cap 256）记录本帧执行过的每个 block。当 PHI 的值在静态路径上都是 Unknown 时：

```text
在 history 里找到 prev 的位置
→ 从那里向前遍历:
   如果 exit[pos] 标记 liveIn:
     沿 liveInPos 映射到 entry 位置
     继续看前一个 block 的 exit 对应位置
   如果是 Konst 或已执行的 Variable def:
     从 result table 取值返回
```

这相当于手动执行"EVM 栈值在历次 block 间怎么传递"的链路追踪。绝大多数之前会 fallback 的情况（内部函数 dispatcher 模式、复杂调用模式）现在都能在 MIR 内部解决。

### 6.3 Error 传播与 fallback（f07845f0d）

上述 5 层都失败时，才返回 `ErrMIRInternal` 包装的错误。`EVMRunner.Run()` 检测到后：

1. `RevertToSnapshot` 回滚 MIR 执行前的 StateDB 快照
2. 恢复 refund counter 到执行前状态
3. 用 stock EVM 重新执行当前 frame，返回权威结果

这保证了：

- **安全性**：从不因静态分析不足而猜测值（绝不返回 u256Zero 作为兜底）
- **正确性**：fallback 会完整回滚 MIR 的 state 变更，和纯 EVM 执行结果一致
- **性能**：只在 5 层恢复都失败时才 fallback，大部分合约不受影响

真正的 EVM 语义错误（`ErrExecutionReverted`、`ErrOutOfGas`、`ErrWriteProtection` 等）不触发 fallback，正常传播。

### 6.4 循环中途 rebuild 的结果保护（82ad4bcbb）

当 runtime 发现新 back-edge 时，loop header 需要 rebuild 来扩展 PHI operands。但简单的 `invalidateBlockResults` 会清除本轮迭代已计算的 def 结果，导致下一轮迭代的 PHI 无法找到 loop-carried 值。

修复：rebuild 前按 `(evmPC, op, phiStackIndex)` key 保存所有非 PHI 结果，rebuild 后按同一 key 找到新 instructions 对应的 resIdx，恢复值。PHI 结果本身不受 invalidate 影响。

## 七、2026-04-15 改动总结

今日六个 commit 的主题是：**让 MIR 在静态分析不完整时通过运行时恢复机制继续执行，而不是 fallback 或静默返回错误值**。

| Commit | 修复内容 |
| --- | --- |
| `0a40f7f97` | 三处静默返回 `u256Zero` 改为返回 error（PHI all-paths-exhausted、PHI def missing、Unknown live-in） |
| `01ca7a982` | evalPhi 加入 prev 运行时 exit stack 物化：snapshot 中 Unknown 时从 prev 实际 exit 取值；PHI def missing 时扫描新 instructions 找 actualResIdx |
| `82ad4bcbb` | 循环中途 rebuild 时按 def key 保存/恢复 loop-carried 结果 |
| `f07845f0d` | 引入 `ErrMIRInternal` sentinel；runner 检测到后 revert StateDB + refund，用 stock EVM 重跑 frame |
| `af9a419fd` | 新增 block 执行历史 ring buffer + `resolveViaHistory`：沿 live-in 链向前遍历找到运行时真实值 |

**效果**：之前会直接 fallback 到 stock EVM 的 CFG 静态分析不完整场景（尤其是多层 dispatcher / 内部函数跳转），现在大部分能在 MIR 内部解析出正确值继续执行。只有极端情况才触发 fallback，且 fallback 保证状态一致性。
