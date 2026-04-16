# MIR v2 实施计划

## 背景

v1 的 `ResetForRebuild` 会清空整个 block 的 instructions 然后从 bytecode 重新 parse。这是因为非 PHI 指令的 operands 通过 `stack.pop()` 获得，直接持有 PHI def 的指针。entry stack 一变，所有 operand 都失效。

核心矛盾：**instructions 的 operand 绑定了 entry stack 的具体 PHI 实例（含 resIdx），但 PHI 在 rebuild 时会被替换。**

## 阶段 1：PHI-only rebuild（operand 重映射）

### 1.1 设计思路

不再在 rebuild 时清空 instructions 重建，而是：

1. **只重建 PHI 部分**：更新/增加/删除 PHI 节点
2. **重映射非 PHI 指令的 operand**：把旧 PHI resIdx → 新 PHI resIdx

关键：引入一个 `phiResMap map[int]int`（旧 resIdx → 新 resIdx），rebuild 后遍历 non-PHI instructions 的 operands 做替换。

### 1.2 具体步骤

#### Step 1: 保存旧 PHI 信息

在 rebuild 前，收集当前 block 的所有 PHI 的 `{phiStackIndex → resIdx}` 映射：

```go
oldPhiMap := map[int]int{} // phiStackIndex → old resIdx
for _, m := range block.instructions {
    if m.op == MirPHI {
        oldPhiMap[m.phiStackIndex] = m.resIdx
    }
}
```

#### Step 2: 只重建 PHI 列表

- 删除 instructions 数组的 PHI 前缀
- 调用 `getEntryStackForBlock` 生成新 PHI 列表
- 把新 PHI 列表插回 instructions 数组前面

```go
// 分离 PHI 和 non-PHI
nonPhiInstr := block.instructions[phiCount:]
// 重建 PHI
newStack := c.getEntryStackForBlock(block)
// newStack 的 PHIs 已经通过 CreatePhiMIR 添加到 block.instructions
// 此时 block.instructions 只有新 PHI
// 拼接: newPHIs + 旧的 nonPhiInstr
block.instructions = append(block.instructions, nonPhiInstr...)
```

#### Step 3: 建立 PHI resIdx 映射

```go
phiResMap := map[int]int{} // old resIdx → new resIdx
for _, m := range block.instructions {
    if m.op == MirPHI {
        if oldIdx, ok := oldPhiMap[m.phiStackIndex]; ok {
            if oldIdx != m.resIdx {
                phiResMap[oldIdx] = m.resIdx
            }
        }
    }
}
```

#### Step 4: 重映射 non-PHI operands

```go
if len(phiResMap) > 0 {
    for _, m := range block.instructions {
        if m.op == MirPHI {
            continue
        }
        for _, op := range m.operands {
            if op != nil && op.kind == Variable && op.def != nil {
                if newIdx, ok := phiResMap[op.def.resIdx]; ok {
                    op.def.resIdx = newIdx
                }
            }
        }
        // 也要更新 pre-encoded fast-path 缓存
        for i, defIdx := range m.opDefIdx {
            if newIdx, ok := phiResMap[defIdx]; ok {
                m.opDefIdx[i] = newIdx
            }
        }
    }
}
```

#### Step 5: 更新 exit stack

exit stack 中引用 PHI def 的 Value 也需要重映射。同样遍历 exit stack 的每个 Value，替换旧 resIdx。

### 1.3 什么时候用 PHI-only rebuild vs full rebuild

- **PHI-only**：entry stack 高度不变，只是 PHI operands 列表变化（新增 parent 的 operand）
- **Full rebuild**：entry stack 高度变化（需要重新 pop/push 生成 operands）

判断标准：

```go
oldHeight := len(block.EntryStack())
// 计算新 incoming snapshots 的一致高度
newHeight := computeExpectedHeight(block)
if newHeight == oldHeight {
    phiOnlyRebuild(block)
} else {
    fullRebuild(block)
}
```

### 1.4 收益

- **消除大部分 invalidateBlockResults 调用**：非 PHI resIdx 不变，result table 不需要清除
- **Loop-carried 值保留**：不需要 save/restore workaround
- **defKeyToResIdx 映射更稳定**：大部分 def 的 resIdx 不变
- **减少 resolve fallback**：operands 直接指向正确的 PHI def

## 阶段 2：引入 RuntimeValue 替代 Unknown

### 2.1 新的 Value Kind

```go
const (
    Konst     ValueKind = iota
    Variable
    Arguments
    Unknown
    RuntimeVal  // 新增：运行时才确定的值
)

// RuntimeVal 携带的信息：
type Value struct {
    kind        ValueKind
    // ... 现有字段 ...
    // RuntimeVal 专用：
    rtSourceBlock  uint  // 来源 block 的 firstPC
    rtStackPos     int   // 在来源 block exit stack 中的位置 (depth from top)
}
```

### 2.2 Parse 时创建 RuntimeValue

在 `getEntryStackForBlock` 中，当 incoming snapshot 缺失或高度不匹配时：

```go
// 现在：填 Unknown
vv := Value{kind: Unknown, liveIn: true, liveInPos: i}

// 改为：填 RuntimeVal（如果能确定来源）
vv := Value{
    kind:          RuntimeVal,
    liveIn:        true,
    liveInPos:     i,
    rtSourceBlock:  parentBlock.firstPC,
    rtStackPos:    distFromTop,
}
```

### 2.3 运行时解析

`evalValue` 遇到 RuntimeVal 时：

```go
case RuntimeVal:
    return it.resolveRuntimeValue(v.rtSourceBlock, v.rtStackPos)
```

`resolveRuntimeValue` 直接查执行历史中对应 block 的 exit stack：

```go
func (it *MIRInterpreter) resolveRuntimeValue(sourceFirstPC uint, stackPos int) (*uint256.Int, error) {
    sourceBlock := it.cfg.pcToBlock[sourceFirstPC]
    if sourceBlock == nil {
        return nil, fmt.Errorf(...)
    }
    exitSnap := it.computeExitSnapshotForEdge(nil, sourceBlock)
    if exitSnap == nil {
        return nil, fmt.Errorf(...)
    }
    idx := (len(exitSnap) - 1) - stackPos
    if idx < 0 || idx >= len(exitSnap) {
        return nil, fmt.Errorf(...)
    }
    return it.evalValue(&exitSnap[idx])
}
```

### 2.4 收益

- **消除所有 Unknown live-in → 0 的 bug**
- **消除 resolveViaHistory 的遍历开销**（O(N) → O(1)）
- **PHI operand 可以是 RuntimeVal**：不需要 snapshot 就能工作
- **ErrMIRInternal fallback 频率大幅降低**

## 阶段 3：多遍 Parse

### 3.1 Pass 1: CFG 骨架

只扫描 bytecode 确定 block 边界和 edges：
- 扫描 JUMPDEST、JUMP、JUMPI、STOP、RETURN、REVERT
- 常量 JUMP 目标直接 connectEdge
- 非常量 JUMP 标记 `unresolvedJump`
- 运行 Tarjan SCC

**不做栈模拟。** 时间复杂度 O(bytecode length)。

### 3.2 Pass 2: 抽象栈分析

Fixpoint iteration，只追踪：
- 每个 block 的 entry/exit 栈高度
- 每个位置的 value identity（PHI vs live-in vs produced）
- 在合并点创建 PHI 节点

此 pass 完成后：
- 每个 block 的 entry stack 高度和 PHI 集合**固定不变**
- 无法确定的值标记为 RuntimeVal

### 3.3 Pass 3: MIR 指令生成

在稳定的 entry stack 上一次性生成所有 MIR instructions：
- stack.pop() 返回的 Value 指向 Pass 2 确定的 PHI def
- 常量折叠、peephole 优化
- 分配 resIdx（一次分配，永不变化）

**此后 instructions 永不 rebuild。**

### 3.4 运行时

- 新 edge 发现 → 只更新 PHI operand（阶段 1 的机制）
- RuntimeVal 解析（阶段 2 的机制）
- 不需要 ResetForRebuild、不需要 invalidateBlockResults

### 3.5 收益

- **Parse 时间可能更长**（3 遍 vs 1 遍），但**执行时间大幅缩短**
- **代码简洁度提升**：不需要 rebuild workaround、save/restore、history traversal
- **可维护性**：每个 pass 职责清晰，互不干扰
