# BSC EVM MIR 优化设计文档

**版本**：基于 `feat-MIR-rework` 分支（迁移至 v1.7.x）
**日期**：2026-03

---

## 目录

1. [背景与动机](#1-背景与动机)
2. [设计目标](#2-设计目标)
3. [整体架构](#3-整体架构)
4. [核心数据结构](#4-核心数据结构)
5. [编译流程：EVM bytecode → CFG](#5-编译流程evm-bytecode--cfg)
6. [运行流程：MIR 解释执行](#6-运行流程mir-解释执行)
7. [PHI 与栈合并模型](#7-phi-与栈合并模型)
8. [动态 CFG 扩展](#8-动态-cfg-扩展)
9. [Gas 计算模型](#9-gas-计算模型)
10. [State 后端与状态管理](#10-state-后端与状态管理)
11. [性能优化策略](#11-性能优化策略)
12. [与 geth EVM 的集成](#12-与-geth-evm-的集成)
13. [调试工具](#13-调试工具)
14. [已知限制与未来规划](#14-已知限制与未来规划)
15. [文件索引](#15-文件索引)

---

## 1. 背景与动机

### 原生 EVM 的问题

BSC 原生 EVM（geth EVMInterpreter）是一个字节码解释器循环，存在以下固有性能瓶颈：

1. **重复 dispatch 开销**：每个 opcode 都需要经过 `table[op]` 查表、栈合法性检查、gas 扣减等固定开销
2. **大量栈 shuffle**：`PUSH/DUP/SWAP` 占据合约执行的相当比例，但本身不做有效计算
3. **控制流隐式**：`JUMP/JUMPI` 的跳转目标在编译期未知，难以做全局分析
4. **分配压力**：`Stack`、`Memory` 对象虽有 pool，但每次 call 仍有不可避免的分配

### MIR 的思路

MIR（Mid-level Intermediate Representation）是一种**寄存器架构的中间表示**，在 EVM bytecode 解释之上加一层结构化 IR：

- 把 bytecode 编译成 **CFG（控制流图）**，节点为基本块，边为控制转移
- 在基本块内，把 EVM 的栈操作"提升"为带显式操作数的 **MIR 指令**，消除运行时 stack shuffle
- 用 **SSA 风格的 PHI 节点**表示控制流汇合处的值合并
- 通过 **全局 `resIdx` 寄存器表**（`results[]uint256.Int`）实现 O(1) 操作数访问

---

## 2. 设计目标

### 目标

| 目标 | 说明 |
|------|------|
| **正确性** | 与原生 EVM 在 gas、state、log、return data 上完全等价 |
| **性能** | 在 USDT/WBNB 等高频合约上超越原生 EVM |
| **渐进落地** | 仅替换顶层调用（`depth==0`），nested calls 保持原生 EVM |
| **可调试** | 提供完整的 block replay 和 CFG 可视化工具 |

### 非目标（当前阶段）

- 不替换 nested calls（CALL/DELEGATECALL/STATICCALL/CREATE/CREATE2）
- 不做全局优化编译器（无死代码消除、无循环展开等）
- 不支持 EOF 格式

---

## 3. 整体架构

```
┌─────────────────────────────────────────────────────┐
│                  vm.EVM.Call()                       │
│                                                     │
│   shouldUseMIR() ?                                  │
│   ├─ true  → EVMRunner.Run()  ──────────────────┐   │
│   └─ false → EVMInterpreter.Run() (原生 EVM)     │   │
└─────────────────────────────────────────────────────┘
                                                   │
                        ┌──────────────────────────┘
                        ▼
          ┌─────────────────────────┐
          │       EVMRunner         │
          │  ┌───────────────────┐  │
          │  │  Global CFG Cache │  │  ← 按 codeHash 缓存，LRU 4096 条
          │  └───────────────────┘  │
          │  ┌───────────────────┐  │
          │  │  MIRInterpreter   │  │  ← Pool 复用
          │  │  (pooled)         │  │
          │  └───────────────────┘  │
          │                         │
          │  性能门控 fallback:       │
          │  ├─ code > 2048 bytes   │→ optEVMInterpreter (super-instr)
          │  └─ hasUnresolvedJumps  │→ baseEVMInterpreter
          └─────────────────────────┘
                        │
                        ▼
          ┌─────────────────────────┐
          │     MIRInterpreter      │
          │                         │
          │  results[]uint256.Int   │  ← 寄存器表（resIdx 寻址）
          │  mem []byte             │  ← 线性内存
          │  CFG (basic blocks)     │  ← 控制流图
          │  StateBackend           │  ← 状态读写
          │  CallCreateBackend      │  ← nested call 回调 geth
          └─────────────────────────┘
```

### 调度策略（evm.go）

```go
func (evm *EVM) shouldUseMIR() bool {
    return evm.Config.EnableMIR &&
           evm.mirRunner != nil &&
           evm.depth == 0          // 仅顶层
}
```

System contracts（Parlia 合约 `0x1000`~`0x3000`）永远不走 MIR。

---

## 4. 核心数据结构

### 4.1 MIR 指令（`MIR.go`）

```go
type MIR struct {
    op          MirOperation   // 操作码（对应 EVM opcode）
    operands    []*Value       // 编译期输入值
    resIdx      int            // 全局寄存器槽位（运行时 results[resIdx]）
    evmPC       uint           // 来源 EVM 字节偏移
    evmOp       byte           // 来源 EVM opcode
    evmOpIndex  int            // 在 block.evmOps 中的位置（用于 gas 计费）
    phiStackIndex int          // PHI 节点代表的栈槽位
    // 预编码操作数（避免运行时 evalOperand 慢路径）
    opKinds  []byte            // 0=常量, 1=寄存器引用, 2=fallback
    opConst  []*uint256.Int    // 常量值
    opDefIdx []int             // 寄存器索引
}
```

**关键设计**：`resIdx` 是全局单调递增的整数，使得每条产生值的 MIR 指令对应 `results[resIdx]` 中的一个固定槽位，无需 hash 查找。

### 4.2 MIRBasicBlock（`MIRBasicBlock.go`）

```go
type MIRBasicBlock struct {
    firstPC  uint              // 块起始 EVM PC
    // 编译期信息
    instructions []*MIR        // 该块的 MIR 指令序列
    parents, children []*MIRBasicBlock  // CFG 边
    evmOps   []evmOpInfo       // 原始 EVM opcode 流（用于 gas 对等）
    incomingStacks map[*MIRBasicBlock][]*Value  // 各前驱的栈快照
    entryStack, exitStack []*Value              // 块入/出口栈
    unresolvedJump bool        // 是否含动态 jump（目标运行时才知道）
    // 运行时信息
    pos int                    // 指令游标（每次进入块时重置为 0）
}
```

**DUP/SWAP 的处理**：这两类 opcode 在编译期直接操作 `ValueStack`，**不生成运行时 MIR 指令**，彻底消除了运行时的栈 shuffle。

### 4.3 MIRInterpreter（`MIRInterpreter.go`）

热路径字段（缓存在对象上，跨 call 复用）：

```go
type MIRInterpreter struct {
    // 寄存器表（核心）
    results    []uint256.Int   // 所有 MIR def 的结果
    resultsGen []uint32        // 世代标记（避免 per-run 清零）
    gen        uint32

    // Gas 计费缓存
    constGas      [256]uint64  // 各 opcode 常量 gas（按 chain rules 缓存）
    blockConstPrefix [][]uint64 // 每个块的 gas 前缀和
    blockConstDelta  [][]uint64 // 每个块每条 MIR 的 gas delta

    // 内存
    mem []byte                 // 可增长，复用 capacity

    // 调用上下文（每次 call 重置）
    gasLimit, gasUsed uint64
    contractAddr, callerAddr, originAddr common.Address
    callValue  *uint256.Int
    txGasPrice *big.Int
    callData, returnData []byte

    // 块/Tx 上下文
    blockNumber, blockTime, blockGasLimit uint64
    blockCoinbase    common.Address
    blockBaseFee, blockBlobBaseFee *big.Int

    // 后端
    state     StateBackend
    vmStateDB vm.StateDB      // fast-path，避免接口 dispatch
    callCreate CallCreateBackend
}
```

### 4.4 EVMRunner（`evm_runner.go`）

```go
type EVMRunner struct {
    evm           *vm.EVM
    it            *MIRInterpreter   // 复用的解释器实例
    baseIt, optIt *vm.EVMInterpreter // fallback 解释器
    stateBackend  StateDBBackend
    callBackend   EVMCallCreateBackend
    // 热路径缓存
    lastAddr, lastCodeHash common.Hash
    lastEntry  *cfgCacheEntry
    localCFGCache map[common.Hash]*cfgCacheEntry  // 动态 CFG 本地缓存
}
```

---

## 5. 编译流程：EVM bytecode → CFG

编译发生在 **第一次调用时**，结果缓存在全局 LRU（4096 条，可通过 `MIR_CFG_CACHE_SIZE` 环境变量调整）。

### 5.1 流程

```
EVM bytecode
    │
    ▼ CFG.Parse()          （opcodeParser.go）
┌──────────────────────────────────────┐
│ 1. 扫描所有 JUMPDEST，建立合法跳转目标集合    │
│ 2. 从 PC=0 开始，工作队列式构建基本块         │
│    - 遇到 JUMP/JUMPI/STOP/RETURN/     │
│      REVERT/SELFDESTRUCT → 块终止      │
│    - 遇到 JUMPDEST → 新块开始           │
│ 3. 每个 opcode 翻译为 MIR 指令            │
│    - PUSH: 生成常量 Value → 编译期折叠    │
│    - DUP/SWAP: 直接操作 ValueStack，    │
│               不生成运行时指令            │
│    - 算术/逻辑: 生成二元/一元 MIR op      │
│    - JUMP/JUMPI: 若目标是常量则静态连边;   │
│                 否则标记 unresolvedJump │
│ 4. 构建 CFG 边，记录各前驱的入口栈快照       │
│ 5. 插入 PHI 节点（控制流汇合处的值合并）     │
└──────────────────────────────────────┘
    │
    ▼
   CFG（基本块 + 边 + PHI）
```

### 5.2 常量折叠

编译期已知值（如 `PUSH1 0x05` 后跟 `JUMP`）会被折叠为常量，直接在 CFG 中生成静态边，无需运行时 dispatch。

---

## 6. 运行流程：MIR 解释执行

### 6.1 EVMRunner.Run() 入口逻辑

```
EVMRunner.Run(contract, input)
    │
    ├─ code > 2048 bytes? → optEVMInterpreter.Run()  (super-instructions)
    │
    ├─ 获取/构建 CFG（全局缓存）
    │
    ├─ cfg.needsRuntimeEpoch() || code > 2048? → optEVMInterpreter.Run()
    │
    ├─ cfg.hasUnresolvedJumps()? → baseEVMInterpreter.Run()
    │
    └─ 初始化 MIRInterpreter，执行 it.RunFrom(0)
```

### 6.2 MIRInterpreter 主循环

```
RunFrom(entryPC=0)
    │
    for each block:
    │
    ├─ 重置 cur.pos = 0  （支持循环重入）
    │
    ├─ 计算入口栈（entryStack）
    │   - 首块：空栈
    │   - 后续块：从前驱的 exitStack 快照 + PHI 解析
    │
    ├─ for each MIR instruction:
    │   ├─ 扣减常量 gas（delta 表 O(1) 查找）
    │   ├─ evalOperand(i): 读取 results[opDefIdx] 或常量
    │   ├─ 执行操作，写入 results[m.resIdx]
    │   └─ 扣减动态 gas（内存扩展、SLOAD、KECCAK 等）
    │
    └─ 处理终止符：
        - JUMP/JUMPI → 跳转到目标块，或 resolveBB()（动态）
        - STOP/RETURN → 结束，返回 ExecResult
        - REVERT → 回滚 state snapshot，返回错误
        - SELFDESTRUCT → 执行销毁，结束
```

---

## 7. PHI 与栈合并模型

### 问题

EVM 栈是隐式的。当控制流在 B3 汇合（B1→B3 和 B2→B3），B3 入口栈上的值可能来自 B1 也可能来自 B2，需要区分。

### 解决方案：PHI 节点

```
B1: PUSH 0x01  →  v1 = 1
B2: PUSH 0x02  →  v2 = 2
B3: [v3 = PHI(v1 from B1, v2 from B2)]
    ADD v3, v4 → ...
```

PHI 节点用 `phiStackIndex` 标识它代表哪个栈槽（0=栈顶），运行时根据**实际执行的前驱块**选取对应值：

```go
// evalPhi (MIRInterpreter.go)
for i, pred := range phi.operands {
    if pred.defBlock == prevBlock {
        return results[pred.resIdx]
    }
}
```

### 入口栈快照（incomingStacks）

每次执行某条边（from → to）时，MIR 记录 `from` 块的出口栈快照，存入 `to.incomingStacks[from]`，供后续 PHI 解析使用。

---

## 8. 动态 CFG 扩展

### 问题

许多合约（如函数 dispatcher）使用 `JUMP` 跳转到运行时计算的目标（calldata 中的函数选择器）。编译期无法确定目标 PC。

### 解决方案：运行时 backfill

```
编译期：
  block B (PC=0x10): JUMP [target=unknown]
  → 标记 unresolvedJump=true

运行时遇到 JUMP：
  1. 从 results 表中取得实际目标 PC = 0x58
  2. resolveBB(0x58):
     a. 验证 0x58 是合法 JUMPDEST
     b. 若 cfg 中无该块 → 构建新块
     c. 记录 CFG 边 B → B'(0x58)
     d. 记录入口栈快照（for PHI）
  3. 跳转到 B'
```

**安全性保证**：
- 目标必须是合法 JUMPDEST，否则 `ErrInvalidJump`
- back-edge（循环）不信任静态快照，每次重新计算
- CFG 在运行时可能被多个 goroutine 访问，通过 `entry.mu` 序列化

---

## 9. Gas 计算模型

### 9.1 常量 Gas：prefix/delta/tail 模型

**目的**：MIR 消除了 DUP/SWAP/PUSH 的运行时执行，但这些 opcode 的 gas 仍需按 EVM 语义扣减。

**方案**：在每个基本块记录原始 `evmOps`（PC + opcode 序列），编译一张前缀和表：

```
evmOps:  [PUSH1(3), PUSH1(3), ADD(3), DUP1(3), JUMP(8)]
prefix:  [0,        3,        6,      9,        12,    20]
delta[i] = prefix[i+1] - prefix[i]
tail     = 0（若 JUMP 已作为 terminator 独立计费）
```

运行时每执行一条 MIR 指令，通过 `evmOpIndex` 查 `delta[i]`，O(1) 扣减，无需扫描。

### 9.2 动态 Gas

| 操作 | 计费方式 |
|------|---------|
| 内存扩展 | 二次方公式，增量计费，`memLastGasFee` 跟踪 |
| SLOAD | EIP-2929：cold=2100, warm=100 |
| SSTORE | EIP-2200 net metering + EIP-3529 退款上限 |
| KECCAK256 | base(30) + 每 word(6) |
| LOG0-LOG4 | base(375) + topic(375×n) + data(8/byte) + memory |
| EXP | base(10) + 指数字节数(50) |
| CALL 族 | EIP-150 63/64 规则 + value transfer surcharge |
| SELFDESTRUCT | EIP-2929 warm/cold beneficiary |

### 9.3 退款处理

在 fullnode 模式（`applyRefundCapInFinish=false`）：MIR **不**在内部应用退款上限，由 geth state_transition 统一处理，避免对 post-intrinsic gas 错误计算。

---

## 10. State 后端与状态管理

### 10.1 StateBackend 接口（`state_backend.go`）

```go
type StateBackend interface {
    GetState(addr, slot) common.Hash
    GetCommittedState(addr, slot) common.Hash   // 用于 SSTORE EIP-2200
    SetState(addr, slot, value common.Hash)
    GetTransientState / SetTransientState        // EIP-1153
    AddRefund / SubRefund
    AddLog(*types.Log)
    AddressInAccessList / SlotInAccessList       // EIP-2929
    AddAddressToAccessList / AddSlotToAccessList
    // ...
}
```

实现：
- **InMemoryState**：单元测试用，内存模拟
- **StateDBBackend**：fullnode 用，wrap `vm.StateDB`

### 10.2 Snapshot/Revert

- **独立模式**（测试工具）：`manageStateSnapshots=true`，MIR 在 REVERT 时调用 `state.RevertToSnapshot()`
- **Fullnode 模式**：`manageStateSnapshots=false`，外层 `evm.Call` 已持有 snapshot，MIR 不重复操作

### 10.3 Nested Call 回调

```go
type CallCreateBackend interface {
    Call(...)    → 调用原生 geth EVM
    Create(...)  → 调用原生 geth EVM
}
```

CALL/CREATE 系列指令在 MIR 中执行完 gas/栈计算后，**回调 geth EVM 执行 callee**，保证 nested call 语义完全正确。

---

## 11. 性能优化策略

| 优化 | 说明 | 位置 |
|------|------|------|
| **寄存器化** | 消除运行时 stack shuffle，DUP/SWAP 编译期处理 | `MIRBasicBlock.go` |
| **CFG 全局缓存** | LRU 4096 条，按 codeHash 缓存，避免重复 parse | `cfg_global_cache.go` |
| **Interpreter Pool** | `sync.Pool` 复用 `MIRInterpreter` 实例 | `evm_runner.go` |
| **resultsGen 世代** | 避免 per-call 清零 results 数组 | `MIRInterpreter.go` |
| **O(1) constant gas** | delta 表预计算，避免热路径 scan | `MIRInterpreter.go` |
| **内存容量复用** | `mem = mem[:0]` 保留 capacity，减少 GC 压力 | `MIRInterpreter.go` |
| **预编码操作数** | `opKinds/opConst/opDefIdx` 避免慢路径 eval | `MIR.go` |
| **热路径 cache** | `lastAddr/lastCodeHash/lastEntry` 跳过全局 cache 查找 | `evm_runner.go` |
| **vmStateDB fast-path** | 直接持有 `vm.StateDB` 避免双重接口 dispatch | `MIRInterpreter.go` |
| **常量折叠** | 编译期 PUSH+JUMP 折叠为静态边 | `opcodeParser.go` |

### 性能门控（Perf Gate）

为保证开启 `EnableMIR` 不会对大合约造成性能退步，`EVMRunner` 内置两个 fallback 路径：

```
code > 2048 bytes         → optEVMInterpreter（super-instructions）
cfg.needsRuntimeEpoch()   → optEVMInterpreter（super-instructions）
cfg.hasUnresolvedJumps()  → baseEVMInterpreter（原生 EVM）
```

这确保 MIR 只在"能赢"的场景下执行。

---

## 12. 与 geth EVM 的集成

### 12.1 Feature Flag

```go
// eth/ethconfig/config.go
type Config struct {
    EnableMIR bool  // 默认 false
    ...
}
```

### 12.2 Fullnode 初始化（`core/state_processor.go`）

```go
evm := vm.NewEVM(context, statedb, config, cfg)
if cfg.EnableMIR {
    evm.SetMIRRunner(mir.NewEVMRunner(evm))
}
```

### 12.3 EVM.Call 中的 dispatch（`core/vm/evm.go`）

```go
if evm.shouldUseMIR() && !isSystemContract(&addr) {
    contract.SetCallCode(&addr, hash, code)
    ret, err = evm.runWithRunner(evm.mirRunner, contract, input, false)
    // 统计 attempt/success counter
} else if evm.Config.EnableOpcodeOptimizations {
    // super-instructions 路径
} else {
    // 原生 EVM 路径
}
```

### 12.4 MIR 统计计数器

```go
var (
    mirTopLevelAttempts   atomic.Uint64
    mirTopLevelSucceeded  atomic.Uint64
    mirTopLevelFallbacks  atomic.Uint64
)
```

每 64K 次尝试打印一次统计日志，方便监控 MIR 覆盖率和回退率。

---

## 13. 调试工具

### 13.1 `mir_block_replay`（`tools/mir_block_replay/main.go`）

用于在全节点 datadir 上重放历史块，比对 MIR 与原生 EVM 的执行结果：

```
mir_block_replay --block 209261 --full --faststate
```

比对项：
- Receipt（status / gasUsed / cumGas / log count）
- State root
- 指定 opcode 的操作数流

调试 hook：
- `SetDebugPhiHook`：PHI 解析轨迹
- `SetDebugOperandHookEx`：操作数值 + 定义来源
- `SetDebugKeccakHook`：KECCAK 输入内存内容
- `SetDebugCallArgsHook`：CALL 参数（offset/size overflow 检测）

### 13.2 `mir_visualizer`（`tools/mir_visualizer/`）

Web UI 工具，粘贴 hex bytecode 即可可视化：
- 基本块及其起止 PC
- CFG 边（fallthrough / jump）
- 各块的入口/出口栈
- 未解析 jump 标记

### 13.3 "Bad Block" 定位流程

```
1. fullnode 报告 bad block N
       ↓
2. mir_block_replay --block N
   找到第一个不匹配的 tx
       ↓
3. 开启 debug hooks：
   - jump operands tail
   - PHI trace
   - SSTORE key/value
       ↓
4. 定位 root cause（常见类型）：
   - CFG 边连接错误（parents/children 覆盖 bug）
   - PHI 选值错误（predecessor 判断错误）
   - 动态 jump backfill 快照形状错误
   - 缺失 opcode 实现（unimplemented MIR op）
   - Gas 计费不对等
       ↓
5. 修复后：重跑 block replay + parity tests
```

---

## 14. 已知限制与未来规划

### 当前限制

| 限制 | 原因 | 影响 |
|------|------|------|
| 仅覆盖顶层调用 | 递归复杂度；nested call 依赖 geth | 高度嵌套合约无加速 |
| code > 2048 bytes fallback | CFG 构建 + 动态 epoch 成本 | 大合约不走 MIR |
| 含 unresolved jumps fallback | 正确性保守策略 | 函数 dispatcher 不走 MIR |
| CFG build 全局锁 | package-level globals（`currentCFGBuild` 等） | 高并发下 build 串行化 |

### 未来规划

1. **去掉 2048 bytes 限制**：完善大合约的 CFG 管理和 epoch 策略
2. **动态 CFG 稳定化**：解除 `hasUnresolvedJumps` fallback，使 dispatcher 合约也能走 MIR
3. **Nested call MIR 化**：至少对常见的 STATICCALL（只读）进行 MIR 化
4. **减少 edge snapshot 分配**：当前 incoming stack snapshot 在每次 backfill 时分配，可改为增量更新
5. **去除全局 build 锁**：将 package-level globals 改为 per-CFG 状态

---

## 15. 文件索引

```
core/opcodeCompiler/compiler/MIR/
├── MIR.go                    # MIR 指令结构体、全局 build mutex
├── MIROperations.go          # MirOperation 枚举（所有 opcode）
├── MIRBasicBlock.go          # 基本块、PHI 创建、DUP/SWAP 编译处理
├── MIRInterpreter.go         # 核心执行引擎（4000+ 行）
├── ValueStack.go             # 编译期 value stack（SSA 构建用）
├── opcodeParser.go           # EVM bytecode → CFG 编译器（1500+ 行）
├── cfg_global_cache.go       # 全局 CFG LRU 缓存
├── cfg_viz.go                # CFG 可视化数据导出
├── debug_dump.go             # 调试 dump 工具
├── state_backend.go          # StateBackend 接口 + InMemoryState
├── statedb_backend.go        # geth StateDB 适配器
├── evm_callcreate_backend.go # CallCreate 接口定义
├── evm_runner.go             # EVMRunner（fullnode 入口，300+ 行）
└── evm_parity_test/          # 端到端 parity 测试（USDT/WBNB/gas）

core/vm/
├── evm.go                    # MIR dispatch 逻辑、isSystemContract
├── interpreter.go            # Config.EnableMIR flag
├── mir_runner.go             # ContractRunner 接口

core/state_processor.go       # fullnode MIR runner 初始化

eth/ethconfig/config.go       # EnableMIR 配置项

tools/
├── mir_block_replay/main.go  # 历史块回放工具
└── mir_visualizer/           # CFG Web 可视化工具

docs/
├── MIR_design_doc.md         # 原始英文设计文档（详尽版）
└── MIR_optimization_design.md  # 本文档
```
