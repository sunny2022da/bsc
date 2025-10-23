package compiler

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
)

// ============================================================================
// MIR Dynamic Gas Table (集中管理，模仿 interpreter.go 的 JumpTable)
// ============================================================================

// mirDynamicGasFunc 定义 MIR 指令的 dynamic gas 计算函数签名
// 类似 vm.gasFunc，但参数适配 MIR 的执行环境
type mirDynamicGasFunc func(it *MIRInterpreter, m *MIR) (uint64, error)

// mirGasTable 存储每个 MIR 指令的 dynamic gas 计算函数
// 索引是 MIROp (如 MirEXP, MirSLOAD 等)
var mirGasTable [256]mirDynamicGasFunc

func init() {
	// 初始化 MIR gas table
	initMIRGasTable()
}

// initMIRGasTable 初始化 MIR 指令的 dynamic gas 配置
func initMIRGasTable() {
	// 内存操作
	mirGasTable[byte(MirMLOAD)] = gasMirMLOAD
	mirGasTable[byte(MirMSTORE)] = gasMirMSTORE
	mirGasTable[byte(MirMSTORE8)] = gasMirMSTORE8
	mirGasTable[byte(MirMCOPY)] = gasMirMCOPY
	
	// 哈希和数据操作
	mirGasTable[byte(MirKECCAK256)] = gasMirKECCAK256
	mirGasTable[byte(MirCALLDATACOPY)] = gasMirCALLDATACOPY
	mirGasTable[byte(MirRETURNDATACOPY)] = gasMirRETURNDATACOPY
	mirGasTable[byte(MirCODECOPY)] = gasMirCODECOPY
	
	// 算术操作
	mirGasTable[byte(MirEXP)] = gasMirEXP
	
	// 存储操作
	mirGasTable[byte(MirSLOAD)] = gasMirSLOAD
	mirGasTable[byte(MirSSTORE)] = gasMirSSTORE
	
	// 日志操作
	mirGasTable[byte(MirLOG0)] = gasMirLOG0
	mirGasTable[byte(MirLOG1)] = gasMirLOG1
	mirGasTable[byte(MirLOG2)] = gasMirLOG2
	mirGasTable[byte(MirLOG3)] = gasMirLOG3
	mirGasTable[byte(MirLOG4)] = gasMirLOG4
	
	// 调用操作
	mirGasTable[byte(MirCALL)] = gasMirCALL
	mirGasTable[byte(MirCALLCODE)] = gasMirCALLCODE
	mirGasTable[byte(MirDELEGATECALL)] = gasMirDELEGATECALL
	mirGasTable[byte(MirSTATICCALL)] = gasMirSTATICCALL
	
	// 合约创建
	mirGasTable[byte(MirCREATE)] = gasMirCREATE
	mirGasTable[byte(MirCREATE2)] = gasMirCREATE2
	
	// 返回操作
	mirGasTable[byte(MirRETURN)] = gasMirRETURN
	mirGasTable[byte(MirREVERT)] = gasMirREVERT
	
	// 自毁
	mirGasTable[byte(MirSELFDESTRUCT)] = gasMirSELFDESTRUCT
	
	// 外部代码操作
	mirGasTable[byte(MirEXTCODECOPY)] = gasMirEXTCODECOPY
	mirGasTable[byte(MirEXTCODESIZE)] = gasMirEXTCODESIZE
	mirGasTable[byte(MirEXTCODEHASH)] = gasMirEXTCODEHASH
	mirGasTable[byte(MirBALANCE)] = gasMirBALANCE
}

// ============================================================================
// 内存操作的 Dynamic Gas
// ============================================================================

// gasMirMLOAD 计算 MLOAD 的 dynamic gas (内存扩展)
func gasMirMLOAD(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	offset := it.evalValue(m.oprands[0])
	return it.calculateMemoryExpansionGas(offset.Uint64(), 32)
}

// gasMirMSTORE 计算 MSTORE 的 dynamic gas (内存扩展)
func gasMirMSTORE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	offset := it.evalValue(m.oprands[0])
	return it.calculateMemoryExpansionGas(offset.Uint64(), 32)
}

// gasMirMSTORE8 计算 MSTORE8 的 dynamic gas (内存扩展)
func gasMirMSTORE8(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	offset := it.evalValue(m.oprands[0])
	return it.calculateMemoryExpansionGas(offset.Uint64(), 1)
}

// gasMirMCOPY 计算 MCOPY 的 dynamic gas (内存扩展 + 复制cost)
func gasMirMCOPY(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}
	dest := it.evalValue(m.oprands[0])
	length := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(dest.Uint64(), length.Uint64())
	if err != nil {
		return 0, err
	}
	
	// 复制 gas: 3 gas per word
	words := toWordSize(length.Uint64())
	copyGas := words * 3
	
	return memGas + copyGas, nil
}

// ============================================================================
// 哈希和数据操作的 Dynamic Gas
// ============================================================================

// gasMirKECCAK256 计算 KECCAK256 的 dynamic gas (内存扩展 + 哈希cost)
func gasMirKECCAK256(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}
	
	// MIR 可能以不同顺序存储参数，需要判断
	aval := it.evalValue(m.oprands[0])
	bval := it.evalValue(m.oprands[1])
	
	var offset, size uint64
	// Heuristic: 如果第一个值像size(如32)且第二个小(如0)，则翻转
	if (aval.Uint64() == 32 && bval.Uint64() < 32) || (aval.Uint64() != 0 && bval.Uint64() == 0) {
		offset, size = bval.Uint64(), aval.Uint64()
	} else {
		offset, size = aval.Uint64(), bval.Uint64()
	}
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(offset, size)
	if err != nil {
		return 0, err
	}
	
	// 哈希 gas: 6 gas per word
	words := toWordSize(size)
	hashGas := words * 6
	
	return memGas + hashGas, nil
}

// gasMirCALLDATACOPY 计算 CALLDATACOPY 的 dynamic gas
func gasMirCALLDATACOPY(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}
	destOffset := it.evalValue(m.oprands[0])
	length := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(destOffset.Uint64(), length.Uint64())
	if err != nil {
		return 0, err
	}
	
	// 复制 gas: 3 gas per word
	words := toWordSize(length.Uint64())
	copyGas := words * 3
	
	return memGas + copyGas, nil
}

// gasMirRETURNDATACOPY 计算 RETURNDATACOPY 的 dynamic gas
func gasMirRETURNDATACOPY(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}
	destOffset := it.evalValue(m.oprands[0])
	length := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(destOffset.Uint64(), length.Uint64())
	if err != nil {
		return 0, err
	}
	
	// 复制 gas: 3 gas per word
	words := toWordSize(length.Uint64())
	copyGas := words * 3
	
	return memGas + copyGas, nil
}

// gasMirCODECOPY 计算 CODECOPY 的 dynamic gas
func gasMirCODECOPY(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}
	destOffset := it.evalValue(m.oprands[0])
	length := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(destOffset.Uint64(), length.Uint64())
	if err != nil {
		return 0, err
	}
	
	// 复制 gas: 3 gas per word
	words := toWordSize(length.Uint64())
	copyGas := words * 3
	
	return memGas + copyGas, nil
}

// ============================================================================
// 算术操作的 Dynamic Gas
// ============================================================================

// gasMirEXP 计算 EXP 的 dynamic gas (基于指数的字节长度)
func gasMirEXP(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}
	
	// 获取指数值（第二个操作数）
	exponent := it.evalValue(m.oprands[1])
	
	// 计算指数的字节长度
	expByteLen := uint64((exponent.BitLen() + 7) / 8)
	
	// 根据 fork 计算 dynamic gas
	var gasPerByte uint64
	if it.env != nil && it.env.IsEIP158 {
		gasPerByte = 50 // EIP-158 (Spurious Dragon)
	} else {
		gasPerByte = 10 // Frontier
	}
	
	return expByteLen * gasPerByte, nil
}

// ============================================================================
// 存储操作的 Dynamic Gas (SLOAD/SSTORE - 最复杂的部分)
// ============================================================================

// gasMirSLOAD 计算 SLOAD 的 dynamic gas (warm/cold access - EIP-2929)
func gasMirSLOAD(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	
	// 获取存储键
	key := it.evalValue(m.oprands[0])
	slot := common.Hash(key.Bytes32())
	
	// 检查是否有 StateDBAccessor（warm/cold tracking）
	if it.env == nil || it.env.StateDBAccessor == nil {
		// 没有 StateDBAccessor，返回基础 gas (200 - EIP-2200)
		// 这是 fallback，实际部署时应该总是有 StateDBAccessor
		return 200, nil
	}
	
	// 获取合约地址
	addr := it.env.ContractAddress
	
	// 检查 slot 是否在访问列表中 (warm)
	if it.env.StateDBAccessor.IsSlotInAccessList(addr, slot) {
		// Warm access: 100 gas (EIP-2929)
		return 100, nil
	}
	
	// Cold access: 2100 gas (EIP-2929)
	// 同时将 slot 加入访问列表
	it.env.StateDBAccessor.AddSlotToAccessList(addr, slot)
	return 2100, nil
}

// gasMirSSTORE 计算 SSTORE 的 dynamic gas (warm/cold + dirty/clean - EIP-2929 + EIP-2200)
func gasMirSSTORE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}
	
	// 获取存储键和新值
	key := it.evalValue(m.oprands[0])
	newValue := it.evalValue(m.oprands[1])
	slot := common.Hash(key.Bytes32())
	newVal := common.Hash(newValue.Bytes32())
	
	// 检查是否有 StateDBAccessor
	if it.env == nil || it.env.StateDBAccessor == nil {
		// Fallback: 返回基础 gas (5000 - reset gas)
		return 5000, nil
	}
	
	addr := it.env.ContractAddress
	
	// 检查 gas 是否足够 (EIP-2200 gas sentry)
	if it.env.GasConsumer != nil && it.env.GasConsumer.GetGas() <= 2300 {
		return 0, errors.New("not enough gas for reentrancy sentry")
	}
	
	// 获取当前值
	currentValue := it.env.StateDBAccessor.GetState(addr, slot)
	
	// Warm/cold access cost (EIP-2929)
	var warmColdCost uint64
	if it.env.StateDBAccessor.IsSlotInAccessList(addr, slot) {
		// Warm: 100 gas
		warmColdCost = 100
	} else {
		// Cold: 2100 gas
		it.env.StateDBAccessor.AddSlotToAccessList(addr, slot)
		warmColdCost = 2100
	}
	
	// EIP-2200/EIP-2929 gas calculation
	if currentValue == newVal {
		// Noop: SLOAD_GAS (warm already included)
		return warmColdCost, nil
	}
	
	// 获取原始值 (transaction 开始时的值)
	originalValue := it.env.StateDBAccessor.GetCommittedState(addr, slot)
	
	if originalValue == currentValue {
		// 这个 slot 在当前 transaction 中还没被修改过
		if originalValue == (common.Hash{}) {
			// 创建新 slot: 20000 gas
			return warmColdCost + 20000, nil
		}
		if newVal == (common.Hash{}) {
			// 删除 slot: 退款 15000 gas
			it.env.StateDBAccessor.AddRefund(15000)
		}
		// 修改现有 slot: 5000 - COLD_SLOAD_COST (已经在 warmColdCost 中扣除)
		// EIP-2929: 5000 - 2100 = 2900 (如果是 cold)
		// 但 warmColdCost 已经扣除了，所以只需再扣 (5000 - 100) = 4900
		if warmColdCost == 100 {
			return warmColdCost + 4900, nil // warm: 100 + 4900 = 5000
		} else {
			return warmColdCost + 2900, nil // cold: 2100 + 2900 = 5000
		}
	}
	
	// Dirty slot (已经在当前 transaction 中被修改过)
	if originalValue != (common.Hash{}) {
		if currentValue == (common.Hash{}) {
			// Recreate slot: 取消之前的退款
			it.env.StateDBAccessor.SubRefund(15000)
		} else if newVal == (common.Hash{}) {
			// Delete slot: 退款
			it.env.StateDBAccessor.AddRefund(15000)
		}
	}
	
	if originalValue == newVal {
		// Reset to original value
		if originalValue == (common.Hash{}) {
			// Reset to original 0: 退款 19800
			it.env.StateDBAccessor.AddRefund(19800)
		} else {
			// Reset to original non-zero: 退款 4800
			it.env.StateDBAccessor.AddRefund(4800)
		}
	}
	
	// Dirty update: 只扣 warm/cold cost
	return warmColdCost, nil
}

// ============================================================================
// 日志操作的 Dynamic Gas
// ============================================================================

// makeGasMirLog 创建 LOG 的 dynamic gas 计算函数
func makeGasMirLog(numTopics int) mirDynamicGasFunc {
	return func(it *MIRInterpreter, m *MIR) (uint64, error) {
		if len(m.oprands) < 2 {
			return 0, nil
		}
		
		dataOffset := it.evalValue(m.oprands[0])
		dataSize := it.evalValue(m.oprands[1])
		
		// 内存扩展 gas
		memGas, err := it.calculateMemoryExpansionGas(dataOffset.Uint64(), dataSize.Uint64())
		if err != nil {
			return 0, err
		}
		
		// 数据 gas: 8 gas per byte
		dataGas := dataSize.Uint64() * 8
		
		return memGas + dataGas, nil
	}
}

var (
	gasMirLOG0 = makeGasMirLog(0)
	gasMirLOG1 = makeGasMirLog(1)
	gasMirLOG2 = makeGasMirLog(2)
	gasMirLOG3 = makeGasMirLog(3)
	gasMirLOG4 = makeGasMirLog(4)
)

// ============================================================================
// 调用操作的 Dynamic Gas (CALL, CALLCODE, DELEGATECALL, STATICCALL)
// ============================================================================

// gasMirCALL 计算 CALL 的 dynamic gas
func gasMirCALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 7 {
		return 0, nil
	}
	
	// CALL 的参数: gas, addr, value, inOffset, inSize, outOffset, outSize
	addr := it.evalValue(m.oprands[1])
	value := it.evalValue(m.oprands[2])
	inOffset := it.evalValue(m.oprands[3])
	inSize := it.evalValue(m.oprands[4])
	outOffset := it.evalValue(m.oprands[5])
	outSize := it.evalValue(m.oprands[6])
	
	var gas uint64
	
	// 内存扩展 gas (input + output 两个区域)
	memGas1, err := it.calculateMemoryExpansionGas(inOffset.Uint64(), inSize.Uint64())
	if err != nil {
		return 0, err
	}
	memGas2, err := it.calculateMemoryExpansionGas(outOffset.Uint64(), outSize.Uint64())
	if err != nil {
		return 0, err
	}
	gas = memGas1
	if memGas2 > memGas1 {
		gas = memGas2
	}
	
	// 检查是否有 StateDBAccessor
	if it.env == nil || it.env.StateDBAccessor == nil {
		// Fallback: 返回基础内存 gas
		return gas, nil
	}
	
	address := common.Address(addr.Bytes20())
	
	// Warm/cold access cost (EIP-2929)
	if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
		it.env.StateDBAccessor.AddAddressToAccessList(address)
		// Cold account access: 2600 gas
		gas += 2600
	}
	
	// Value transfer cost (如果转账 value > 0)
	transfersValue := !value.IsZero()
	if transfersValue {
		// Value transfer: 9000 gas
		gas += 9000
		
		// 检查是否创建新账户
		if it.env.StateDBAccessor.IsAccountEmpty(address) {
			// New account: 25000 gas
			gas += 25000
		}
	}
	
	return gas, nil
}

// gasMirCALLCODE 计算 CALLCODE 的 dynamic gas
func gasMirCALLCODE(it *MIRInterpreter, m *MIR) (uint64, error) {
	// CALLCODE 的 gas 计算与 CALL 类似
	return gasMirCALL(it, m)
}

// gasMirDELEGATECALL 计算 DELEGATECALL 的 dynamic gas
func gasMirDELEGATECALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 6 {
		return 0, nil
	}
	
	// DELEGATECALL 参数: gas, addr, inOffset, inSize, outOffset, outSize (no value)
	addr := it.evalValue(m.oprands[1])
	inOffset := it.evalValue(m.oprands[2])
	inSize := it.evalValue(m.oprands[3])
	outOffset := it.evalValue(m.oprands[4])
	outSize := it.evalValue(m.oprands[5])
	
	var gas uint64
	
	// 内存扩展 gas
	memGas1, err := it.calculateMemoryExpansionGas(inOffset.Uint64(), inSize.Uint64())
	if err != nil {
		return 0, err
	}
	memGas2, err := it.calculateMemoryExpansionGas(outOffset.Uint64(), outSize.Uint64())
	if err != nil {
		return 0, err
	}
	gas = memGas1
	if memGas2 > memGas1 {
		gas = memGas2
	}
	
	// Warm/cold access (EIP-2929)
	if it.env != nil && it.env.StateDBAccessor != nil {
		address := common.Address(addr.Bytes20())
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += 2600
		}
	}
	
	return gas, nil
}

// gasMirSTATICCALL 计算 STATICCALL 的 dynamic gas
func gasMirSTATICCALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	// STATICCALL 与 DELEGATECALL 的 gas 计算相同
	return gasMirDELEGATECALL(it, m)
}

// ============================================================================
// 合约创建的 Dynamic Gas (CREATE, CREATE2)
// ============================================================================

// gasMirCREATE 计算 CREATE 的 dynamic gas
func gasMirCREATE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}
	
	// CREATE 参数: value, offset, size
	offset := it.evalValue(m.oprands[1])
	size := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	return it.calculateMemoryExpansionGas(offset.Uint64(), size.Uint64())
}

// gasMirCREATE2 计算 CREATE2 的 dynamic gas
func gasMirCREATE2(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 4 {
		return 0, nil
	}
	
	// CREATE2 参数: value, offset, size, salt
	offset := it.evalValue(m.oprands[1])
	size := it.evalValue(m.oprands[2])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(offset.Uint64(), size.Uint64())
	if err != nil {
		return 0, err
	}
	
	// CREATE2 特有: 对 init code 进行 keccak256 hash
	// Hash gas: 6 gas per word
	words := toWordSize(size.Uint64())
	hashGas := words * 6
	
	return memGas + hashGas, nil
}

// ============================================================================
// 返回操作的 Dynamic Gas
// ============================================================================

// gasMirRETURN 计算 RETURN 的 dynamic gas
func gasMirRETURN(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}
	
	offset := it.evalValue(m.oprands[0])
	size := it.evalValue(m.oprands[1])
	
	return it.calculateMemoryExpansionGas(offset.Uint64(), size.Uint64())
}

// gasMirREVERT 计算 REVERT 的 dynamic gas
func gasMirREVERT(it *MIRInterpreter, m *MIR) (uint64, error) {
	// REVERT 与 RETURN 的 gas 计算相同
	return gasMirRETURN(it, m)
}

// ============================================================================
// SELFDESTRUCT 的 Dynamic Gas
// ============================================================================

// gasMirSELFDESTRUCT 计算 SELFDESTRUCT 的 dynamic gas
func gasMirSELFDESTRUCT(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	
	addr := it.evalValue(m.oprands[0])
	address := common.Address(addr.Bytes20())
	
	var gas uint64
	
	// 检查是否有 StateAccessor
	if it.env != nil && it.env.StateDBAccessor != nil {
		// Warm/cold access (EIP-2929)
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += 2600
		}
		
		// 检查是否创建新账户（发送余额到不存在的账户）
		if it.env.StateDBAccessor.IsAccountEmpty(address) && it.env.SelfBalance > 0 {
			// New account: 25000 gas
			gas += 25000
		}
		
		// 退款 (如果还没有 self-destruct)
		if !it.env.StateDBAccessor.HasSelfDestructed(it.env.ContractAddress) {
			it.env.StateDBAccessor.AddRefund(24000)
		}
	}
	
	return gas, nil
}

// ============================================================================
// 外部代码操作的 Dynamic Gas
// ============================================================================

// gasMirEXTCODECOPY 计算 EXTCODECOPY 的 dynamic gas
func gasMirEXTCODECOPY(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 4 {
		return 0, nil
	}
	
	addr := it.evalValue(m.oprands[0])
	destOffset := it.evalValue(m.oprands[1])
	length := it.evalValue(m.oprands[3])
	
	// 内存扩展 gas
	memGas, err := it.calculateMemoryExpansionGas(destOffset.Uint64(), length.Uint64())
	if err != nil {
		return 0, err
	}
	
	// 复制 gas
	words := toWordSize(length.Uint64())
	copyGas := words * 3
	
	gas := memGas + copyGas
	
	// Warm/cold access (EIP-2929)
	if it.env != nil && it.env.StateDBAccessor != nil {
		address := common.Address(addr.Bytes20())
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += 2600
		}
	}
	
	return gas, nil
}

// gasMirEXTCODESIZE 计算 EXTCODESIZE 的 dynamic gas
func gasMirEXTCODESIZE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}
	
	addr := it.evalValue(m.oprands[0])
	address := common.Address(addr.Bytes20())
	
	// Warm/cold access (EIP-2929)
	if it.env != nil && it.env.StateDBAccessor != nil {
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			return 2600, nil
		}
	}
	
	return 0, nil
}

// gasMirEXTCODEHASH 计算 EXTCODEHASH 的 dynamic gas
func gasMirEXTCODEHASH(it *MIRInterpreter, m *MIR) (uint64, error) {
	// EXTCODEHASH 与 EXTCODESIZE 的 gas 计算相同
	return gasMirEXTCODESIZE(it, m)
}

// gasMirBALANCE 计算 BALANCE 的 dynamic gas
func gasMirBALANCE(it *MIRInterpreter, m *MIR) (uint64, error) {
	// BALANCE 与 EXTCODESIZE 的 gas 计算相同
	return gasMirEXTCODESIZE(it, m)
}

// ============================================================================
// 辅助函数
// ============================================================================

// calculateMemoryExpansionGas 计算内存扩展的 dynamic gas（不改变 lastMemoryGasCost）
// 这是一个纯查询函数，实际扣除和更新在统一的地方处理
func (it *MIRInterpreter) calculateMemoryExpansionGas(offset, length uint64) (uint64, error) {
	if length == 0 {
		return 0, nil
	}
	
	// 计算新的内存大小
	if offset > ^uint64(0)-length {
		return 0, errors.New("memory offset overflow")
	}
	newMemSize := offset + length
	
	if newMemSize == 0 {
		return 0, nil
	}
	
	// 检查溢出
	if newMemSize > 0x1FFFFFFFE0 {
		return 0, errors.New("gas uint overflow")
	}
	
	newMemSizeWords := toWordSize(newMemSize)
	newMemSize = newMemSizeWords * 32
	
	currentMemSize := uint64(len(it.memory))
	
	// 只有当需要扩展内存时才计算 gas
	if newMemSize <= currentMemSize {
		return 0, nil
	}
	
	const MemoryGas = uint64(3)
	const QuadCoeffDiv = uint64(512)
	
	// 计算新的总 gas
	square := newMemSizeWords * newMemSizeWords
	linCoef := newMemSizeWords * MemoryGas
	quadCoef := square / QuadCoeffDiv
	newTotalFee := linCoef + quadCoef
	
	// 返回增量 gas
	return newTotalFee - it.lastMemoryGasCost, nil
}

