package compiler

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ============================================================================
// MIR Dynamic Gas Table (优化版 - 使用工厂函数，模仿 vm/gas_table.go)
// ============================================================================

// mirDynamicGasFunc 定义 MIR 指令的 dynamic gas 计算函数签名
// 类似 vm.gasFunc，但参数适配 MIR 的执行环境
type mirDynamicGasFunc func(it *MIRInterpreter, m *MIR) (uint64, error)

// mirGasTable 存储每个 MIR 指令的 dynamic gas 计算函数
// 索引是 MirOperation (如 MirEXP, MirSLOAD 等)
var mirGasTable [256]mirDynamicGasFunc

func init() {
	initMIRGasTable()
}

// ============================================================================
// Helper Functions（辅助函数，模仿 vm/gas_table.go）
// ============================================================================

// mirMemoryGasCost 计算内存扩展的 gas（模仿 vm.memoryGasCost）
func mirMemoryGasCost(it *MIRInterpreter, newMemSize uint64) (uint64, error) {
	if newMemSize == 0 {
		return 0, nil
	}
	if newMemSize > 0x1FFFFFFFE0 {
		return 0, errors.New("gas uint overflow")
	}

	newMemSizeWords := toWordSize(newMemSize)
	newMemSize = newMemSizeWords * 32

	if newMemSize > uint64(len(it.memory)) {
		square := newMemSizeWords * newMemSizeWords
		linCoef := newMemSizeWords * params.MemoryGas
		quadCoef := square / params.QuadCoeffDiv
		newTotalFee := linCoef + quadCoef

		fee := newTotalFee - it.lastMemoryGasCost
		return fee, nil
	}
	return 0, nil
}

// pureMemoryGasCost 纯粹基于内存扩展的 gas（模仿 vm.pureMemoryGascost）
// 用于 RETURN, REVERT, CREATE 等只需要内存扩展的 opcodes
func pureMemoryGasCost(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}
	offset := it.evalValue(m.oprands[0])
	size := it.evalValue(m.oprands[1])
	return mirMemoryGasCost(it, offset.Uint64()+size.Uint64())
}

// ============================================================================
// Factory Functions（工厂函数，模仿 vm/gas_table.go）
// ============================================================================

// makeMirMemoryCopierGas 创建 data copy 操作的 gas 函数（模仿 vm.memoryCopierGas）
// 用于 CALLDATACOPY, CODECOPY, RETURNDATACOPY, EXTCODECOPY, MCOPY
func makeMirMemoryCopierGas(sizeOprandIndex int) mirDynamicGasFunc {
	return func(it *MIRInterpreter, m *MIR) (uint64, error) {
		if len(m.oprands) <= sizeOprandIndex {
			return 0, nil
		}

		// 获取 dest offset 和 size
		destOffset := it.evalValue(m.oprands[0])
		size := it.evalValue(m.oprands[sizeOprandIndex])

		// 内存扩展 gas
		gas, err := mirMemoryGasCost(it, destOffset.Uint64()+size.Uint64())
		if err != nil {
			return 0, err
		}

		// Copy gas: 3 gas per word
		words := toWordSize(size.Uint64())
		copyGas := words * params.CopyGas

		var overflow bool
		if gas, overflow = math.SafeAdd(gas, copyGas); overflow {
			return 0, errors.New("gas uint overflow")
		}

		return gas, nil
	}
}

// makeMirGasLog 创建 LOG 操作的 gas 函数（模仿 vm.makeGasLog）
// 用于 LOG0, LOG1, LOG2, LOG3, LOG4
func makeMirGasLog(n uint64) mirDynamicGasFunc {
	return func(it *MIRInterpreter, m *MIR) (uint64, error) {
		if len(m.oprands) < 2 {
			return 0, nil
		}

		// LOG: offset, size, topic0, topic1, ...
		offset := it.evalValue(m.oprands[0])
		size := it.evalValue(m.oprands[1])

		// 内存扩展 gas
		gas, err := mirMemoryGasCost(it, offset.Uint64()+size.Uint64())
		if err != nil {
			return 0, err
		}

		// Data gas: 8 gas per byte
		dataGas := size.Uint64() * params.LogDataGas

		var overflow bool
		if gas, overflow = math.SafeAdd(gas, dataGas); overflow {
			return 0, errors.New("gas uint overflow")
		}

		// Topic gas: 375 gas per topic
		// LOG0=0 topics, LOG1=1 topic, ..., LOG4=4 topics
		topicGas := n * params.LogTopicGas
		if gas, overflow = math.SafeAdd(gas, topicGas); overflow {
			return 0, errors.New("gas uint overflow")
		}

		return gas, nil
	}
}

// ============================================================================
// 通过工厂函数和变量定义生成的 gas 函数（模仿 vm/gas_table.go:91-97, 281-288）
// ============================================================================

var (
	// Data copy operations - 使用工厂函数生成（模仿 vm/gas_table.go:91-97）
	gasMirCALLDATACOPY   = makeMirMemoryCopierGas(2)
	gasMirCODECOPY       = makeMirMemoryCopierGas(2)
	gasMirRETURNDATACOPY = makeMirMemoryCopierGas(2)
	gasMirMCOPY          = makeMirMemoryCopierGas(2)
	gasMirEXTCODECOPY    = func(it *MIRInterpreter, m *MIR) (uint64, error) {
		// EXTCODECOPY 需要额外考虑 warm/cold access
		gas, err := makeMirMemoryCopierGas(3)(it, m)
		if err != nil {
			return 0, err
		}

		// Warm/cold address access
		if len(m.oprands) > 0 && it.env != nil && it.env.StateDBAccessor != nil {
			addrVal := it.evalValue(m.oprands[0])
			addr := common.BytesToAddress(addrVal.Bytes())

			if !it.env.StateDBAccessor.IsAddressInAccessList(addr) {
				it.env.StateDBAccessor.AddAddressToAccessList(addr)
				gas += params.ColdAccountAccessCostEIP2929
			}
		}

		return gas, nil
	}

	// Pure memory operations - 复用 pureMemoryGasCost（模仿 vm/gas_table.go:281-288）
	gasMirRETURN = pureMemoryGasCost
	gasMirREVERT = pureMemoryGasCost
	gasMirCREATE = pureMemoryGasCost
	gasMirMLOAD  = func(it *MIRInterpreter, m *MIR) (uint64, error) {
		if len(m.oprands) < 1 {
			return 0, nil
		}
		offset := it.evalValue(m.oprands[0])
		return mirMemoryGasCost(it, offset.Uint64()+32)
	}
	gasMirMSTORE  = gasMirMLOAD // MSTORE 与 MLOAD 的 gas 计算相同
	gasMirMSTORE8 = func(it *MIRInterpreter, m *MIR) (uint64, error) {
		if len(m.oprands) < 1 {
			return 0, nil
		}
		offset := it.evalValue(m.oprands[0])
		return mirMemoryGasCost(it, offset.Uint64()+1)
	}

	// Log operations - 使用工厂函数生成（模仿 vm/gas_table.go:226-254）
	gasMirLOG0 = makeMirGasLog(0)
	gasMirLOG1 = makeMirGasLog(1)
	gasMirLOG2 = makeMirGasLog(2)
	gasMirLOG3 = makeMirGasLog(3)
	gasMirLOG4 = makeMirGasLog(4)
)

// ============================================================================
// 独立的 gas 函数（需要特殊逻辑的 opcodes）
// ============================================================================

// gasMirKECCAK256 计算 KECCAK256 的 dynamic gas（模仿 vm/gas_table.go:256）
func gasMirKECCAK256(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}

	// 可能的参数顺序：offset, size 或 size, offset（MIR 优化可能交换）
	val1 := it.evalValue(m.oprands[0])
	val2 := it.evalValue(m.oprands[1])

	// 启发式判断：较小的值更可能是 size
	var offset, size *uint256.Int
	if val1.Uint64() < val2.Uint64() {
		size, offset = val1, val2
	} else {
		offset, size = val1, val2
	}

	// 内存扩展 gas
	gas, err := mirMemoryGasCost(it, offset.Uint64()+size.Uint64())
	if err != nil {
		return 0, err
	}

	// Hash gas: 6 gas per word
	words := toWordSize(size.Uint64())
	hashGas := words * params.Keccak256WordGas

	var overflow bool
	if gas, overflow = math.SafeAdd(gas, hashGas); overflow {
		return 0, errors.New("gas uint overflow")
	}

	return gas, nil
}

// gasMirEXP 计算 EXP 的 dynamic gas（模仿 vm/gas_table.go:360）
func gasMirEXP(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}

	// EXP: base, exponent
	exponent := it.evalValue(m.oprands[1])

	// 计算指数的字节长度
	expByteLen := uint64((exponent.BitLen() + 7) / 8)

	// 使用 EIP-158 gas (50 gas per byte)
	gas := expByteLen * params.ExpByteEIP158

	return gas, nil
}

// gasMirSLOAD 计算 SLOAD 的 dynamic gas (EIP-2929 warm/cold)
func gasMirSLOAD(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}

	key := it.evalValue(m.oprands[0])
	slot := common.Hash(key.Bytes32())

	if it.env == nil || it.env.StateDBAccessor == nil {
		return params.SloadGasEIP2200, nil
	}

	addr := it.env.ContractAddress
	if it.env.StateDBAccessor.IsSlotInAccessList(addr, slot) {
		return params.WarmStorageReadCostEIP2929, nil
	}

	it.env.StateDBAccessor.AddSlotToAccessList(addr, slot)
	return params.ColdSloadCostEIP2929, nil
}

// gasMirSSTORE 计算 SSTORE 的 dynamic gas (EIP-2200 + EIP-2929)
func gasMirSSTORE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 2 {
		return 0, nil
	}

	key := it.evalValue(m.oprands[0])
	newValue := it.evalValue(m.oprands[1])

	slot := common.Hash(key.Bytes32())
	newVal := common.Hash(newValue.Bytes32())

	if it.env == nil || it.env.StateDBAccessor == nil {
		return params.SstoreSetGasEIP2200, nil
	}

	addr := it.env.ContractAddress

	// Gas sentry (EIP-2200)
	if it.env.GasConsumer != nil && it.env.GasConsumer.GetGas() <= params.SstoreSentryGasEIP2200 {
		return 0, errors.New("not enough gas for reentrancy sentry")
	}

	currentValue := it.env.StateDBAccessor.GetState(addr, slot)

	// Warm/cold access (EIP-2929)
	var warmColdCost uint64
	if it.env.StateDBAccessor.IsSlotInAccessList(addr, slot) {
		warmColdCost = params.WarmStorageReadCostEIP2929
	} else {
		it.env.StateDBAccessor.AddSlotToAccessList(addr, slot)
		warmColdCost = params.ColdSloadCostEIP2929
	}

	// EIP-2200 logic
	if currentValue == newVal {
		return warmColdCost, nil
	}

	originalValue := it.env.StateDBAccessor.GetCommittedState(addr, slot)
	if originalValue == currentValue {
		if originalValue == (common.Hash{}) {
			// create slot (2.1.1)
			return warmColdCost + params.SstoreSetGasEIP2200, nil
		}
		if newVal == (common.Hash{}) {
			// delete slot (2.1.2b)
			it.env.StateDBAccessor.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
		// write existing slot (2.1.2)
		// EIP-2929: SstoreResetGasEIP2200 already includes cold cost, so we subtract it
		return warmColdCost + (params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929), nil
	}

	// Dirty update
	if originalValue != (common.Hash{}) {
		if currentValue == (common.Hash{}) {
			// recreate slot (2.2.1.1)
			it.env.StateDBAccessor.SubRefund(params.SstoreClearsScheduleRefundEIP2200)
		} else if newVal == (common.Hash{}) {
			// delete slot (2.2.1.2)
			it.env.StateDBAccessor.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
	}
	if originalValue == newVal {
		if originalValue == (common.Hash{}) {
			// reset to original inexistent slot (2.2.2.1)
			it.env.StateDBAccessor.AddRefund(params.SstoreSetGasEIP2200 - params.ColdSloadCostEIP2929)
		} else {
			// reset to original existing slot (2.2.2.2)
			it.env.StateDBAccessor.AddRefund(params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929)
		}
	}

	// dirty update (2.2)
	return warmColdCost, nil
}

// gasMirCREATE2 计算 CREATE2 的 dynamic gas（模仿 vm/gas_table.go:290）
func gasMirCREATE2(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 3 {
		return 0, nil
	}

	// CREATE2: value, offset, size, salt
	offset := it.evalValue(m.oprands[1])
	size := it.evalValue(m.oprands[2])

	// 内存扩展 gas
	gas, err := mirMemoryGasCost(it, offset.Uint64()+size.Uint64())
	if err != nil {
		return 0, err
	}

	// Hash gas for CREATE2: 6 gas per word
	words := toWordSize(size.Uint64())
	hashGas := words * params.Keccak256WordGas

	var overflow bool
	if gas, overflow = math.SafeAdd(gas, hashGas); overflow {
		return 0, errors.New("gas uint overflow")
	}

	return gas, nil
}

// gasMirCALL 计算 CALL 的 dynamic gas（模仿 vm/gas_table.go:373）
func gasMirCALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 7 {
		return 0, nil
	}

	// CALL: gas, addr, value, inOffset, inSize, outOffset, outSize
	addr := it.evalValue(m.oprands[1])
	value := it.evalValue(m.oprands[2])
	inOffset := it.evalValue(m.oprands[3])
	inSize := it.evalValue(m.oprands[4])
	outOffset := it.evalValue(m.oprands[5])
	outSize := it.evalValue(m.oprands[6])

	var gas uint64

	// Warm/cold address access (EIP-2929)
	address := common.BytesToAddress(addr.Bytes())
	if it.env != nil && it.env.StateDBAccessor != nil {
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += params.ColdAccountAccessCostEIP2929
		}
	}

	// Value transfer
	if value.Sign() != 0 {
		gas += params.CallValueTransferGas

		// New account creation
		if it.env != nil && it.env.StateDBAccessor != nil {
			if it.env.StateDBAccessor.IsAccountEmpty(address) {
				gas += params.CallNewAccountGas
			}
		}
	}

	// Memory expansion
	inEnd := inOffset.Uint64() + inSize.Uint64()
	outEnd := outOffset.Uint64() + outSize.Uint64()
	maxEnd := inEnd
	if outEnd > maxEnd {
		maxEnd = outEnd
	}

	memGas, err := mirMemoryGasCost(it, maxEnd)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if gas, overflow = math.SafeAdd(gas, memGas); overflow {
		return 0, errors.New("gas uint overflow")
	}

	return gas, nil
}

// gasMirCALLCODE 计算 CALLCODE 的 dynamic gas（模仿 vm/gas_table.go:416）
func gasMirCALLCODE(it *MIRInterpreter, m *MIR) (uint64, error) {
	return gasMirCALL(it, m) // CALLCODE 与 CALL 的 gas 计算相同
}

// gasMirDELEGATECALL 计算 DELEGATECALL 的 dynamic gas（模仿 vm/gas_table.go:451）
func gasMirDELEGATECALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 6 {
		return 0, nil
	}

	// DELEGATECALL: gas, addr, inOffset, inSize, outOffset, outSize
	addr := it.evalValue(m.oprands[1])
	inOffset := it.evalValue(m.oprands[2])
	inSize := it.evalValue(m.oprands[3])
	outOffset := it.evalValue(m.oprands[4])
	outSize := it.evalValue(m.oprands[5])

	var gas uint64

	// Warm/cold address access
	address := common.BytesToAddress(addr.Bytes())
	if it.env != nil && it.env.StateDBAccessor != nil {
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += params.ColdAccountAccessCostEIP2929
		}
	}

	// Memory expansion
	inEnd := inOffset.Uint64() + inSize.Uint64()
	outEnd := outOffset.Uint64() + outSize.Uint64()
	maxEnd := inEnd
	if outEnd > maxEnd {
		maxEnd = outEnd
	}

	memGas, err := mirMemoryGasCost(it, maxEnd)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if gas, overflow = math.SafeAdd(gas, memGas); overflow {
		return 0, errors.New("gas uint overflow")
	}

	return gas, nil
}

// gasMirSTATICCALL 计算 STATICCALL 的 dynamic gas（模仿 vm/gas_table.go:467）
func gasMirSTATICCALL(it *MIRInterpreter, m *MIR) (uint64, error) {
	return gasMirDELEGATECALL(it, m) // STATICCALL 与 DELEGATECALL 的 gas 计算相同
}

// gasMirSELFDESTRUCT 计算 SELFDESTRUCT 的 dynamic gas（模仿 vm/gas_table.go:483）
func gasMirSELFDESTRUCT(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}

	beneficiary := it.evalValue(m.oprands[0])
	address := common.BytesToAddress(beneficiary.Bytes())

	var gas uint64

	// Warm/cold address access
	if it.env != nil && it.env.StateDBAccessor != nil {
		if !it.env.StateDBAccessor.IsAddressInAccessList(address) {
			it.env.StateDBAccessor.AddAddressToAccessList(address)
			gas += params.ColdAccountAccessCostEIP2929
		}

		// New account creation (if has balance and beneficiary is empty)
		if it.env.SelfBalance > 0 && it.env.StateDBAccessor.IsAccountEmpty(address) {
			gas += params.CreateBySelfdestructGas
		}

		// Refund (EIP-3529)
		if !it.env.StateDBAccessor.HasSelfDestructed(it.env.ContractAddress) {
			it.env.StateDBAccessor.AddRefund(params.SelfdestructRefundGas)
		}
	}

	return gas, nil
}

// gasMirBALANCE 计算 BALANCE 的 dynamic gas (warm/cold access)
func gasMirBALANCE(it *MIRInterpreter, m *MIR) (uint64, error) {
	if len(m.oprands) < 1 {
		return 0, nil
	}

	addrVal := it.evalValue(m.oprands[0])
	addr := common.BytesToAddress(addrVal.Bytes())

	if it.env == nil || it.env.StateDBAccessor == nil {
		return 0, nil
	}

	if it.env.StateDBAccessor.IsAddressInAccessList(addr) {
		return 0, nil
	}

	it.env.StateDBAccessor.AddAddressToAccessList(addr)
	return params.ColdAccountAccessCostEIP2929, nil
}

// gasMirEXTCODESIZE 计算 EXTCODESIZE 的 dynamic gas
func gasMirEXTCODESIZE(it *MIRInterpreter, m *MIR) (uint64, error) {
	return gasMirBALANCE(it, m) // 与 BALANCE 的 gas 计算相同
}

// gasMirEXTCODEHASH 计算 EXTCODEHASH 的 dynamic gas
func gasMirEXTCODEHASH(it *MIRInterpreter, m *MIR) (uint64, error) {
	return gasMirBALANCE(it, m) // 与 BALANCE 的 gas 计算相同
}

// ============================================================================
// 初始化 MIR Gas Table
// ============================================================================

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
