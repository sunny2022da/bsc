package vm

import "github.com/ethereum/go-ethereum/params"

// ConstantGasForOp returns the constant (static) gas for the given opcode under the
// provided chain rules. This is a small exported helper so other packages (e.g. MIR)
// can do gas accounting without duplicating the fork-dependent jump tables.
//
// Note: The returned value does NOT include any dynamic gas component (memory expansion,
// Keccak word gas, SSTORE rules, CALL costs, etc.).
func ConstantGasForOp(r params.Rules, op OpCode) (uint64, bool) {
	jt := jumpTableForRules(r)
	entry := jt[byte(op)]
	if entry == nil {
		return 0, false
	}
	return entry.constantGas, true
}

// jumpTableForRules selects the canonical jump table for a given ruleset.
// This mirrors the selection logic in NewEVMInterpreter.
func jumpTableForRules(r params.Rules) JumpTable {
	switch {
	case r.IsVerkle:
		return verkleInstructionSet
	case r.IsPrague:
		return pragueInstructionSet
	case r.IsCancun:
		return cancunInstructionSet
	case r.IsShanghai:
		return shanghaiInstructionSet
	case r.IsMerge:
		return mergeInstructionSet
	case r.IsLondon:
		return londonInstructionSet
	case r.IsBerlin:
		return berlinInstructionSet
	case r.IsIstanbul:
		return istanbulInstructionSet
	case r.IsConstantinople:
		return constantinopleInstructionSet
	case r.IsByzantium:
		return byzantiumInstructionSet
	case r.IsEIP158:
		return spuriousDragonInstructionSet
	case r.IsEIP150:
		return tangerineWhistleInstructionSet
	case r.IsHomestead:
		return homesteadInstructionSet
	default:
		return frontierInstructionSet
	}
}


