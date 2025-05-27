package compiler

// ByteCode represents an EVM opcode
type ByteCode byte

// Opcode definitions
const (
	// 0x0 range - arithmetic ops
	STOP ByteCode = iota
	ADD
	MUL
	SUB
	DIV
	SDIV
	MOD
	SMOD
	EXP
	NOT
	LT
	GT
	SLT
	SGT
	EQ
	ISZERO
	AND
	OR
	XOR
	BYTE
	SHL
	SHR
	SAR
	ADDMOD
	MULMOD
	SIGNEXTEND

	// 0x10 range - comparison & bitwise logic
	KECCAK256

	// 0x20 range - block operations
	ADDRESS
	BALANCE
	ORIGIN
	CALLER
	CALLVALUE
	CALLDATALOAD
	CALLDATASIZE
	CALLDATACOPY
	CODESIZE
	CODECOPY
	GASPRICE
	EXTCODESIZE
	EXTCODECOPY
	RETURNDATASIZE
	RETURNDATACOPY
	EXTCODEHASH

	// 0x30 range - block operations
	BLOCKHASH
	COINBASE
	TIMESTAMP
	NUMBER
	DIFFICULTY
	GASLIMIT
	CHAINID
	SELFBALANCE
	BASEFEE

	// 0x40 range - block operations
	POP
	MLOAD
	MSTORE
	MSTORE8
	SLOAD
	SSTORE
	JUMP
	JUMPI
	PC
	MSIZE
	GAS
	JUMPDEST

	// 0x50 range - push operations
	PUSH1 ByteCode = 0x60 + iota
	PUSH2
	PUSH3
	PUSH4
	PUSH5
	PUSH6
	PUSH7
	PUSH8
	PUSH9
	PUSH10
	PUSH11
	PUSH12
	PUSH13
	PUSH14
	PUSH15
	PUSH16
	PUSH17
	PUSH18
	PUSH19
	PUSH20
	PUSH21
	PUSH22
	PUSH23
	PUSH24
	PUSH25
	PUSH26
	PUSH27
	PUSH28
	PUSH29
	PUSH30
	PUSH31
	PUSH32

	// 0x80 range - dups
	DUP1 ByteCode = 0x80 + iota
	DUP2
	DUP3
	DUP4
	DUP5
	DUP6
	DUP7
	DUP8
	DUP9
	DUP10
	DUP11
	DUP12
	DUP13
	DUP14
	DUP15
	DUP16

	// 0x90 range - swaps
	SWAP1  ByteCode = 0x90
	SWAP2  ByteCode = 0x91
	SWAP3  ByteCode = 0x92
	SWAP4  ByteCode = 0x93
	SWAP5  ByteCode = 0x94
	SWAP6  ByteCode = 0x95
	SWAP7  ByteCode = 0x96
	SWAP8  ByteCode = 0x97
	SWAP9  ByteCode = 0x98
	SWAP10 ByteCode = 0x99
	SWAP11 ByteCode = 0x9a
	SWAP12 ByteCode = 0x9b
	SWAP13 ByteCode = 0x9c
	SWAP14 ByteCode = 0x9d
	SWAP15 ByteCode = 0x9e
	SWAP16 ByteCode = 0x9f

	// 0xa0 range - logging ops
	LOG0 ByteCode = 0xa0
	LOG1 ByteCode = 0xa1
	LOG2 ByteCode = 0xa2
	LOG3 ByteCode = 0xa3
	LOG4 ByteCode = 0xa4

	// 0xd0 range - customized instructions
	Nop                   ByteCode = 0xd0
	AndSwap1PopSwap2Swap1 ByteCode = 0xd1
	Swap2Swap1PopJump     ByteCode = 0xd2
	Swap1PopSwap2Swap1    ByteCode = 0xd3
	PopSwap2Swap1Pop      ByteCode = 0xd4
	Push2Jump             ByteCode = 0xd5
	Push2JumpI            ByteCode = 0xd6
	Push1Push1            ByteCode = 0xd7
	Push1Add              ByteCode = 0xd8
	Push1Shl              ByteCode = 0xd9
	Push1Dup1             ByteCode = 0xda
	Swap1Pop              ByteCode = 0xdb
	PopJump               ByteCode = 0xdc
	Pop2                  ByteCode = 0xdd
	Swap2Swap1            ByteCode = 0xde
	Swap2Pop              ByteCode = 0xdf
	Dup2LT                ByteCode = 0xe0
	JumpIfZero            ByteCode = 0xe2

	// 0xf0 range - closures
	CREATE       ByteCode = 0xf0
	CALL         ByteCode = 0xf1
	CALLCODE     ByteCode = 0xf2
	RETURN       ByteCode = 0xf3
	DELEGATECALL ByteCode = 0xf4
	CREATE2      ByteCode = 0xf5

	STATICCALL   ByteCode = 0xfa
	REVERT       ByteCode = 0xfd
	INVALID      ByteCode = 0xfe
	SELFDESTRUCT ByteCode = 0xff

	// 0xb0 range
	TLOAD  ByteCode = 0xb3
	TSTORE ByteCode = 0xb4
)
