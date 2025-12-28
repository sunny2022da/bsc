package MIR

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// StateDBBackend adapts a geth vm.StateDB into the MIR StateBackend interface.
// This is the "full StateDB integration" path for MIR execution inside a fullnode.
type StateDBBackend struct {
	db vm.StateDB
}

func NewStateDBBackend(db vm.StateDB) *StateDBBackend {
	return &StateDBBackend{db: db}
}

func (b *StateDBBackend) GetBalance(addr common.Address) common.Hash {
	if b == nil || b.db == nil {
		return common.Hash{}
	}
	u := b.db.GetBalance(addr)
	if u == nil {
		return common.Hash{}
	}
	return common.Hash(u.Bytes32())
}

func (b *StateDBBackend) GetBalanceU256(addr common.Address) *uint256.Int {
	if b == nil || b.db == nil {
		return uint256.NewInt(0)
	}
	u := b.db.GetBalance(addr)
	if u == nil {
		return uint256.NewInt(0)
	}
	return uint256.NewInt(0).Set(u)
}

func (b *StateDBBackend) SetBalanceU256(addr common.Address, amount *uint256.Int) {
	if b == nil || b.db == nil {
		return
	}
	if amount == nil {
		amount = uint256.NewInt(0)
	}
	b.db.SetBalance(addr, amount, tracing.BalanceChangeUnspecified)
}

func (b *StateDBBackend) AddBalanceU256(addr common.Address, amount *uint256.Int) {
	if b == nil || b.db == nil || amount == nil || amount.IsZero() {
		return
	}
	b.db.AddBalance(addr, amount, tracing.BalanceIncreaseSelfdestruct)
}

func (b *StateDBBackend) SubBalanceU256(addr common.Address, amount *uint256.Int) {
	if b == nil || b.db == nil || amount == nil || amount.IsZero() {
		return
	}
	b.db.SubBalance(addr, amount, tracing.BalanceDecreaseSelfdestruct)
}

func (b *StateDBBackend) GetCode(addr common.Address) []byte {
	if b == nil || b.db == nil {
		return nil
	}
	return b.db.GetCode(addr)
}

func (b *StateDBBackend) GetCodeHash(addr common.Address) common.Hash {
	if b == nil || b.db == nil {
		return common.Hash{}
	}
	return b.db.GetCodeHash(addr)
}

func (b *StateDBBackend) GetCodeSize(addr common.Address) int {
	if b == nil || b.db == nil {
		return 0
	}
	return b.db.GetCodeSize(addr)
}

func (b *StateDBBackend) Exists(addr common.Address) bool {
	if b == nil || b.db == nil {
		return false
	}
	return b.db.Exist(addr)
}

func (b *StateDBBackend) Empty(addr common.Address) bool {
	if b == nil || b.db == nil {
		return true
	}
	return b.db.Empty(addr)
}

func (b *StateDBBackend) HasSelfDestructed(addr common.Address) bool {
	if b == nil || b.db == nil {
		return false
	}
	return b.db.HasSelfDestructed(addr)
}

func (b *StateDBBackend) SelfDestruct(addr common.Address) {
	if b == nil || b.db == nil {
		return
	}
	b.db.SelfDestruct(addr)
}

func (b *StateDBBackend) GetState(addr common.Address, slot common.Hash) common.Hash {
	if b == nil || b.db == nil {
		return common.Hash{}
	}
	return b.db.GetState(addr, slot)
}

func (b *StateDBBackend) GetCommittedState(addr common.Address, slot common.Hash) common.Hash {
	if b == nil || b.db == nil {
		return common.Hash{}
	}
	return b.db.GetCommittedState(addr, slot)
}

func (b *StateDBBackend) SetState(addr common.Address, slot common.Hash, value common.Hash) {
	if b == nil || b.db == nil {
		return
	}
	b.db.SetState(addr, slot, value)
}

func (b *StateDBBackend) AddRefund(gas uint64) {
	if b == nil || b.db == nil {
		return
	}
	b.db.AddRefund(gas)
}

func (b *StateDBBackend) SubRefund(gas uint64) {
	if b == nil || b.db == nil {
		return
	}
	b.db.SubRefund(gas)
}

func (b *StateDBBackend) GetRefund() uint64 {
	if b == nil || b.db == nil {
		return 0
	}
	return b.db.GetRefund()
}

func (b *StateDBBackend) AddressInAccessList(addr common.Address) bool {
	if b == nil || b.db == nil {
		return false
	}
	return b.db.AddressInAccessList(addr)
}

func (b *StateDBBackend) SlotInAccessList(addr common.Address, slot common.Hash) (bool, bool) {
	if b == nil || b.db == nil {
		return false, false
	}
	return b.db.SlotInAccessList(addr, slot)
}

func (b *StateDBBackend) AddAddressToAccessList(addr common.Address) {
	if b == nil || b.db == nil {
		return
	}
	b.db.AddAddressToAccessList(addr)
}

func (b *StateDBBackend) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	if b == nil || b.db == nil {
		return
	}
	b.db.AddSlotToAccessList(addr, slot)
}

func (b *StateDBBackend) Snapshot() int {
	if b == nil || b.db == nil {
		return 0
	}
	return b.db.Snapshot()
}

func (b *StateDBBackend) RevertToSnapshot(id int) {
	if b == nil || b.db == nil {
		return
	}
	b.db.RevertToSnapshot(id)
}

// Helpers for fullnode integrations that want to move balances during SELFDESTRUCT.
// Not part of StateBackend yet; call sites that need it should use vm.StateDB directly.
func (b *StateDBBackend) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	if b == nil || b.db == nil {
		return *uint256.NewInt(0)
	}
	return b.db.AddBalance(addr, amount, reason)
}


