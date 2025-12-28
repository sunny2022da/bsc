package MIR

import "github.com/ethereum/go-ethereum/common"

// StateBackend is the minimal storage/refund/access-list surface needed for SLOAD/SSTORE gas accounting.
// Fullnode integration should wrap the real StateDB here.
type StateBackend interface {
	// Account/code/balance reads (needed for BALANCE/EXTCODE* and CALL/CREATE semantics)
	GetBalance(addr common.Address) common.Hash // 256-bit, big-endian in Hash
	GetCode(addr common.Address) []byte
	GetCodeHash(addr common.Address) common.Hash
	GetCodeSize(addr common.Address) int
	Exists(addr common.Address) bool
	Empty(addr common.Address) bool

	GetState(addr common.Address, slot common.Hash) common.Hash
	GetCommittedState(addr common.Address, slot common.Hash) common.Hash
	SetState(addr common.Address, slot common.Hash, value common.Hash)

	AddRefund(gas uint64)
	SubRefund(gas uint64)

	// Access list for EIP-2929 (warm/cold storage)
	AddressInAccessList(addr common.Address) bool
	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool)
	AddAddressToAccessList(addr common.Address)
	AddSlotToAccessList(addr common.Address, slot common.Hash)
}

// InMemoryState is a minimal in-process backend for tests and tools.
// It models current+committed storage, refund counter, and a per-address access list.
type InMemoryState struct {
	current   map[[52]byte]common.Hash
	committed map[[52]byte]common.Hash
	refund    uint64
	addrWarm  map[[20]byte]bool
	access    map[[20]byte]map[[32]byte]bool

	balance  map[[20]byte]common.Hash
	code     map[[20]byte][]byte
	codeHash map[[20]byte]common.Hash
}

func NewInMemoryState() *InMemoryState {
	return &InMemoryState{
		current:   make(map[[52]byte]common.Hash),
		committed: make(map[[52]byte]common.Hash),
		refund:    0,
		addrWarm:  make(map[[20]byte]bool, 64),
		access:    make(map[[20]byte]map[[32]byte]bool),
		balance:   make(map[[20]byte]common.Hash),
		code:      make(map[[20]byte][]byte),
		codeHash:  make(map[[20]byte]common.Hash),
	}
}

func storageKey(addr common.Address, slot common.Hash) (k [52]byte) {
	copy(k[:20], addr[:])
	copy(k[20:], slot[:])
	return k
}

func addrKey(addr common.Address) (k [20]byte) {
	copy(k[:], addr[:])
	return k
}

func slotKey(slot common.Hash) (k [32]byte) {
	copy(k[:], slot[:])
	return k
}

func (s *InMemoryState) GetState(addr common.Address, slot common.Hash) common.Hash {
	if s == nil {
		return common.Hash{}
	}
	if v, ok := s.current[storageKey(addr, slot)]; ok {
		return v
	}
	return common.Hash{}
}

func (s *InMemoryState) GetBalance(addr common.Address) common.Hash {
	if s == nil {
		return common.Hash{}
	}
	if v, ok := s.balance[addrKey(addr)]; ok {
		return v
	}
	return common.Hash{}
}

func (s *InMemoryState) GetCode(addr common.Address) []byte {
	if s == nil {
		return nil
	}
	if b, ok := s.code[addrKey(addr)]; ok {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	return nil
}

func (s *InMemoryState) GetCodeHash(addr common.Address) common.Hash {
	if s == nil {
		return common.Hash{}
	}
	if h, ok := s.codeHash[addrKey(addr)]; ok {
		return h
	}
	return common.Hash{}
}

func (s *InMemoryState) GetCodeSize(addr common.Address) int {
	if s == nil {
		return 0
	}
	if b, ok := s.code[addrKey(addr)]; ok {
		return len(b)
	}
	return 0
}

func (s *InMemoryState) Exists(addr common.Address) bool {
	if s == nil {
		return false
	}
	ak := addrKey(addr)
	if _, ok := s.code[ak]; ok {
		return true
	}
	if _, ok := s.balance[ak]; ok {
		return true
	}
	for k := range s.current {
		var a [20]byte
		copy(a[:], k[:20])
		if a == ak {
			return true
		}
	}
	return false
}

func (s *InMemoryState) Empty(addr common.Address) bool {
	// Rough approximation: empty if no code and zero balance.
	if s == nil {
		return true
	}
	if s.GetCodeSize(addr) != 0 {
		return false
	}
	return s.GetBalance(addr) == (common.Hash{})
}

func (s *InMemoryState) GetCommittedState(addr common.Address, slot common.Hash) common.Hash {
	if s == nil {
		return common.Hash{}
	}
	if v, ok := s.committed[storageKey(addr, slot)]; ok {
		return v
	}
	return common.Hash{}
}

func (s *InMemoryState) SetState(addr common.Address, slot common.Hash, value common.Hash) {
	if s == nil {
		return
	}
	s.current[storageKey(addr, slot)] = value
}

func (s *InMemoryState) AddRefund(gas uint64) {
	if s == nil || gas == 0 {
		return
	}
	s.refund += gas
}

func (s *InMemoryState) SubRefund(gas uint64) {
	if s == nil || gas == 0 {
		return
	}
	if gas >= s.refund {
		s.refund = 0
		return
	}
	s.refund -= gas
}

func (s *InMemoryState) AddressInAccessList(addr common.Address) bool {
	if s == nil {
		return false
	}
	return s.addrWarm[addrKey(addr)]
}

func (s *InMemoryState) SlotInAccessList(addr common.Address, slot common.Hash) (bool, bool) {
	if s == nil {
		return false, false
	}
	ak := addrKey(addr)
	m, ok := s.access[ak]
	if !ok {
		return false, false
	}
	return true, m[slotKey(slot)]
}

func (s *InMemoryState) AddAddressToAccessList(addr common.Address) {
	if s == nil {
		return
	}
	s.addrWarm[addrKey(addr)] = true
}

func (s *InMemoryState) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	if s == nil {
		return
	}
	ak := addrKey(addr)
	m, ok := s.access[ak]
	if !ok {
		m = make(map[[32]byte]bool, 32)
		s.access[ak] = m
	}
	m[slotKey(slot)] = true
}
