package MIR

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// StateBackend is the minimal storage/refund/access-list surface needed for SLOAD/SSTORE gas accounting.
// Fullnode integration should wrap the real StateDB here.
type StateBackend interface {
	// Account/code/balance reads (needed for BALANCE/EXTCODE* and CALL/CREATE semantics)
	GetBalance(addr common.Address) common.Hash // 256-bit, big-endian in Hash
	GetBalanceU256(addr common.Address) *uint256.Int
	SetBalanceU256(addr common.Address, amount *uint256.Int)
	AddBalanceU256(addr common.Address, amount *uint256.Int)
	SubBalanceU256(addr common.Address, amount *uint256.Int)
	GetCode(addr common.Address) []byte
	GetCodeHash(addr common.Address) common.Hash
	GetCodeSize(addr common.Address) int
	Exists(addr common.Address) bool
	Empty(addr common.Address) bool
	HasSelfDestructed(addr common.Address) bool
	SelfDestruct(addr common.Address)

	GetState(addr common.Address, slot common.Hash) common.Hash
	GetCommittedState(addr common.Address, slot common.Hash) common.Hash
	SetState(addr common.Address, slot common.Hash, value common.Hash)

	AddRefund(gas uint64)
	SubRefund(gas uint64)
	GetRefund() uint64

	// Access list for EIP-2929 (warm/cold storage)
	AddressInAccessList(addr common.Address) bool
	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool)
	AddAddressToAccessList(addr common.Address)
	AddSlotToAccessList(addr common.Address, slot common.Hash)

	// Logs
	AddLog(addr common.Address, topics []common.Hash, data []byte, blockNumber uint64)

	Snapshot() int
	RevertToSnapshot(id int)
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

	selfDestructed map[[20]byte]bool

	// snapshots store coarse copies for Snapshot/RevertToSnapshot.
	snapshots []inMemorySnapshot

	logs []inMemoryLog // Journal of logs
}

type inMemorySnapshot struct {
	current        map[[52]byte]common.Hash
	committed      map[[52]byte]common.Hash
	refund         uint64
	addrWarm       map[[20]byte]bool
	access         map[[20]byte]map[[32]byte]bool
	balance        map[[20]byte]common.Hash
	code           map[[20]byte][]byte
	codeHash       map[[20]byte]common.Hash
	selfDestructed map[[20]byte]bool

	logs []inMemoryLog
}

// Define helper struct for in-memory logs
type inMemoryLog struct {
	Address     common.Address
	Topics      []common.Hash
	Data        []byte
	BlockNumber uint64
}

func NewInMemoryState() *InMemoryState {
	return &InMemoryState{
		current:        make(map[[52]byte]common.Hash),
		committed:      make(map[[52]byte]common.Hash),
		refund:         0,
		addrWarm:       make(map[[20]byte]bool, 64),
		access:         make(map[[20]byte]map[[32]byte]bool),
		balance:        make(map[[20]byte]common.Hash),
		code:           make(map[[20]byte][]byte),
		codeHash:       make(map[[20]byte]common.Hash),
		selfDestructed: make(map[[20]byte]bool, 16),
		snapshots:      nil,
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

func (s *InMemoryState) AddLog(addr common.Address, topics []common.Hash, data []byte, blockNumber uint64) {
	if s == nil {
		return
	}
	// Deep copy to be safe
	d := make([]byte, len(data))
	copy(d, data)
	t := make([]common.Hash, len(topics))
	copy(t, topics)

	s.logs = append(s.logs, inMemoryLog{
		Address:     addr,
		Topics:      t,
		Data:        d,
		BlockNumber: blockNumber,
	})
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

func (s *InMemoryState) GetBalanceU256(addr common.Address) *uint256.Int {
	h := s.GetBalance(addr)
	return uint256.NewInt(0).SetBytes(h[:])
}

func (s *InMemoryState) SetBalanceU256(addr common.Address, amount *uint256.Int) {
	if s == nil {
		return
	}
	if amount == nil {
		delete(s.balance, addrKey(addr))
		return
	}
	s.balance[addrKey(addr)] = common.Hash(amount.Bytes32())
}

func (s *InMemoryState) AddBalanceU256(addr common.Address, amount *uint256.Int) {
	if s == nil || amount == nil || amount.IsZero() {
		return
	}
	cur := s.GetBalanceU256(addr)
	cur.Add(cur, amount)
	s.SetBalanceU256(addr, cur)
}

func (s *InMemoryState) SubBalanceU256(addr common.Address, amount *uint256.Int) {
	if s == nil || amount == nil || amount.IsZero() {
		return
	}
	cur := s.GetBalanceU256(addr)
	cur.Sub(cur, amount)
	s.SetBalanceU256(addr, cur)
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

func (s *InMemoryState) HasSelfDestructed(addr common.Address) bool {
	if s == nil {
		return false
	}
	return s.selfDestructed[addrKey(addr)]
}

func (s *InMemoryState) SelfDestruct(addr common.Address) {
	if s == nil {
		return
	}
	s.selfDestructed[addrKey(addr)] = true
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

func (s *InMemoryState) GetRefund() uint64 {
	if s == nil {
		return 0
	}
	return s.refund
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

func (s *InMemoryState) Snapshot() int {
	if s == nil {
		return 0
	}
	// Deep-ish copy; good enough for tests/tools.
	snap := inMemorySnapshot{
		current:        make(map[[52]byte]common.Hash, len(s.current)),
		committed:      make(map[[52]byte]common.Hash, len(s.committed)),
		refund:         s.refund,
		addrWarm:       make(map[[20]byte]bool, len(s.addrWarm)),
		access:         make(map[[20]byte]map[[32]byte]bool, len(s.access)),
		balance:        make(map[[20]byte]common.Hash, len(s.balance)),
		code:           make(map[[20]byte][]byte, len(s.code)),
		codeHash:       make(map[[20]byte]common.Hash, len(s.codeHash)),
		selfDestructed: make(map[[20]byte]bool, len(s.selfDestructed)),
		logs:           make([]inMemoryLog, len(s.logs)),
	}
	for k, v := range s.current {
		snap.current[k] = v
	}
	for k, v := range s.committed {
		snap.committed[k] = v
	}
	for k, v := range s.addrWarm {
		snap.addrWarm[k] = v
	}
	for ak, m := range s.access {
		cp := make(map[[32]byte]bool, len(m))
		for sk, sv := range m {
			cp[sk] = sv
		}
		snap.access[ak] = cp
	}
	for k, v := range s.balance {
		snap.balance[k] = v
	}
	for k, v := range s.code {
		cp := make([]byte, len(v))
		copy(cp, v)
		snap.code[k] = cp
	}
	for k, v := range s.codeHash {
		snap.codeHash[k] = v
	}
	for k, v := range s.selfDestructed {
		snap.selfDestructed[k] = v
	}

	// Copy logs
	copy(snap.logs, s.logs)

	s.snapshots = append(s.snapshots, snap)
	return len(s.snapshots) - 1
}

func (s *InMemoryState) RevertToSnapshot(id int) {
	if s == nil {
		return
	}
	if id < 0 || id >= len(s.snapshots) {
		return
	}
	snap := s.snapshots[id]
	s.current = snap.current
	s.committed = snap.committed
	s.refund = snap.refund
	s.addrWarm = snap.addrWarm
	s.access = snap.access
	s.balance = snap.balance
	s.code = snap.code
	s.codeHash = snap.codeHash
	s.selfDestructed = snap.selfDestructed
	s.logs = snap.logs // Restore log slice (truncating newer logs)

	s.snapshots = s.snapshots[:id]
}
