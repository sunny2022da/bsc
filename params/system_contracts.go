package params

import (
	"github.com/ethereum/go-ethereum/common"
)

// IsSystemContract reports whether addr is a BSC system contract address.
//
// We keep this helper in params to avoid import cycles between vm/consensus/systemcontracts.
// NOTE: This intentionally mirrors Parlia's allowlist semantics (exact address match),
// not a broad range check, to avoid accidentally classifying non-system addresses as system.
func IsSystemContract(addr common.Address) bool {
	switch addr {
	case common.HexToAddress("0x0000000000000000000000000000000000001000"), // ValidatorContract
		common.HexToAddress("0x0000000000000000000000000000000000001001"), // SlashContract
		common.HexToAddress("0x0000000000000000000000000000000000001002"), // SystemRewardContract
		common.HexToAddress("0x0000000000000000000000000000000000001003"), // LightClientContract
		common.HexToAddress("0x0000000000000000000000000000000000001004"), // TokenHubContract
		common.HexToAddress("0x0000000000000000000000000000000000001005"), // RelayerIncentivizeContract
		common.HexToAddress("0x0000000000000000000000000000000000001006"), // RelayerHubContract
		common.HexToAddress("0x0000000000000000000000000000000000001007"), // GovHubContract
		common.HexToAddress("0x0000000000000000000000000000000000001008"), // TokenManagerContract
		common.HexToAddress("0x0000000000000000000000000000000000002000"), // CrossChainContract
		common.HexToAddress("0x0000000000000000000000000000000000002001"), // StakingContract
		common.HexToAddress("0x0000000000000000000000000000000000002002"), // StakeHubContract
		common.HexToAddress("0x0000000000000000000000000000000000002003"), // StakeCreditContract
		common.HexToAddress("0x0000000000000000000000000000000000002004"), // GovernorContract
		common.HexToAddress("0x0000000000000000000000000000000000002005"), // GovTokenContract
		common.HexToAddress("0x0000000000000000000000000000000000002006"), // TimelockContract
		common.HexToAddress("0x0000000000000000000000000000000000003000"): // TokenRecoverPortalContract
		return true
	default:
		return false
	}
}
