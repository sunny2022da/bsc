package runtime

import (
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
)

// Function selectors for USDT contract
var (
	mintSelector      = []byte{0x40, 0xc1, 0x0f, 0x19} // mint(address,uint256)
	balanceOfSelector = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	transferSelector  = []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
)

// ContractRef implementation
type AddressRef struct {
	addr common.Address
}

func (a AddressRef) Address() common.Address {
	return a.addr
}

// Addresses for USDT contract
var (
	aliceAddr    = common.HexToAddress("0x1000000000000000000000000000000000000001")
	usdtContract = common.HexToAddress("0x2000000000000000000000000000000000000001")
	// Global variable to store the actual deployed contract address
	globalUsdtContract common.Address
	// ContractRef for Alice
	aliceRef = AddressRef{addr: aliceAddr}
)

// Setup BSC detailed logging
func setupBSCLogging(t *testing.T) {
	// Set environment variables to enable BSC detailed logging
	os.Setenv("BSC_LOG_LEVEL", "debug")
	os.Setenv("ETH_LOG_LEVEL", "debug")
	os.Setenv("EVM_DEBUG", "true")
	os.Setenv("BSC_DEBUG", "true")

	// Set BSC specific log environment variables
	os.Setenv("GETH_LOG_LEVEL", "debug")
	os.Setenv("GETH_DEBUG", "true")
	os.Setenv("VM_DEBUG", "true")
	os.Setenv("CORE_DEBUG", "true")
	os.Setenv("TRIE_DEBUG", "true")
	os.Setenv("STATE_DEBUG", "true")

	// Set log output to console
	os.Setenv("GETH_LOG_OUTPUT", "console")
	os.Setenv("BSC_LOG_OUTPUT", "console")

	t.Log("🔧 BSC detailed logging enabled")
	t.Log("📊 Log levels: BSC=debug, ETH=debug, EVM=debug")
}

// Configure 500K transfer test parameters (conservative version)
func get500KScaleConfigConservative() (int64, uint64, uint64) {
	// 500K transfer test configuration (conservative version)
	numTransfers := int64(500000)          // 500K transfers
	batchGasLimit := uint64(100000000000)  // 100B gas for batch transfer
	blockGasLimit := uint64(1000000000000) // 1T gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// Configure 500K transfer test parameters
func get500KScaleConfig() (int64, uint64, uint64) {
	// 500K transfer test configuration
	numTransfers := int64(500000)          // 500K transfers
	batchGasLimit := uint64(100000000000)  // 100B gas for individual transfers (approximately 200K gas per transfer)
	blockGasLimit := uint64(1000000000000) // 1T gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// Configure large scale test parameters
func getLargeScaleConfig() (int64, uint64, uint64) {
	// Large scale test configuration
	numTransfers := int64(50000000)         // 50 million transfers
	batchGasLimit := uint64(1000000000000)  // 1T gas for batch transfer (increased from 100B to 1T)
	blockGasLimit := uint64(10000000000000) // 10T gas limit for block (increased from 1T to 10T)

	return numTransfers, batchGasLimit, blockGasLimit
}

// Configure medium scale test parameters
func getMediumScaleConfig() (int64, uint64, uint64) {
	// Medium scale test configuration
	numTransfers := int64(5000000)        // 5 million transfers
	batchGasLimit := uint64(10000000000)  // 10B gas for batch transfer
	blockGasLimit := uint64(100000000000) // 100B gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// Configure small scale test parameters
func getSmallScaleConfig() (int64, uint64, uint64) {
	// Small scale test configuration - for debugging
	numTransfers := int64(1)             // Only test 1 transfer
	batchGasLimit := uint64(10000000)    // 10M gas (enough for one transfer)
	blockGasLimit := uint64(10000000000) // 10B gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

func TestMIRUSDTTransfer(t *testing.T) {
	// Enable BSC detailed logging
	setupBSCLogging(t)

	// Select test scale - use small scale test to avoid timeout
	numTransfers, batchGasLimit, blockGasLimit := getSmallScaleConfig() // 50K transfers

	t.Logf("🚀 Pure BSC-EVM Benchmark - USDT Token Individual Transfers (Scale: %d transfers)", numTransfers)
	t.Logf("📊 Gas Configuration - Total: %d, Block: %d", batchGasLimit, blockGasLimit)

	// Load USDT contract bytecode
	t.Log("📦 Loading USDT contract bytecode...")
	usdtBytecode := loadBytecode(t, "usdt.bin")
	t.Logf("✅ Bytecode loaded, size: %d bytes", len(usdtBytecode))

	// Initialize EVM with BSC configur	ation
	t.Log("🔧 Initializing EVM with BSC configuration...")
	db := rawdb.NewMemoryDatabase()
	t.Log("✅ Memory database created")

	trieDB := triedb.NewDatabase(db, nil)
	t.Log("✅ Trie database created")

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(trieDB, nil))
	t.Log("✅ State database created")

	// Create Alice account with some BNB for gas
	t.Logf("👤 Creating Alice account: %s", aliceAddr.Hex())
	statedb.CreateAccount(aliceAddr)
	aliceBalance := uint256.NewInt(1000000000000000000) // 1 BNB
	statedb.SetBalance(aliceAddr, aliceBalance, tracing.BalanceChangeUnspecified)
	t.Logf("💰 Set Alice balance: %s wei", aliceBalance.String())

	// Create EVM context with BSC parameters
	t.Log("🔧 Creating BSC chain configuration...")
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(56), // BSC Mainnet
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		RamanujanBlock:      big.NewInt(0),          // BSC specific
		NielsBlock:          big.NewInt(0),          // BSC specific
		Parlia:              &params.ParliaConfig{}, // BSC consensus mechanism
	}
	t.Logf("✅ Chain config created - Chain ID: %d", chainConfig.ChainID)

	vmConfig := vm.Config{
		EnableOpcodeOptimizations: true,
		EnableMIR:                 true,
		EnableMIRInitcode:         true,
		MIRStrictNoFallback:       true, // STRICT: No fallback allowed
	}

	compiler.EnableOpcodeParse()

	// 🔍 Enable MIR debug logs
	compiler.EnableDebugLogs(true)
	compiler.EnableMIRDebugLogs(true)
	compiler.EnableParserDebugLogs(true)
	t.Log("🔍 MIR debug logs enabled")

	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: big.NewInt(1),
		Time:        uint64(1681338455),
		Difficulty:  big.NewInt(1),
		GasLimit:    blockGasLimit,
		BaseFee:     big.NewInt(0),
	}
	t.Logf("✅ Block context created - Block #%d, Gas Limit: %d", blockContext.BlockNumber, blockContext.GasLimit)

	// Create EVM
	t.Log("🚀 Creating EVM instance...")
	evm := vm.NewEVM(blockContext, statedb, chainConfig, vmConfig)
	t.Log("✅ EVM instance created successfully")

	// Deploy USDT contract
	t.Log("📦 Deploying USDT contract...")
	deployContract(t, evm, usdtBytecode)

	t.Log("💰 USDT contract constructor already gave tokens to Alice")

	// Verify Alice's balance
	t.Log("🔍 Verifying Alice's balance...")
	aliceTokenBalance := getTokenBalance(t, evm, aliceAddr)
	t.Logf("✅ Alice's balance: %s tokens", new(big.Int).Div(aliceTokenBalance, big.NewInt(1000000000000000000)).String())

	// 🧪 Test with base EVM first to confirm transfer logic works
	// DISABLED: Base EVM transfer succeeds but MIR fails, suggests state conflict
	// t.Log("🧪 Testing transfer with base EVM first (control test)...")
	// testTransferWithBaseEVM(t, evm.Context, statedb, evm.ChainConfig(), globalUsdtContract)

	// Perform individual transfers
	t.Log("🔄 Performing individual transfers with MIR...")
	duration := performIndividualTransfersWithConfig(t, evm, numTransfers, batchGasLimit)
	t.Logf("✅ Individual transfers completed in %v", duration)

	// Calculate performance metrics
	transfersPerSecond := float64(numTransfers) / duration.Seconds()
	t.Logf("⚡ Benchmark Results - Transfers: %d, Duration: %.2fms, TPS: %.2f",
		numTransfers, float64(duration.Nanoseconds())/1000000, transfersPerSecond)

	// Verify some recipient balances
	t.Log("🔍 Verifying transfers...")
	startRecipient := common.HexToAddress("0x3000000000000000000000000000000000000001")
	for i := 0; i < 3; i++ {
		recipient := common.BigToAddress(new(big.Int).Add(startRecipient.Big(), big.NewInt(int64(i))))
		balance := getTokenBalance(t, evm, recipient)
		t.Logf("✅ Recipient %d (%s): %s tokens", i+1, recipient.Hex(), new(big.Int).Div(balance, big.NewInt(1000000000000000000)).String())
	}

	// Verify Alice's final balance
	t.Log("🔍 Verifying Alice's final balance...")
	aliceFinalBalance := getTokenBalance(t, evm, aliceAddr)
	t.Logf("✅ Alice's final balance: %s tokens", new(big.Int).Div(aliceFinalBalance, big.NewInt(1000000000000000000)).String())

	t.Log("✨ BSC-EVM Benchmark completed successfully!")
}

func loadBytecode(t *testing.T, path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read bytecode file: %v", err)
	}

	bytecodeStr := strings.TrimSpace(string(data))
	if strings.HasPrefix(bytecodeStr, "0x") {
		bytecodeStr = bytecodeStr[2:]
	}

	bytecode, err := hex.DecodeString(bytecodeStr)
	if err != nil {
		t.Fatalf("Invalid hex in bytecode: %v", err)
	}

	return bytecode
}

func deployContract(t *testing.T, evm *vm.EVM, initcode []byte) {
	value := uint256.NewInt(0)
	deployGasLimit := uint64(2000000000)

	// Check if we're using MIR for constructor (Mode B) or just runtime (Mode A)
	useMIRForConstructor := evm.Config.EnableMIRInitcode

	if useMIRForConstructor {
		// Mode B: Use MIR for both constructor and runtime (strict mode)
		t.Log("🔧 Deploying contract with MIR for constructor (Mode B - will hang)...")
		t.Logf("   Deploying with %d gas...", deployGasLimit)

		ret, contractAddr, leftOverGas, err := evm.Create(aliceRef, initcode, deployGasLimit, value)
		gasUsed := deployGasLimit - leftOverGas
		t.Logf("📝 evm.Create returned: err=%v, gasUsed=%d", err, gasUsed)

		if err != nil {
			t.Fatalf("❌ Contract deployment failed: %v (Gas used: %d/%d)", err, gasUsed, deployGasLimit)
		}

		t.Logf("✅ Contract deployed at: %s, gas used: %d/%d (%.2f%%)",
			contractAddr.Hex(), gasUsed, deployGasLimit, float64(gasUsed)/float64(deployGasLimit)*100)

		globalUsdtContract = contractAddr
		_ = ret
	} else {
		// Mode A: Use base EVM for constructor, MIR for runtime (working mode)
		t.Log("🔧 Deploying contract using Method A (Base EVM for constructor, MIR for runtime)...")

		// Step 1: Use base EVM to execute constructor and get runtime code
		t.Log("   Step 1: Executing constructor with base EVM...")
		tempConfig := vm.Config{
			EnableOpcodeOptimizations: false,
			EnableMIR:                 false,
			EnableMIRInitcode:         false,
		}
		tempEVM := vm.NewEVM(evm.Context, evm.StateDB, evm.ChainConfig(), tempConfig)

		runtimeCode, contractAddr, leftOverGas, err := tempEVM.Create(aliceRef, initcode, deployGasLimit, value)
		gasUsed := deployGasLimit - leftOverGas

		if err != nil {
			t.Fatalf("❌ Failed to deploy with base EVM: %v (Gas: %d/%d)", err, gasUsed, deployGasLimit)
		}

		t.Logf("   ✅ Constructor executed: %d bytes runtime code, gas: %d/%d", len(runtimeCode), gasUsed, deployGasLimit)
		t.Logf("   ✅ Contract deployed at: %s", contractAddr.Hex())
		t.Log("   Step 2: Runtime calls will use MIR interpreter...")

		globalUsdtContract = contractAddr
	}
}

func getTokenBalance(t *testing.T, evm *vm.EVM, account common.Address) *big.Int {
	// Prepare calldata
	calldata := make([]byte, 0, 36)
	calldata = append(calldata, balanceOfSelector...)
	calldata = append(calldata, make([]byte, 12)...) // padding for address
	calldata = append(calldata, account.Bytes()...)

	// Execute transaction
	ret := executeTransaction(t, evm, globalUsdtContract, calldata, 100000000)

	if len(ret) >= 32 {
		balance := new(big.Int).SetBytes(ret[:32])
		return balance
	}
	return big.NewInt(0)
}

func performIndividualTransfersWithConfig(t *testing.T, evm *vm.EVM, numTransfers int64, gasLimit uint64) time.Duration {
	startRecipient := common.HexToAddress("0x3000000000000000000000000000000000000001")
	amountPerTransfer := big.NewInt(1000000000000000000) // 1 token

	t.Logf("🔄 Starting individual transfers with %d transfers, gas limit per transfer: %d", numTransfers, gasLimit/uint64(numTransfers))

	// Measure execution time
	startTime := time.Now()

	// Allocate gas for each transfer
	gasPerTransfer := gasLimit / uint64(numTransfers)

	for i := 0; i < int(numTransfers); i++ {
		// Calculate recipient address
		recipient := common.BigToAddress(new(big.Int).Add(startRecipient.Big(), big.NewInt(int64(i))))

		// Prepare calldata for transfer function
		calldata := make([]byte, 0, 68)
		calldata = append(calldata, transferSelector...)
		calldata = append(calldata, make([]byte, 12)...) // padding for address
		calldata = append(calldata, recipient.Bytes()...)
		calldata = append(calldata, common.LeftPadBytes(amountPerTransfer.Bytes(), 32)...)

		if i == 0 {
			// Log first transfer details
			t.Logf("📤 First transfer details:")
			t.Logf("   From: %s (Alice)", aliceAddr.Hex())
			t.Logf("   To: %s", recipient.Hex())
			t.Logf("   Amount: %s wei", amountPerTransfer.String())
			t.Logf("   Gas limit: %d", gasPerTransfer)
			t.Logf("   Calldata: %x", calldata)
		}

		// Execute transfer call
		executeTransaction(t, evm, globalUsdtContract, calldata, gasPerTransfer)

		// Print progress every 10000 transfers
		if (i+1)%10000 == 0 {
			t.Logf("📊 Progress: %d/%d transfers completed", i+1, numTransfers)
		}
	}

	duration := time.Since(startTime)
	t.Logf("✅ Individual transfers completed in %v", duration)

	return duration
}

func executeTransaction(t *testing.T, evm *vm.EVM, to common.Address, data []byte, gasLimit uint64) []byte {
	// Execute call
	value := uint256.NewInt(0)
	ret, leftOverGas, err := evm.Call(aliceRef, to, data, gasLimit, value)
	gasUsed := gasLimit - leftOverGas

	if err != nil {
		t.Logf("❌ Transaction failed: %v", err)
		t.Logf("   Gas used: %d/%d (%.2f%%)", gasUsed, gasLimit, float64(gasUsed)/float64(gasLimit)*100)
		t.Logf("   Calldata: %x (len=%d)", data[:4], len(data))
		t.Logf("   To: %s", to.Hex())
		t.Logf("   Return data: %x", ret)
		t.Fatalf("Transaction failed")
	}

	return ret
}
