package runtime

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"

	// "github.com/ethereum/go-ethereum/core/opcodeCompiler/compiler"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"

	// ethlog "github.com/ethereum/go-ethereum/log"
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
	// 全局变量存储实际部署的合约地址
	globalUsdtContract common.Address
	// ContractRef for Alice
	aliceRef = AddressRef{addr: aliceAddr}
)

// 设置BSC详细日志
func setupBSCLogging() {
	// 设置环境变量启用BSC的详细日志
	os.Setenv("BSC_LOG_LEVEL", "debug")
	os.Setenv("ETH_LOG_LEVEL", "debug")
	os.Setenv("EVM_DEBUG", "true")
	os.Setenv("BSC_DEBUG", "true")

	// 设置Go标准库日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	// 设置BSC特定的日志环境变量
	os.Setenv("GETH_LOG_LEVEL", "debug")
	os.Setenv("GETH_DEBUG", "true")
	os.Setenv("VM_DEBUG", "true")
	os.Setenv("CORE_DEBUG", "true")
	os.Setenv("TRIE_DEBUG", "true")
	os.Setenv("STATE_DEBUG", "true")

	// 设置日志输出到控制台
	os.Setenv("GETH_LOG_OUTPUT", "console")
	os.Setenv("BSC_LOG_OUTPUT", "console")

	fmt.Println("🔧 BSC detailed logging enabled")
	fmt.Println("📊 Log levels: BSC=debug, ETH=debug, EVM=debug")
}

// 配置50万次转账测试参数（保守版本）
func get500KScaleConfigConservative() (int64, uint64, uint64) {
	// 50万次转账测试配置（保守版本）
	numTransfers := int64(500000)          // 50万次转账
	batchGasLimit := uint64(100000000000)  // 100B gas for batch transfer
	blockGasLimit := uint64(1000000000000) // 1T gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// 配置50万次转账测试参数
func get500KScaleConfig() (int64, uint64, uint64) {
	// 50万次转账测试配置
	numTransfers := int64(500000)          // 50万次转账
	batchGasLimit := uint64(100000000000)  // 100B gas for individual transfers (每次转账约200K gas)
	blockGasLimit := uint64(1000000000000) // 1T gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// 配置大规模测试参数
func getLargeScaleConfig() (int64, uint64, uint64) {
	// 大规模测试配置
	numTransfers := int64(50000000)         // 5000万次转账
	batchGasLimit := uint64(1000000000000)  // 1T gas for batch transfer (从100B增加到1T)
	blockGasLimit := uint64(10000000000000) // 10T gas limit for block (从1T增加到10T)

	return numTransfers, batchGasLimit, blockGasLimit
}

// 配置中等规模测试参数
func getMediumScaleConfig() (int64, uint64, uint64) {
	// 中等规模测试配置
	numTransfers := int64(5000000)        // 500万次转账
	batchGasLimit := uint64(10000000000)  // 10B gas for batch transfer
	blockGasLimit := uint64(100000000000) // 100B gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

// 配置小规模测试参数
func getSmallScaleConfig() (int64, uint64, uint64) {
	// 小规模测试配置
	numTransfers := int64(50000)         // 5万次转账
	batchGasLimit := uint64(2000000000)  // 2B gas for batch transfer
	blockGasLimit := uint64(10000000000) // 10B gas limit for block

	return numTransfers, batchGasLimit, blockGasLimit
}

func main() {
	// 启用BSC详细日志
	setupBSCLogging()

	// 选择测试规模 - 使用50万次转账
	// numTransfers, batchGasLimit, blockGasLimit := getSmallScaleConfig()    // 5万次转账
	// numTransfers, batchGasLimit, blockGasLimit := getMediumScaleConfig()   // 500万次转账
	// numTransfers, batchGasLimit, blockGasLimit := getLargeScaleConfig()    // 5000万次转账
	numTransfers, batchGasLimit, blockGasLimit := get500KScaleConfig() // 50万次转账
	// 如果上面的配置仍然出现gas不足，可以尝试保守配置：
	// numTransfers, batchGasLimit, blockGasLimit := get500KScaleConfigConservative() // 50万次转账（保守版本）

	fmt.Printf("🚀 Pure BSC-EVM Benchmark - USDT Token Individual Transfers (Scale: %d transfers)\n", numTransfers)
	fmt.Printf("📊 Gas Configuration - Total: %d, Block: %d\n", batchGasLimit, blockGasLimit)

	// Load USDT contract bytecode
	log.Println("📦 Loading USDT contract bytecode...")
	usdtBytecode := loadBytecode("usdt.bin")
	log.Printf("✅ Bytecode loaded, size: %d bytes", len(usdtBytecode))

	// Initialize EVM with BSC configuration
	log.Println("🔧 Initializing EVM with BSC configuration...")
	db := rawdb.NewMemoryDatabase()
	log.Println("✅ Memory database created")

	trieDB := triedb.NewDatabase(db, nil)
	log.Println("✅ Trie database created")

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(trieDB, nil))
	log.Println("✅ State database created")

	// Create Alice account with some BNB for gas
	log.Printf("👤 Creating Alice account: %s", aliceAddr.Hex())
	statedb.CreateAccount(aliceAddr)
	aliceBalance := uint256.NewInt(1000000000000000000) // 1 BNB
	statedb.SetBalance(aliceAddr, aliceBalance, tracing.BalanceChangeUnspecified)
	log.Printf("💰 Set Alice balance: %s wei", aliceBalance.String())

	// Create EVM context with BSC parameters
	log.Println("🔧 Creating BSC chain configuration...")
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
		RamanujanBlock:      big.NewInt(0),          // BSC特有
		NielsBlock:          big.NewInt(0),          // BSC特有
		Parlia:              &params.ParliaConfig{}, // BSC的共识机制
	}
	log.Printf("✅ Chain config created - Chain ID: %d", chainConfig.ChainID)

	vmConfig := vm.Config{
		EnableOpcodeOptimizations: true,
		// ✅ Runtime 优先使用 MIR
		EnableMIR:           true,
		EnableMIRInitcode:   true,
		MIRStrictNoFallback: true,
	}
	log.Println("✅ EVM configuration created (MIR runtime with fallback, Constructor uses base EVM)")

	// ⚠️ 暂时也禁用 OpcodeParse 来排查问题
	compiler.EnableOpcodeParse()

	// 🔍 启用 MIR 调试日志
	compiler.EnableDebugLogs(true)
	compiler.EnableMIRDebugLogs(true)
	compiler.EnableParserDebugLogs(true)
	log.Println("🔍 MIR debug logs enabled")

	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: big.NewInt(1),
		Time:        uint64(1681338455), // Set to a time after Shanghai activation
		Difficulty:  big.NewInt(1),
		GasLimit:    blockGasLimit, // 使用配置的gas限制
		BaseFee:     big.NewInt(0), // BSC has 0 base fee
	}
	log.Printf("✅ Block context created - Block #%d, Gas Limit: %d", blockContext.BlockNumber, blockContext.GasLimit)

	// Create EVM
	log.Println("🚀 Creating EVM instance...")
	evm := vm.NewEVM(blockContext, statedb, chainConfig, vmConfig)
	log.Println("✅ EVM instance created successfully")

	// Deploy USDT contract
	fmt.Println("📦 Deploying USDT contract...")
	log.Println("📦 Starting USDT contract deployment...")
	deployContract(evm, usdtBytecode)

	// USDT合约构造函数已经给了Alice足够的代币，不需要再mint
	fmt.Println("💰 USDT contract constructor already gave tokens to Alice...")
	log.Println("💰 USDT contract constructor already gave tokens to Alice")

	// Verify Alice's balance
	log.Println("🔍 Verifying Alice's balance...")
	aliceTokenBalance := getTokenBalance(evm, aliceAddr)
	fmt.Printf("✅ Alice's balance: %s tokens\n", new(big.Int).Div(aliceTokenBalance, big.NewInt(1000000000000000000)).String())
	log.Printf("✅ Alice's verified balance: %s tokens", new(big.Int).Div(aliceTokenBalance, big.NewInt(1000000000000000000)).String())

	// Perform individual transfers (50万次单独转账)
	fmt.Println("🔄 Performing individual transfers...")
	log.Println("🔄 Starting individual transfers...")
	duration := performIndividualTransfersWithConfig(evm, numTransfers, batchGasLimit)
	log.Printf("✅ Individual transfers completed in %v", duration)

	// Calculate performance metrics
	transfersPerSecond := float64(numTransfers) / duration.Seconds()

	fmt.Println("⚡ BSC-EVM Benchmark Results:")
	fmt.Printf("   Transfers: %d\n", numTransfers)
	fmt.Printf("   Duration: %.2fms\n", float64(duration.Nanoseconds())/1000000)
	fmt.Printf("   Transfers/sec: %.2f\n", transfersPerSecond)

	log.Printf("📊 Performance results - Transfers: %d, Duration: %v, TPS: %.2f",
		numTransfers, duration, transfersPerSecond)

	// Verify some recipient balances
	fmt.Println("🔍 Verifying transfers...")
	log.Println("🔍 Verifying recipient balances...")
	startRecipient := common.HexToAddress("0x3000000000000000000000000000000000000001")
	for i := 0; i < 3; i++ {
		recipient := common.BigToAddress(new(big.Int).Add(startRecipient.Big(), big.NewInt(int64(i))))
		balance := getTokenBalance(evm, recipient)
		fmt.Printf("   Recipient %d: %s tokens\n", i+1, new(big.Int).Div(balance, big.NewInt(1000000000000000000)).String())
		log.Printf("✅ Recipient %d (%s): %s tokens", i+1, recipient.Hex(), new(big.Int).Div(balance, big.NewInt(1000000000000000000)).String())
	}

	// Verify Alice's final balance
	log.Println("🔍 Verifying Alice's final balance...")
	aliceFinalBalance := getTokenBalance(evm, aliceAddr)
	fmt.Printf("   Alice final balance: %s tokens\n", new(big.Int).Div(aliceFinalBalance, big.NewInt(1000000000000000000)).String())
	log.Printf("✅ Alice's final balance: %s tokens", new(big.Int).Div(aliceFinalBalance, big.NewInt(1000000000000000000)).String())

	fmt.Println("✨ BSC-EVM Benchmark completed successfully!")
	log.Println("✨ BSC-EVM Benchmark completed successfully!")
}

func loadBytecode(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to read bytecode file: %v", err))
	}

	bytecodeStr := strings.TrimSpace(string(data))
	if strings.HasPrefix(bytecodeStr, "0x") {
		bytecodeStr = bytecodeStr[2:]
	}

	bytecode, err := hex.DecodeString(bytecodeStr)
	if err != nil {
		panic(fmt.Sprintf("Invalid hex in bytecode: %v", err))
	}

	return bytecode
}

func deployContract(evm *vm.EVM, bytecode []byte) {
	// Deploy contract with increased gas limit
	value := uint256.NewInt(0)
	deployGasLimit := uint64(2000000000) // 2B gas (sufficient for base EVM)
	fmt.Printf("🔧 Deploying contract with %d gas...\n", deployGasLimit)
	log.Println("📝 About to call evm.Create...")

	ret, contractAddr, leftOverGas, err := evm.Create(aliceRef, bytecode, deployGasLimit, value)
	log.Printf("📝 evm.Create returned: err=%v, gasUsed=%d\n", err, deployGasLimit-leftOverGas)
	if err != nil {
		gasUsed := deployGasLimit - leftOverGas
		fmt.Printf("❌ Contract deployment failed: %v (Gas used: %d/%d)\n", err, gasUsed, deployGasLimit)
		panic(fmt.Sprintf("Contract deployment failed: %v", err))
	}

	gasUsed := deployGasLimit - leftOverGas
	fmt.Printf("✅ Contract deployed at: %s, gas used: %d/%d (%.2f%%)\n",
		contractAddr.Hex(), gasUsed, deployGasLimit, float64(gasUsed)/float64(deployGasLimit)*100)

	// 更新全局变量存储实际部署的合约地址
	globalUsdtContract = contractAddr
	_ = ret // 避免未使用变量警告
}

func mintTokens(evm *vm.EVM, amount *big.Int) {
	// USDT合约的mint函数签名是 mint(uint256 amount)
	// 不需要to参数，因为USDT的mint函数会将代币铸造给msg.sender

	// Prepare calldata for USDT mint function
	calldata := make([]byte, 0, 36)
	calldata = append(calldata, mintSelector...)
	calldata = append(calldata, common.LeftPadBytes(amount.Bytes(), 32)...)

	// Execute transaction with increased gas limit
	executeTransaction(evm, globalUsdtContract, calldata, 100000000) // 从10M增加到100M (适合50万次转账)
}

func getTokenBalance(evm *vm.EVM, account common.Address) *big.Int {
	log.Printf("🔍 getTokenBalance called for account: %s", account.Hex())

	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("❌ PANIC in getTokenBalance: %v", r)
			panic(r) // re-panic after logging
		}
	}()

	// Prepare calldata
	calldata := make([]byte, 0, 36)
	calldata = append(calldata, balanceOfSelector...)
	calldata = append(calldata, make([]byte, 12)...) // padding for address
	calldata = append(calldata, account.Bytes()...)

	log.Printf("🔍 Calling executeTransaction with gas limit: 100000000")
	// Execute transaction with increased gas limit
	ret := executeTransaction(evm, globalUsdtContract, calldata, 100000000) // 从10M增加到100M (适合50万次转账)

	log.Printf("✅ executeTransaction returned, ret length: %d", len(ret))
	if len(ret) >= 32 {
		balance := new(big.Int).SetBytes(ret[:32])
		log.Printf("✅ Balance parsed: %s", balance.String())
		return balance
	}
	log.Printf("⚠️ Empty balance, returning 0")
	return big.NewInt(0)
}

func performIndividualTransfersWithConfig(evm *vm.EVM, numTransfers int64, gasLimit uint64) time.Duration {
	startRecipient := common.HexToAddress("0x3000000000000000000000000000000000000001")
	amountPerTransfer := big.NewInt(1000000000000000000) // 1 token

	fmt.Printf("🔄 Starting individual transfers with %d transfers, gas limit per transfer: %d\n", numTransfers, gasLimit/uint64(numTransfers))
	log.Printf("🔄 Individual transfer config - Transfers: %d, Gas Limit per transfer: %d", numTransfers, gasLimit/uint64(numTransfers))

	// Measure execution time
	startTime := time.Now()

	// 为每次转账分配gas
	gasPerTransfer := gasLimit / uint64(numTransfers)

	for i := 0; i < int(numTransfers); i++ {
		// 计算接收地址
		recipient := common.BigToAddress(new(big.Int).Add(startRecipient.Big(), big.NewInt(int64(i))))

		// 准备transfer函数的calldata
		calldata := make([]byte, 0, 68)
		calldata = append(calldata, transferSelector...)
		calldata = append(calldata, make([]byte, 12)...) // padding for address
		calldata = append(calldata, recipient.Bytes()...)
		calldata = append(calldata, common.LeftPadBytes(amountPerTransfer.Bytes(), 32)...)

		// 执行transfer调用
		executeTransaction(evm, globalUsdtContract, calldata, gasPerTransfer)

		// 每10万次转账打印一次进度
		if (i+1)%100000 == 0 {
			fmt.Printf("📊 Progress: %d/%d transfers completed\n", i+1, numTransfers)
			log.Printf("📊 Progress: %d/%d transfers completed", i+1, numTransfers)
		}
	}

	duration := time.Since(startTime)

	fmt.Printf("✅ Individual transfers completed in %v\n", duration)
	log.Printf("✅ Individual transfers completed in %v", duration)

	return duration
}

func performBatchTransfersWithConfig(evm *vm.EVM, numTransfers int64, gasLimit uint64) time.Duration {
	// USDT合约没有batchTransferSequential函数，所以这个函数不能用于USDT
	// 这里保留函数结构，但实际不会被执行
	fmt.Printf("⚠️ BUSD contract does not have batchTransferSequential function\n")
	log.Printf("⚠️ BUSD contract does not have batchTransferSequential function")

	// Measure execution time
	startTime := time.Now()
	// 不执行任何操作，因为USDT没有批量转账功能
	duration := time.Since(startTime)

	fmt.Printf("✅ Batch transfer not available for USDT contract\n")
	log.Printf("✅ Batch transfer not available for USDT contract")

	return duration
}

func executeTransaction(evm *vm.EVM, to common.Address, data []byte, gasLimit uint64) []byte {
	log.Printf("🚀 executeTransaction: to=%s, dataLen=%d, gasLimit=%d", to.Hex(), len(data), gasLimit)

	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("❌ PANIC in executeTransaction: %v", r)
			panic(r) // re-panic after logging
		}
	}()

	// Execute call
	value := uint256.NewInt(0)
	log.Printf("🔍 Calling evm.Call...")
	ret, leftOverGas, err := evm.Call(aliceRef, to, data, gasLimit, value)
	log.Printf("✅ evm.Call returned: err=%v, retLen=%d, leftOverGas=%d", err, len(ret), leftOverGas)

	if err != nil {
		gasUsed := gasLimit - leftOverGas
		fmt.Printf("❌ Transaction failed: %v (Gas used: %d/%d)\n", err, gasUsed, gasLimit)
		log.Printf("❌ Transaction failed: %v (Gas used: %d/%d)", err, gasUsed, gasLimit)
		panic(fmt.Sprintf("Transaction failed: %v", err))
	}

	gasUsed := gasLimit - leftOverGas
	log.Printf("✅ Transaction executed, gas used: %d/%d (%.2f%%)", gasUsed, gasLimit, float64(gasUsed)/float64(gasLimit)*100)
	return ret
}
