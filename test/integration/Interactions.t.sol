// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployContracts} from "../../script/Deployments.s.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {InitPool} from "../../script/Interactions.s.sol";
// import {ProvideLiquidity} from "../../script/Interactions.s.sol";
import {TestData} from "../mocks/TestData.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

contract InteractionsTest is Test {
    using PoolIdLibrary for PoolKey;

    error PoolAlreadyInitialized();

    HelperConfig helperConfig;
    HelperConfig.NetworkConfig networkConfig;
    TestData testData;

    bool isForkedTest = vm.envOr("FORKED_TEST", false);

    modifier onlyForkedTest() {
        if (!isForkedTest) {
            console.log("Skipping test for non-forked test");
            return;
        }
        _;
    }

    /// @notice Modifier that ensures a pool is initialized before executing a test. If it is already initialized, it will not revert just continue. Otherwise, will initialize it. Then it will check that it cannot be initialized again. Otherwise, will revert
    /// @param poolKey The key identifying the pool to initialize
    /// @param initialDeployer The address that will deploy and initialize the pool
    /// @param sqrtPriceX96 The initial sqrt price of the pool, as a Q64.96
    /// @param hookData Additional data to be passed to the hook during initialization
    modifier initializedPool(
        PoolKey memory poolKey,
        address initialDeployer,
        uint160 sqrtPriceX96,
        bytes memory hookData
    ) {
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        try initPool.initPool(poolManager, poolKey, initialDeployer, sqrtPriceX96, hookData) {}
        catch (bytes memory err) {
            if (keccak256(err) != keccak256(abi.encodeWithSignature("PoolAlreadyInitialized()"))) {
                revert();
            }
        }
        _;
    }

    function setUp() public {
        console.log("Deploying contracts on chain %s", block.chainid);
        helperConfig = new HelperConfig();
        networkConfig = helperConfig.getLocalNetworkConfig();
        DeployContracts deployments = new DeployContracts();
        networkConfig = deployments.run();
        console.log("Network config after deployment:");
        helperConfig.printNetworkConfig(networkConfig);
        console.log("Balances of the relevant accounts after deployment:");
        helperConfig.printETHBalances(networkConfig);
        console.log("Setup complete on chain %s", block.chainid);
        testData = new TestData(networkConfig);
        console.log("Test data initialized");
    }

    function test_Interactions_initPool_withoutKYC_revertsIfAlreadyInitialized() public onlyForkedTest {
        //Revert if the pool is already initialized ... is the case for nonKYC pool with Poolkey from Deployment
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(
            poolManager,
            networkConfig.nonKycPool.key,
            networkConfig.activeOwners.poolNonKYCOwner,
            networkConfig.nonKycPool.sqrtPriceX96,
            networkConfig.nonKycPool.hookData
        );
        console.log("Reverts when attempting to initialize the same pool without KYC");
    }

    function test_Interactions_initPool_withKYC_revertsIfAlreadyInitialized() public onlyForkedTest {
        //Revert if the pool is already initialized ... is the case for kyc pool with Poolkey from TestData
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(
            poolManager,
            networkConfig.kycPool.key,
            networkConfig.activeOwners.poolKYCOwner,
            networkConfig.kycPool.sqrtPriceX96,
            networkConfig.kycPool.hookData
        );
        console.log("Reverts when attempting to initialize the same pool with KYC");
    }

    function test_Interactions_initPool_withKYC_attemptTwice() public onlyForkedTest {
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        // Get the pool key before initialization
        PoolKey memory testPoolKey = testData.getTestNonKycPoolKey();

        // Expect Initialize event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit IPoolManager.Initialize(
            testPoolKey.toId(),
            testPoolKey.currency0,
            testPoolKey.currency1,
            testPoolKey.fee,
            testPoolKey.tickSpacing,
            testPoolKey.hooks,
            networkConfig.kycPool.sqrtPriceX96,
            0 // tick - we don't know exact value, can be checked if needed
        );
        initPool.initPool(
            poolManager,
            testPoolKey,
            networkConfig.activeOwners.poolKYCOwner,
            networkConfig.kycPool.sqrtPriceX96,
            networkConfig.kycPool.hookData
        );
        console.log("Pool initialized with KYC");
        // Try to initialize again - should revert
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(
            poolManager,
            testPoolKey,
            networkConfig.activeOwners.poolKYCOwner,
            networkConfig.kycPool.sqrtPriceX96,
            networkConfig.kycPool.hookData
        );
        console.log("Reverts when attempting to initialize the same pool with KYC");
    }

    function test_Interactions_initPool_withoutKYC_attemptTwice() public onlyForkedTest {
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));

        // Get the pool key before initialization
        PoolKey memory testPoolKey = testData.getTestNonKycPoolKey();

        // Expect Initialize event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit IPoolManager.Initialize(
            testPoolKey.toId(),
            testPoolKey.currency0,
            testPoolKey.currency1,
            testPoolKey.fee,
            testPoolKey.tickSpacing,
            testPoolKey.hooks,
            networkConfig.nonKycPool.sqrtPriceX96,
            0 // tick - we don't know exact value, can be checked if needed
        );

        // First initialization
        initPool.initPool(
            poolManager,
            testPoolKey,
            networkConfig.activeOwners.poolNonKYCOwner,
            networkConfig.nonKycPool.sqrtPriceX96,
            networkConfig.nonKycPool.hookData
        );
        console.log("Pool initialized without KYC");

        // Now try to initialize again - should revert
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(
            poolManager,
            testPoolKey,
            networkConfig.activeOwners.poolNonKYCOwner,
            networkConfig.nonKycPool.sqrtPriceX96,
            networkConfig.nonKycPool.hookData
        );
        console.log("Reverts when attempting to initialize the same pool without KYC");
        assertTrue(true);
    }

    /*
    function test_Interactions_provideLiquidity_nonKYC()
        public
        onlyForkedTest
        initializedPool(
            testData.getTestNonKycPoolKey(),
            networkConfig.activeOwners.poolNonKYCOwner,
            networkConfig.nonKycPool.sqrtPriceX96,
            networkConfig.nonKycPool.hookData
        )
    {
        ProvideLiquidity provideLiquidity = new ProvideLiquidity();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        PoolKey memory testPoolKey = testData.getTestNonKycPoolKey();
        provideLiquidity.provideLiquidity(
            poolManager, testPoolKey, networkConfig.activeOwners.poolNonKYCOwner, 100, 100
        );
        console.log("Liquidity provided to non-KYC pool");
        assertTrue(true);
    }
    */
}
