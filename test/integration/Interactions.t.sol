// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployContracts} from "../../script/Deployments.s.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {InitPool} from "../../script/Interactions.s.sol";
import {TestData} from "../mocks/TestData.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
contract InteractionsTest is Test {

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
        //Revert if the pool is already initialized ... is the case for nonKYC pool with Poolkex from Deployment
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(poolManager, networkConfig.nonKycPool.key, networkConfig.activeOwners.poolNonKYCOwner, networkConfig.nonKycPool.sqrtPriceX96, networkConfig.nonKycPool.hookData);
    }

    function test_Interactions_initPool_withKYC_revertsIfAlreadyInitialized() public onlyForkedTest {
        //Revert if the pool is already initialized ... is the case for kyc pool with Poolkey from TestData
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        vm.expectRevert(PoolAlreadyInitialized.selector);
        initPool.initPool(poolManager, networkConfig.kycPool.key, networkConfig.activeOwners.poolKYCOwner, networkConfig.kycPool.sqrtPriceX96, networkConfig.kycPool.hookData);
    }

    function test_Interactions_initPool_withKYC() public onlyForkedTest {
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        initPool.initPool(
            poolManager,
            testData.getTestKycPoolKey(),
            networkConfig.activeOwners.poolKYCOwner,
            networkConfig.kycPool.sqrtPriceX96,
            networkConfig.kycPool.hookData
        );
        console.log("Pool initialized with KYC");
        assertTrue(true);
    }

    function test_Interactions_initPool_withoutKYC() public onlyForkedTest {
        InitPool initPool = new InitPool();
        PoolManager poolManager = PoolManager(address(networkConfig.uniswapV4Contracts.poolManager));
        initPool.initPool(poolManager, testData.getTestNonKycPoolKey(), networkConfig.activeOwners.poolNonKYCOwner, networkConfig.nonKycPool.sqrtPriceX96, networkConfig.nonKycPool.hookData);
        console.log("Pool initialized without KYC");
        assertTrue(true);
    }



}