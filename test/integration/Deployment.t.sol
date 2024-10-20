// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {DeployContracts} from "../../script/Deployments.s.sol";
import {HelperConfig, AnvilConstants, SepoliaEthereumConstants, EnvLookups} from "../../script/HelperConfig.s.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {KYCRouter} from "../../src/routers/KYCRouter.sol";
import {LazyRouter} from "../../src/routers/LazyRouter.sol";
import {MaliciousRouter} from "../../src/routers/MaliciousRouter.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";

contract DeploymentTest is Test, AnvilConstants, SepoliaEthereumConstants, EnvLookups {
    HelperConfig helperConfig;
    HelperConfig.NetworkConfig networkConfigBeforeDeployment;
    HelperConfig.NetworkConfig networkConfigAfterDeployment;
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
        networkConfigBeforeDeployment = helperConfig.getLocalNetworkConfig();
        console.log("Network config before deployment:");
        helperConfig.printNetworkConfig(networkConfigBeforeDeployment);
        DeployContracts deployments = new DeployContracts();
        networkConfigAfterDeployment = deployments.run();
        console.log("Network config after deployment:");
        helperConfig.printNetworkConfig(networkConfigAfterDeployment);
        console.log("Balances of the relevant accounts after deployment:");
        helperConfig.printETHBalances(networkConfigAfterDeployment);
        console.log("Setup complete on chain %s", block.chainid);
    }

    function test_Deployment_fundsAccountsWithETH() public onlyForkedTest {
        if (block.chainid == ANVIL_CHAIN_ID) {
            uint256 swapperBalance = address(networkConfigAfterDeployment.users.swapper).balance;
            assertEq(swapperBalance, 10000 ether);
            uint256 liquidityProviderBalance = address(networkConfigAfterDeployment.users.liquidityProvider).balance;
            assertEq(liquidityProviderBalance, 10000 ether);
            uint256 rogueUserBalance = address(networkConfigAfterDeployment.users.rogueUser).balance;
            assertEq(rogueUserBalance, 10000 ether);
            uint256 poolKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolKYCOwner).balance;
            assertEq(poolKYCOwnerBalance, 10000 ether);
            uint256 poolNonKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner).balance;
            assertEq(poolNonKYCOwnerBalance, 10000 ether);
            uint256 tokenPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner).balance;
            assertEq(tokenPolicyOwnerBalance, 10000 ether);
            uint256 usdcBlacklistPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner).balance;
            assertEq(usdcBlacklistPolicyOwnerBalance, 10000 ether);
            uint256 kycHookOwnerBalance = address(networkConfigAfterDeployment.activeOwners.kycHookOwner).balance;
            assertEq(kycHookOwnerBalance, 10000 ether);
        }
        if (block.chainid == ETHEREUM_SEPOLIA_CHAIN_ID) {
            uint256 swapperBalance = address(networkConfigAfterDeployment.users.swapper).balance;
            assertGt(swapperBalance, 0);
            uint256 liquidityProviderBalance = address(networkConfigAfterDeployment.users.liquidityProvider).balance;
            assertGt(liquidityProviderBalance, 0);
            uint256 rogueUserBalance = address(networkConfigAfterDeployment.users.rogueUser).balance;
            assertGt(rogueUserBalance, 0);
            uint256 poolKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolKYCOwner).balance;
            assertGt(poolKYCOwnerBalance, 0);
            uint256 poolNonKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner).balance;
            assertGt(poolNonKYCOwnerBalance, 0);
            uint256 tokenPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner).balance;
            assertGt(tokenPolicyOwnerBalance, 0);
            uint256 usdcBlacklistPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner).balance;
            assertGt(usdcBlacklistPolicyOwnerBalance, 0);
            uint256 kycHookOwnerBalance = address(networkConfigAfterDeployment.activeOwners.kycHookOwner).balance;
            assertGt(kycHookOwnerBalance, 0);
        }
    }

    function test_Deployment_ERC20Contracts_Are_Deployed() public onlyForkedTest {
        ERC20 pool_token0 = ERC20(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token0));
        ERC20 pool_token1 = ERC20(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token1));
        ERC20 usdc_token = ERC20(address(networkConfigAfterDeployment.erc20Contracts.usdc_token));
        ERC20 link_token = ERC20(address(networkConfigAfterDeployment.erc20Contracts.link_token));

        uint256 pool_token0_totalSupply = pool_token0.totalSupply();
        assertTrue(address(pool_token0) != address(0));
        assertTrue(pool_token0_totalSupply > 0);
        uint256 pool_token1_totalSupply = pool_token1.totalSupply();
        assertTrue(address(pool_token1) != address(0));
        assertTrue(pool_token1_totalSupply > 0);
        string memory usdc_token_name = usdc_token.name();
        string memory link_token_name = link_token.name();
        assertTrue(keccak256(abi.encodePacked(usdc_token_name)) == keccak256(abi.encodePacked("USDC")));
        assertTrue(keccak256(abi.encodePacked(link_token_name)) == keccak256(abi.encodePacked("ChainLink Token")));

        if (block.chainid == ANVIL_CHAIN_ID) {
            console.log("MOCKERC20 does not deploy with a total supply on Anvil");
         } else {
            uint256 usdc_token_totalSupply = usdc_token.totalSupply();
            uint256 link_token_totalSupply = link_token.totalSupply();
            assertTrue(address(usdc_token) != address(0));
            assertTrue(usdc_token_totalSupply > 0);
            assertTrue(address(link_token) != address(0));
            assertTrue(link_token_totalSupply > 0);
        }
    }

    function test_NetWorkConfig_Is_UpdatedAfterDeployment() public {
        assertTrue(address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager) != address(0));

        assertTrue(address(networkConfigAfterDeployment.routerContracts.kycRouter) != address(0));
        assertTrue(address(networkConfigAfterDeployment.routerContracts.maliciousRouter) != address(0));
        assertTrue(address(networkConfigAfterDeployment.routerContracts.carelessRouter) != address(0));
        assertTrue(address(networkConfigAfterDeployment.routerContracts.swapRouter) != address(0));
        assertTrue(address(networkConfigAfterDeployment.routerContracts.modifyLiquidityRouter) != address(0));

        assertTrue(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token0) != address(0));
        assertTrue(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token1) != address(0));
        assertTrue(address(networkConfigAfterDeployment.erc20Contracts.usdc_token) != address(0));
        assertTrue(address(networkConfigAfterDeployment.erc20Contracts.link_token) != address(0));

        assertTrue(address(networkConfigAfterDeployment.policyContracts.kycTokenPolicy) != address(0));
        assertTrue(address(networkConfigAfterDeployment.policyContracts.kycToken) != address(0));

        assertTrue(address(networkConfigAfterDeployment.activeOwners.poolKYCOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner) != address(0));
        // assertTrue(address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.kycHookOwner) != address(0));
        // assertTrue(address(networkConfigAfterDeployment.activeOwners.kycHook_byWhitelistOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.kycRouterOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.maliciousRouterOwner) != address(0));
        assertTrue(address(networkConfigAfterDeployment.activeOwners.carelessRouterOwner) != address(0));
    }

    function test_KYC_Hook_Is_Deployed() public onlyForkedTest {
        // Check that the KYC hook has the getHookOwner function implemented
        address contractAddress = address(networkConfigAfterDeployment.hookContracts.kycHook);
        bytes4 functionSelector = bytes4(keccak256("getHookOwner()"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
    }

    function test_PoolManager_Is_Deployed() public onlyForkedTest { 
        // Check that the PoolManager has the initialize and swap functions implemented
        address contractAddress = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager); 
        bytes4 functionSelector = bytes4(keccak256("initialize((address,address,uint24,int24,address),uint160,bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the PoolManager has the swap function implemented
        functionSelector = bytes4(keccak256("swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
    }
    
    function test_KYCRouter_Is_Deployed() public onlyForkedTest {
        // Check that the KYCRouter has the swap function implemented
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.kycRouter);
        bytes4 functionSelector = bytes4(keccak256("swap((address,address,uint24,int24,address),(bool,int256,uint160),(bool,bool),bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
    }

    function test_KYCRouter_Is_Initialized_With_PoolManager() public onlyForkedTest {
        // Check that the KYCRouter is initialized with the PoolManager
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.kycRouter);
        bytes4 functionSelector = bytes4(keccak256("manager()"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the manager is the PoolManager
        address manager = address(KYCRouter(contractAddress).manager());
        address expectedManager = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager);
        assertEq(manager, expectedManager, "KYCRouter is not initialized with the correct PoolManager");
    }

    function test_LazyRouter_Is_DeployedAndInitializedWithPoolManager() public onlyForkedTest {
        // Check that the LazyRouter has the swap function implemented
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.carelessRouter);
        bytes4 functionSelector = bytes4(keccak256("swap((address,address,uint24,int24,address),(bool,int256,uint160),(bool,bool),bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the LazyRouter is initialized with the PoolManager
        functionSelector = bytes4(keccak256("manager()"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the manager is the PoolManager
        address manager = address(LazyRouter(contractAddress).manager());
        address expectedManager = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager);
        assertEq(manager, expectedManager, "LazyRouter is not initialized with the correct PoolManager");
    }

    function test_MaliciousRouter_Is_DeployedAndInitializedWithPoolManager() public onlyForkedTest {
        // Check that the MaliciousRouter has the swap function implemented
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.maliciousRouter);
        bytes4 functionSelector = bytes4(keccak256("swap((address,address,uint24,int24,address),(bool,int256,uint160),(bool,bool),bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the MaliciousRouter is initialized with the PoolManager
        functionSelector = bytes4(keccak256("manager()"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the manager is the PoolManager
        address manager = address(MaliciousRouter(contractAddress).manager());
        address expectedManager = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager);
        assertEq(manager, expectedManager, "MaliciousRouter is not initialized with the correct PoolManager");
    }

    function test_SwapRouter_Is_DeployedAndInitializedWithPoolManager() public onlyForkedTest {
        // Check that the SwapRouter has the swap function implemented
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.swapRouter);
        bytes4 functionSelector = bytes4(keccak256("swap((address,address,uint24,int24,address),(bool,int256,uint160),(bool,bool),bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the SwapRouter is initialized with the PoolManager
        functionSelector = bytes4(keccak256("manager()"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the manager is the PoolManager
        address manager = address(PoolSwapTest(contractAddress).manager());
        address expectedManager = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager);
        assertEq(manager, expectedManager, "SwapRouter is not initialized with the correct PoolManager");
    }

    function test_ModifyLiquidityRouter_Is_DeployedAndInitializedWithPoolManager() public onlyForkedTest {
        // Check that the ModifyLiquidityRouter has the modifyLiquidity function implemented
        address contractAddress = address(networkConfigAfterDeployment.routerContracts.modifyLiquidityRouter);
        bytes4 functionSelector = bytes4(keccak256("modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the ModifyLiquidityRouter is initialized with the PoolManager
        functionSelector = bytes4(keccak256("manager()"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the manager is the PoolManager
        address manager = address(PoolModifyLiquidityTest(contractAddress).manager());
        address expectedManager = address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager);
        assertEq(manager, expectedManager, "ModifyLiquidityRouter is not initialized with the correct PoolManager");
    }

    function test_KYCToken_Is_Deployed() public onlyForkedTest {
        // Check that the KYCToken has the ownerOf function implemented
        address contractAddress = address(networkConfigAfterDeployment.policyContracts.kycToken);
        bytes4 functionSelector = bytes4(keccak256("ownerOf(uint256)"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        console.log("KYCToken ... checking ownerOf function");
        console.log("KYCToken address:", address(networkConfigAfterDeployment.policyContracts.kycToken));
        console.log("Function selector (ownerOf):");
        console.logBytes4(functionSelector);
        console.log("Has ownerOf function:");
        console.log(hasFunctionImplemented);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the KYCToken has the mintTo function implemented
        functionSelector = bytes4(keccak256("mintTo(address,(bool,bool,bool,bool,bool,uint16))"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        console.log("KYCToken ... checking mintTo function");
        console.log("KYCToken address:", address(networkConfigAfterDeployment.policyContracts.kycToken));
        console.log("Function selector (mintTo):");
        console.logBytes4(functionSelector);
        console.log("Has mintTo function:", hasFunctionImplemented);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the KYCToken has the getRetailKYCInformationFromTokenId function implemented
        contractAddress = address(networkConfigAfterDeployment.policyContracts.kycToken);
        functionSelector = bytes4(keccak256("getRetailKYCInformationFromTokenId(uint256)"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        console.log("KYCToken ... checking getRetailKYCInformationFromTokenId function");
        console.log("KYCToken address:", address(networkConfigAfterDeployment.policyContracts.kycToken));
        console.log("Function selector (getRetailKYCInformationFromTokenId):");
        console.logBytes4(functionSelector);
        console.log("Has getRetailKYCInformationFromTokenId function:");
        console.log(hasFunctionImplemented);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
    }

    function test_KYCTokenPolicy_Is_Deployed() public onlyForkedTest {
        // Check that the KYCTokenPolicy has the getOwner function implemented
        address contractAddress = address(networkConfigAfterDeployment.policyContracts.kycTokenPolicy);
        bytes4 functionSelector = bytes4(keccak256("getOwner()"));
        bool hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check that the KYCTokenPolicy has the getPolicyStandard function implemented
        functionSelector = bytes4(keccak256("getPolicyStandard()"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
        // Check has the function validateSwapAuthorization implemented
        functionSelector = bytes4(keccak256("validateSwapAuthorization(address,(address,address,uint24,int24,address),(bool,int256,uint160))"));
        hasFunctionImplemented = hasFunction(contractAddress, functionSelector);
        assertTrue(hasFunctionImplemented, "Contract does not have the specified function");
    }



    ///////////////////////////////////////////////////////////////////////////////////////////////////////////// 
    // HELPERS
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////   

    function hasFunction(address contractAddress, bytes4 functionSelector) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(contractAddress)
        }
        if (size == 0) return false;

        bytes memory code = contractAddress.code;
        for (uint i = 0; i < code.length - 3; i++) {
            if (code[i] == functionSelector[0] &&
                code[i+1] == functionSelector[1] &&
                code[i+2] == functionSelector[2] &&
                code[i+3] == functionSelector[3]) {
                return true;
            }
        }
        return false;
    }
}
