// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {Test} from "forge-std/Test.sol";
import {HelperConfig, CodeConstants, SepoliaEthereumConstants, EnvLookups, AnvilConstants} from "./HelperConfig.s.sol";
import {console} from "forge-std/console.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {KYCHook, InitializeHookWithKYCParams} from "../src/hooks/KYCHook.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {BlackWhitelistPolicy} from "../src/policies/BlackWhitelistPolicy.sol";
import {KYCPolicy} from "../src/base/KYCPolicy.sol";
import {KYCTokenPolicy} from "../src/policies/KYCTokenPolicy.sol";
import {KYCRouter} from "../src/routers/KYCRouter.sol";
import {MaliciousRouter} from "../src/routers/MaliciousRouter.sol";
import {LazyRouter} from "../src/routers/LazyRouter.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {KYCToken} from "../src/base/KYCToken.sol";
import {RetailKYC, RetailKYCInformation, IdDocumentsBundle} from "../src/base/RetailKYC.sol";
import {HookMiner} from "../src/utils/HookMiner.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";


contract DeployContracts is Script, CodeConstants, AnvilConstants, SepoliaEthereumConstants, EnvLookups {
    using PoolIdLibrary for PoolKey;
    MockERC20 tokenA;
    MockERC20 tokenB;
    Currency pool_token0;
    Currency pool_token1;
    InitializeHookWithKYCParams initParams;

    constructor() {
        tokenA = MockERC20(address(0));
        tokenB = MockERC20(address(0));
        pool_token0 = Currency.wrap(address(0));
        pool_token1 = Currency.wrap(address(0));
    }


    function run() external returns (HelperConfig.NetworkConfig memory updatedNetworkConfig) {

        console.log("Getting network config for chainid before deployment:", block.chainid);
        HelperConfig helperConfig = new HelperConfig();
        updatedNetworkConfig = helperConfig.getLocalNetworkConfig();
        
        // Print the initial network configuration
        
        helperConfig.printNetworkConfig(updatedNetworkConfig);

        console.log("\nBalances of the relevant accounts before deployment:");
        helperConfig.printETHBalances(updatedNetworkConfig);

        console.log("\nDeploying contracts for chainid:", block.chainid);
        //Deploy Tokens
        if (address(updatedNetworkConfig.erc20Contracts.link_token) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
            MockERC20 link_token = new MockERC20("ChainLink Token", "LINK", 18);
            vm.stopBroadcast();
            updatedNetworkConfig.erc20Contracts.link_token = link_token;
            console.log("Link token deployed at", address(link_token));
        } else {
            console.log("!! Link token already deployed at", address(updatedNetworkConfig.erc20Contracts.link_token));
        }
        if (address(updatedNetworkConfig.erc20Contracts.usdc_token) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
            MockERC20 usdc_token = new MockERC20("USDC", "USDC", 18);
            vm.stopBroadcast();
            updatedNetworkConfig.erc20Contracts.usdc_token = usdc_token;
            console.log("USDC token deployed at", address(usdc_token));
        } else {
            console.log("!! USDC token already deployed at", address(updatedNetworkConfig.erc20Contracts.usdc_token));
        }
        if (Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token0) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
            tokenA = new MockERC20("Uniswap V4 Pool Token 0", "UNIV4PT1", 18);
            vm.stopBroadcast();
        } else {
            console.log("!! Pool token 0 already deployed at", Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token0));
            tokenA = MockERC20(Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token0));
        }
        if (Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token1) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
            tokenB = new MockERC20("Uniswap V4 Pool Tokeni 1", "UNIV4PT2", 18);
            vm.stopBroadcast();
        } else {
            console.log("!! Pool token 1 already deployed at", Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token1));
            tokenB = MockERC20(Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token1));
        }
        // Order newly created tokens
        if (address(tokenA) > address(tokenB)) {
            (pool_token0, pool_token1) = (
                Currency.wrap(address(tokenB)),
                Currency.wrap(address(tokenA))
            );
        } else {
            (pool_token0, pool_token1) = (
                Currency.wrap(address(tokenA)),
                Currency.wrap(address(tokenB))
            );
        }
        if (Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token0) != Currency.unwrap(pool_token0)) {
            updatedNetworkConfig.erc20Contracts.pool_token0 = pool_token0;
            console.log("Pool token 0 deployed at", Currency.unwrap(pool_token0));
        }
        if (Currency.unwrap(updatedNetworkConfig.erc20Contracts.pool_token1) != Currency.unwrap(pool_token1)) {
            updatedNetworkConfig.erc20Contracts.pool_token1 = pool_token1;
            console.log("Pool token 1 deployed at", Currency.unwrap(pool_token1));
        }

        //Deploy V4 Contracts
        if (address(updatedNetworkConfig.uniswapV4Contracts.poolManager) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
            uint256 controllerGasLimit = CONTROLED_GAS_LIMIT_POOL_MANAGER_DEPLOYMENT_SEPOLIA;
            IPoolManager poolManager = new PoolManager(controllerGasLimit);
            vm.stopBroadcast();
            updatedNetworkConfig.uniswapV4Contracts.poolManager = poolManager;
            console.log("PoolManager deployed at", address(poolManager));
        } else {
            console.log("!! PoolManager already deployed at", address(updatedNetworkConfig.uniswapV4Contracts.poolManager));
        }
        // Deploy Routers
        if (address(updatedNetworkConfig.routerContracts.kycRouter) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["kycRouterOwner"]));
            KYCRouter kycRouter = new KYCRouter(updatedNetworkConfig.uniswapV4Contracts.poolManager);
            vm.stopBroadcast();
            updatedNetworkConfig.routerContracts.kycRouter = kycRouter;
            console.log("KYCRouter deployed at", address(kycRouter));
        } else {
            console.log("!! KYCRouter already deployed at", address(updatedNetworkConfig.routerContracts.kycRouter));
        }
        if (address(updatedNetworkConfig.routerContracts.maliciousRouter) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["maliciousRouterOwner"]));
            MaliciousRouter maliciousRouter = new MaliciousRouter(updatedNetworkConfig.uniswapV4Contracts.poolManager);
            vm.stopBroadcast();
            updatedNetworkConfig.routerContracts.maliciousRouter = maliciousRouter;
            console.log("MaliciousRouter deployed at", address(maliciousRouter));
        } else {
            console.log("!! MaliciousRouter already deployed at", address(updatedNetworkConfig.routerContracts.maliciousRouter));
        }
        if (address(updatedNetworkConfig.routerContracts.carelessRouter) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["carelessRouterOwner"]));
            LazyRouter carelessRouter = new LazyRouter(updatedNetworkConfig.uniswapV4Contracts.poolManager);
            vm.stopBroadcast();
            updatedNetworkConfig.routerContracts.carelessRouter = carelessRouter;
            console.log("CarelessRouter deployed at", address(carelessRouter));
        } else {
            console.log("!! CarelessRouter already deployed at", address(updatedNetworkConfig.routerContracts.carelessRouter));
        }
        if (address(updatedNetworkConfig.routerContracts.swapRouter) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["swapRouterOwner"]));
            PoolSwapTest swapRouter = new PoolSwapTest(updatedNetworkConfig.uniswapV4Contracts.poolManager);
            vm.stopBroadcast();
            updatedNetworkConfig.routerContracts.swapRouter = swapRouter;
            console.log("SwapRouter deployed at", address(swapRouter));
        } else {
            console.log("!! SwapRouter already deployed at", address(updatedNetworkConfig.routerContracts.swapRouter));
        }
        if (address(updatedNetworkConfig.routerContracts.modifyLiquidityRouter) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["modifyLiquidityRouterOwner"]));
            PoolModifyLiquidityTest modifyLiquidityRouter = new PoolModifyLiquidityTest(updatedNetworkConfig.uniswapV4Contracts.poolManager);
            vm.stopBroadcast();
            updatedNetworkConfig.routerContracts.modifyLiquidityRouter = modifyLiquidityRouter;
            console.log("ModifyLiquidityRouter deployed at", address(modifyLiquidityRouter));
        } else {
            console.log("!! ModifyLiquidityRouter already deployed at", address(updatedNetworkConfig.routerContracts.modifyLiquidityRouter));
        }           
        // Deploy policies
        if (address(updatedNetworkConfig.policyContracts.kycToken) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["tokenOwner"]));
            KYCToken kycToken = new KYCToken();
            vm.stopBroadcast();
            updatedNetworkConfig.policyContracts.kycToken = kycToken;
            console.log("KYCToken deployed at", address(kycToken));
        } else {
            console.log("!! KYCToken already deployed at", address(updatedNetworkConfig.policyContracts.kycToken));
        }
        if (address(updatedNetworkConfig.policyContracts.kycTokenPolicy) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["tokenPolicyOwner"]));
            updatedNetworkConfig.policyContracts.kycTokenPolicy = new KYCTokenPolicy({
                _policyStandard: updatedNetworkConfig.policyContracts.initialRetailKYCInformation,
                _kycTokenAddress: address(updatedNetworkConfig.policyContracts.kycToken)
            });
            vm.stopBroadcast();
            console.log("KYCTokenPolicy deployed at", address(updatedNetworkConfig.policyContracts.kycTokenPolicy));
        } else {
            console.log("!! KYCTokenPolicy already deployed at", address(updatedNetworkConfig.policyContracts.kycTokenPolicy));
        }
        //Deploy KYCHooks
        if (address(updatedNetworkConfig.hookContracts.kycHook) == address(0)) {
            // Requires Mining an address that conforms to the flags
            uint160 flags = uint160(
                Hooks.BEFORE_SWAP_FLAG | 
                Hooks.BEFORE_ADD_LIQUIDITY_FLAG | 
                Hooks.BEFORE_INITIALIZE_FLAG | 
                Hooks.AFTER_INITIALIZE_FLAG
            );
            // Use HookMiner to find a salt that will produce a hook address with the correct flags
            address deployingAddressForNewKYCHook;
            if (block.chainid == ANVIL_CHAIN_ID) {
                deployingAddressForNewKYCHook = CREATE2_DEPLOYER_ANVIL;
            } else {
                deployingAddressForNewKYCHook = CREATE2_DEPLOYER_SEPOLIA;
            }

            console.log("Running HookMiner for KYCHook on chainid:", block.chainid);
            /*********************************************************/
            // Running the HookMiner
            /*********************************************************/
            (address hookAddress, bytes32 salt) = HookMiner.find({
                deployer: deployingAddressForNewKYCHook,
                flags: flags,
                creationCode: type(KYCHook).creationCode,
                constructorArgs: abi.encode(updatedNetworkConfig.uniswapV4Contracts.poolManager, "KYCHook")
            });
            /*********************************************************/
            console.log("Mined hook address:", hookAddress);
            console.log("Salt:", uint256(salt));
            bytes memory creationCode = abi.encodePacked(
                type(KYCHook).creationCode,
                abi.encode(updatedNetworkConfig.uniswapV4Contracts.poolManager, "KYCHook")
            );
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["kycHookOwner"]));
            KYCHook kycHook = new KYCHook{salt: salt}(updatedNetworkConfig.uniswapV4Contracts.poolManager, "KYCHook");
            vm.stopBroadcast();
            console.log("Deployed hook address:", address(kycHook));
            require(address(kycHook) == hookAddress, "Deployed address doesn't match mined address");
            updatedNetworkConfig.hookContracts.kycHook = KYCHook(hookAddress);
            /*********************************************************/
            // Verify the hook address matches the mined address
            console.log("KYCHook deployed at", address(kycHook));
            console.log("Expected flags:", flags);
            console.log("Actual flags:", uint160(uint256(uint160(address(kycHook)))));
            console.log("Hook address matches expected flags");

        } else {
            console.log("!! KYCHook already deployed at", address(updatedNetworkConfig.hookContracts.kycHook));
        }
        /*
        // Deploy Brevis
        if (address(updatedNetworkConfig.brevisContracts.brevisRequest) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["tokenPolicyOwner"]));
            // Brevis brevis = new BrevisREquest();

            vm.stopBroadcast();
            // updatedNetworkConfig.policyContracts.brevis = brevis;
            address brevisRequest = address(0);
            console.log("BrevisRequest deployed at", address(updatedNetworkConfig.brevisContracts.brevisRequest));
        }  
        if (address(updatedNetworkConfig.brevisContracts.brevisProof) == address(0)) {
            vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["tokenPolicyOwner"]));
            // Brevis brevis = new BrevisProof();
            vm.stopBroadcast();
            // updatedNetworkConfig.policyContracts.brevis = brevis;
            address brevisProof = address(0);
            console.log("BrevisProof deployed at", address(updatedNetworkConfig.brevisContracts.brevisProof));
        }
        */
        // Deploy 
        // Include remaining deployments

        // mint  tokens to swapper, liquidity provider, and rogue user
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["initialDeployer"]));
        tokenA.mint(updatedNetworkConfig.users.swapper, 10 ether);
        tokenA.mint(updatedNetworkConfig.users.liquidityProvider, 100 ether);
        tokenA.mint(updatedNetworkConfig.users.rogueUser, 10 ether);
        tokenB.mint(updatedNetworkConfig.users.swapper, 10 ether);
        tokenB.mint(updatedNetworkConfig.users.liquidityProvider, 100 ether);
        tokenB.mint(updatedNetworkConfig.users.rogueUser, 10 ether);
        vm.stopBroadcast();
        console.log("Minted tokens to swapper, liquidity provider, and rogue user");
        // approve the routers to spend the tokens
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["swapper"]));
        tokenA.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        vm.stopBroadcast();
        console.log("Approved routers to spend tokens on behalf of swapper");
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["liquidityProvider"]));
        tokenA.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        vm.stopBroadcast();
        console.log("Approved routers to spend tokens on behalf of liquidity provider");
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["rogueUser"]));
        tokenA.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.kycRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.maliciousRouter), type(uint256).max);
        tokenA.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        tokenB.approve(address(updatedNetworkConfig.routerContracts.carelessRouter), type(uint256).max);
        vm.stopBroadcast();
        console.log("Approved routers to spend tokens on behalf of rogue user");

        // Initialize 2 pools, one with and one without KYC
        if (Currency.unwrap(updatedNetworkConfig.kycPool.key.currency0) == address(0)) {
            console.log("Initializing pool with KYC policy");
            initParams = InitializeHookWithKYCParams({
            policyContractAddress: address(updatedNetworkConfig.policyContracts.kycTokenPolicy),
            isKYCRequired: true
        }); 
        updatedNetworkConfig.kycPool.key.currency0 = updatedNetworkConfig.erc20Contracts.pool_token0;
        updatedNetworkConfig.kycPool.key.currency1 = updatedNetworkConfig.erc20Contracts.pool_token1;
        updatedNetworkConfig.kycPool.key.fee = 3000;
        updatedNetworkConfig.kycPool.key.tickSpacing = 120;
        updatedNetworkConfig.kycPool.key.hooks = IHooks(address(updatedNetworkConfig.hookContracts.kycHook));
        updatedNetworkConfig.kycPool.hookData = abi.encode(initParams);
        updatedNetworkConfig.kycPool.sqrtPriceX96 = SQRT_PRICE_1_1;

        bytes memory initData = updatedNetworkConfig.hookContracts.kycHook.encodeInitializeHookData(initParams);
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["poolKYCOwner"]));
        updatedNetworkConfig.uniswapV4Contracts.poolManager.initialize(
            updatedNetworkConfig.kycPool.key,
            updatedNetworkConfig.kycPool.sqrtPriceX96,
            initData
        );
        vm.stopBroadcast();
        console.log("Initialized pool with KYC");
        printPoolKey(updatedNetworkConfig.kycPool.key);
        console.log("SqrtPriceX96:", updatedNetworkConfig.kycPool.sqrtPriceX96);
        console.log("Hook:", address(updatedNetworkConfig.hookContracts.kycHook));
        console.log("Attached Policy Address:", address(updatedNetworkConfig.policyContracts.kycTokenPolicy));

        // Initialize the non-KYC pool
        updatedNetworkConfig.nonKycPool.key.currency0 = updatedNetworkConfig.erc20Contracts.pool_token0;
        updatedNetworkConfig.nonKycPool.key.currency1 = updatedNetworkConfig.erc20Contracts.pool_token1;
        updatedNetworkConfig.nonKycPool.key.fee = 3000;
        updatedNetworkConfig.nonKycPool.key.tickSpacing = 120;
        updatedNetworkConfig.nonKycPool.key.hooks = IHooks(address(0x0));
        updatedNetworkConfig.nonKycPool.hookData = bytes("");
        updatedNetworkConfig.nonKycPool.sqrtPriceX96 = SQRT_PRICE_1_1;
        vm.startBroadcast(vm.envUint(envPrivKey[block.chainid]["poolNonKYCOwner"]));
        updatedNetworkConfig.uniswapV4Contracts.poolManager.initialize(
            updatedNetworkConfig.nonKycPool.key, 
            updatedNetworkConfig.nonKycPool.sqrtPriceX96, 
            updatedNetworkConfig.nonKycPool.hookData
        );
        vm.stopBroadcast();
        console.log("Initialized pool without KYC");
        printPoolKey(updatedNetworkConfig.nonKycPool.key);
        console.log("SqrtPriceX96:", updatedNetworkConfig.nonKycPool.sqrtPriceX96);
        console.log("Hook:", address(0x0));
        console.log("Attached Policy Address:", address(0x0));

        }
        
        console.log("\nUpdated Network Configuration after deployments:");
        helperConfig.printNetworkConfig(updatedNetworkConfig);

        return updatedNetworkConfig;
    }

    // Helper functions -------------------------------------------------------- //
    function checkHookFlags(address hookAddress, uint160 expectedFlags) public pure returns (bool) {
        // Extract the least significant 20 bytes (160 bits) from the hook address
        uint160 addressFlags = uint160(uint256(uint160(hookAddress)));
        
        // Mask to consider only the bits that correspond to possible hook flags
        uint160 hookFlagsMask = 0x3FFF;

        
        // Apply the mask to both the address flags and expected flags
        addressFlags &= hookFlagsMask;
        expectedFlags &= hookFlagsMask;
       
        // Check if all expected flags are set
        return addressFlags == expectedFlags;
    }


    function printPoolKey(PoolKey memory key) internal pure{
        console.log("PoolKey:");
        console.log("  Token0:", Currency.unwrap(key.currency0));
        console.log("  Token1:", Currency.unwrap(key.currency1));
        console.log("  Fee:", key.fee);
        console.log("  TickSpacing:", key.tickSpacing);
        console.log("  Hooks:", address(key.hooks));
    }

}
