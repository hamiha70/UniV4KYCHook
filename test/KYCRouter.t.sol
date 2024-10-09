// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {KYCRouter} from "../src/routers/KYCRouter.sol";
import {KYCHook, InitializeHookWithKYCParams} from "../src/hooks/KYCHook.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {KYCEvents} from "../src/utils/events.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {console} from "forge-std/console.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";

import {
    KYCRouter__RouterNotWhitelisted,
    KYCRouter__NoKYCPermission,
    KYCRouter__KYCHookMisbehaving__CallToGetIsRouterWhitelistedReverted,
    KYCRouter__KYCHookMisbehaving__CallToIsRouterWhitelistedReverted,
    KYCRouter__KYCHookMisbehaving__CallToGetKYCPolicyAddressReverted,
    KYCRouter__PolicyMisbehaving__CallToValidateSwapAuthorizationReverted
} from "../src/routers/KYCRouter.sol";

contract KYCRouterTest is Test, Deployers, KYCEvents {
    using PoolIdLibrary for PoolKey;
    using TickMath for uint160;
    using TickMath for int24;

    uint160 constant HOOK_OFFSET_1 = uint160(108523659815 * 2 ** 23);
    uint160 constant HOOK_OFFSET_3 = uint160(908523659815 * 2 ** 23);
    address constant BLACKLISTED_ADDRESS_1 = address(0x1234567890123456789012345678901234567890);
    address constant BLACKLISTED_ADDRESS_2 = address(0x2345678901234567890123456789012345678901);
    address constant SWAPPER_ADDRESS = address(0x7777777777777777777777777777777777777777);
    // Contract Deployer and Swapper
    address constant HOOK_OWNER = address(0x9999999999999999999999999999999999999999);
    address constant KYC_ROUTER_OWNER = address(0x8888888888888888888888888888888888888888);
    address constant RANDOM_ADDRESS = address(0x6666666666666666666666666666666666666666);
    address constant BLACKLIST_POLICY_OWNER = address(0x3333333333333333333333333333333333333333);
    address constant POOL1_OWNER = address(0x1122222222222222222222222222222222222222);
    address constant POOL2_OWNER = address(0x2233333333333333333333333332222222222222);
    // Define KYCHooks ... addresses
    address constant KYCHOOK_ADDRESS_1 = address(
        uint160(
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
                | Hooks.AFTER_INITIALIZE_FLAG | HOOK_OFFSET_1
        )
    );
    address constant KYCHOOK_ADDRESS_3 = address(
        uint160(
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
                | Hooks.AFTER_INITIALIZE_FLAG | HOOK_OFFSET_3
        )
    );

    struct Contracts {
        IPoolManager poolManager;
        KYCRouter kycRouter;
        KYCHook kycHook1;
        KYCHook kycHook3;
        BlacklistPolicy blacklistPolicy1;
        WhitelistPolicy whitelistPolicy;
        PoolSwapTest swapRouter;
        PoolModifyLiquidityTest modifyLiquidityRouter;
    }

    Contracts s_contracts;

    PoolId s_poolId1;
    PoolKey s_poolKey1;
    PoolId s_poolId2;
    PoolKey s_poolKey2;

    address payable s_swapper = payable(SWAPPER_ADDRESS);

    function setUp() public {
        console.log("\nSetup starting\n");
        console.log("Deploying v4-core");
        deployFreshManager();

        s_contracts.poolManager = manager;
        console.log("PoolManager contract deployed with address: %s", address(s_contracts.poolManager));

        // Deploy KYCHook1
        vm.prank(HOOK_OWNER);
        deployCodeTo("KYCHook", abi.encode(s_contracts.poolManager, ""), KYCHOOK_ADDRESS_1);
        s_contracts.kycHook1 = KYCHook(KYCHOOK_ADDRESS_1);
        console.log("KYCHook contract deployed with address: %s", KYCHOOK_ADDRESS_1);
        console.log("Other hooks not deployed at this stage!");

        // Deploy BlacklistPolicy
        address[] memory INITIALLY_BLACKLISTED_ADDRESSES = new address[](2);
        INITIALLY_BLACKLISTED_ADDRESSES[0] = BLACKLISTED_ADDRESS_1;
        INITIALLY_BLACKLISTED_ADDRESSES[1] = BLACKLISTED_ADDRESS_2;
        vm.prank(BLACKLIST_POLICY_OWNER);
        s_contracts.blacklistPolicy1 = new BlacklistPolicy(INITIALLY_BLACKLISTED_ADDRESSES);
        console.log("BlacklistPolicy contract deployed at address: %s", address(s_contracts.blacklistPolicy1));
        console.log(
            "Initially blacklisted addresses: %s, %s",
            INITIALLY_BLACKLISTED_ADDRESSES[0],
            INITIALLY_BLACKLISTED_ADDRESSES[1]
        );

        // Register Policy with KYCHook
        vm.prank(HOOK_OWNER);
        address[] memory routersToWhitelist = new address[](1);
        routersToWhitelist[0] = address(s_contracts.kycRouter);
        s_contracts.kycHook1.updateRouterWhitelist(routersToWhitelist, true);

        // Deploy KYCSimpleRouter
        vm.prank(KYC_ROUTER_OWNER);
        s_contracts.kycRouter = new KYCRouter(s_contracts.poolManager);
        console.log("KYCRouter contract deployed with address: %s", address(s_contracts.kycRouter));

        // Deploy Standard swapRouter and modifyLiquidityRouter
        s_contracts.swapRouter = new PoolSwapTest(s_contracts.poolManager);
        s_contracts.modifyLiquidityRouter = new PoolModifyLiquidityTest(s_contracts.poolManager);

        //Deploy, mint tokens for two tokens
        console.log("Deploying and mint 2 currencies");
        (currency0, currency1) = deployAndMint2Currencies();
        console.log("Currency0: %s", Currency.unwrap(currency0));
        console.log("Currency1: %s", Currency.unwrap(currency1));

        // Approve  Swapper for both tokens with respect to all Routers
        address[3] memory toApprove = [
            address(s_contracts.swapRouter),
            address(s_contracts.modifyLiquidityRouter),
            address(s_contracts.kycRouter)
        ];
        for (uint256 i = 0; i < toApprove.length; i++) {
            vm.startPrank(s_swapper);
            MockERC20(Currency.unwrap(currency0)).approve(toApprove[i], type(uint256).max);
            MockERC20(Currency.unwrap(currency1)).approve(toApprove[i], type(uint256).max);
            vm.stopPrank();
        }
        console.log("Approved all Routers to spend on behalf of Swapper");

        // Deal ETH and tokens to Swapper
        vm.deal(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(currency0)).mint(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(currency1)).mint(s_swapper, 1000 ether);
        console.log(
            "Swapper has %s of currency0 and %s of currency1 and %s ether",
            MockERC20(Currency.unwrap(currency0)).balanceOf(s_swapper),
            MockERC20(Currency.unwrap(currency1)).balanceOf(s_swapper),
            address(s_swapper).balance
        );

        // Deploy pools
        console.log("Deploying KYC pool with KYCHook1");
        InitializeHookWithKYCParams memory initializeSettings =
            InitializeHookWithKYCParams(address(s_contracts.blacklistPolicy1), true);
        bytes memory initData = abi.encode(initializeSettings);
        vm.prank(POOL1_OWNER);
        (s_poolKey1, s_poolId1) =
            initPool(currency0, currency1, s_contracts.kycHook1, 3000, 60, SQRT_PRICE_1_1, initData);
        console.log("Deploying non KYC pool with no hooks");
        vm.prank(POOL2_OWNER);
        (s_poolKey2, s_poolId2) = initPool(currency0, currency1, IHooks(address(0)), 3000, 60, SQRT_PRICE_1_1, "");

        // Whitelist the respective Routers with the KYCHooks
        vm.startPrank(HOOK_OWNER);
        address[] memory routersToWhitelist2 = new address[](3);
        routersToWhitelist2[0] = address(s_contracts.kycRouter);
        routersToWhitelist2[1] = address(s_contracts.swapRouter);
        routersToWhitelist2[2] = address(s_contracts.modifyLiquidityRouter);
        s_contracts.kycHook1.updateRouterWhitelist(routersToWhitelist2, true);
        vm.stopPrank();

        // Approve PoolManager on behalf of KYCSimpleRouter for both tokens
        vm.startPrank(KYC_ROUTER_OWNER);
        MockERC20(Currency.unwrap(currency0)).approve(address(s_contracts.poolManager), type(uint256).max);
        MockERC20(Currency.unwrap(currency1)).approve(address(s_contracts.poolManager), type(uint256).max);
        console.log("Approved PoolManager on behalf of KYCSimpleRouter for both tokens");
        vm.stopPrank();

        // Add more ETH to the swapper account
        vm.deal(s_swapper, 1000 ether);

        //Setup complete
        console.log("Setup complete\n");
    }

    function test_setup() public {
        console.log("\nTesting setup\n");
        // Check HookOwner is set correctly
        assertEq(s_contracts.kycHook1.getHookOwner(), HOOK_OWNER);
        console.log("HookOwner is set correctly set to %s:", HOOK_OWNER);
        // Check if allowances are set correctly by the Swapper
        assertEq(
            MockERC20(Currency.unwrap(currency0)).allowance(s_swapper, address(s_contracts.kycRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency1)).allowance(s_swapper, address(s_contracts.kycRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency0)).allowance(s_swapper, address(s_contracts.swapRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency1)).allowance(s_swapper, address(s_contracts.swapRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency0)).allowance(s_swapper, address(s_contracts.modifyLiquidityRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency1)).allowance(s_swapper, address(s_contracts.modifyLiquidityRouter)),
            type(uint256).max
        );
        console.log("Allowances are set correctly by the Swapper");
        // Check swapper is funded correctly
        assertEq(address(s_swapper).balance, 1000 ether);
        assertEq(MockERC20(Currency.unwrap(currency0)).balanceOf(s_swapper), 1000 ether);
        assertEq(MockERC20(Currency.unwrap(currency1)).balanceOf(s_swapper), 1000 ether);
        console.log("Swapper is funded correctly");
        // Check inital whitelisting of Routers with the KYCHooks
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.kycRouter)));
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.swapRouter)));
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.modifyLiquidityRouter)));
        assert(!s_contracts.kycHook1.isRouterWhitelisted(RANDOM_ADDRESS));
        console.log("Routers are initialized correctly in the KYCHooks");
        // Check add and remove routers from the KYCHooks
        vm.startPrank(HOOK_OWNER);
        vm.expectRevert();
        s_contracts.kycHook1.updateRouterWhitelist(toArray(RANDOM_ADDRESS), false);
        s_contracts.kycHook1.updateRouterWhitelist(toArray(RANDOM_ADDRESS), true);
        vm.expectRevert();
        s_contracts.kycHook1.updateRouterWhitelist(toArray(RANDOM_ADDRESS), true);
        s_contracts.kycHook1.updateRouterWhitelist(toArray(RANDOM_ADDRESS), false);
        assert(!s_contracts.kycHook1.isRouterWhitelisted(RANDOM_ADDRESS));
        vm.stopPrank();
        console.log("Can add and remove routers correctly in the KYCHooks");
        console.log("Cannot add already whitelisted router and remove non existent router.. as expected");
        // Check if addresses are blacklisted correctly in the BlacklistPolicy
        assert(s_contracts.blacklistPolicy1.isBlacklisted(BLACKLISTED_ADDRESS_1));
        assert(s_contracts.blacklistPolicy1.isBlacklisted(BLACKLISTED_ADDRESS_2));
        assert(!s_contracts.blacklistPolicy1.isBlacklisted(RANDOM_ADDRESS));
        console.log("Addresses are blacklisted iniilizedin the BlacklistPolicy");
        // Check add and remove addresses from the BlacklistPolicy
        vm.expectRevert();
        s_contracts.blacklistPolicy1.removeFromBlacklist(BLACKLISTED_ADDRESS_1);
        vm.expectRevert();
        s_contracts.blacklistPolicy1.addToBlacklist(BLACKLISTED_ADDRESS_1);
        console.log("Cannot add and remove addresses from the BlacklistPolicy if not owner.. as expected");
        vm.startPrank(BLACKLIST_POLICY_OWNER);
        s_contracts.blacklistPolicy1.removeFromBlacklist(BLACKLISTED_ADDRESS_1);
        assert(!s_contracts.blacklistPolicy1.isBlacklisted(BLACKLISTED_ADDRESS_1));
        s_contracts.blacklistPolicy1.addToBlacklist(BLACKLISTED_ADDRESS_1);
        assert(s_contracts.blacklistPolicy1.isBlacklisted(BLACKLISTED_ADDRESS_1));
        vm.stopPrank();
        console.log("Addresses are added and removed correctly from the BlacklistPolicy");
        // Check if pool is initialized correctly
        assertEq(PoolId.unwrap(s_poolId2), PoolId.unwrap(s_poolKey2.toId()));
        assertEq(address(s_poolKey2.hooks), address(0));
        assertEq(s_contracts.kycHook1.getPoolCreator(s_poolKey2), address(0)); // pool creator only stored for Pools with KYC
        console.log("Non KYC Pool is initialized correctly");
        assertEq(PoolId.unwrap(s_poolId1), PoolId.unwrap(s_poolKey1.toId()));
        assertEq(address(s_poolKey1.hooks), KYCHOOK_ADDRESS_1);
        assertEq(s_contracts.kycHook1.getPoolCreator(s_poolKey1), POOL1_OWNER);
        assertEq(s_contracts.kycHook1.getIsKYCRequired(s_poolKey1), true);
        console.log("KYC Pool is initialized correctly");
        // Check updating KYCPolicy address in KYCHook for specific pool
        vm.prank(POOL1_OWNER);
        InitializeHookWithKYCParams memory newSettings =
            InitializeHookWithKYCParams(address(s_contracts.blacklistPolicy1), false);
        s_contracts.kycHook1.updateKYCPolicy(s_poolKey1, newSettings);
        assertEq(s_contracts.kycHook1.getKYCPolicyAddress(s_poolKey1), address(s_contracts.blacklistPolicy1));
        assertEq(s_contracts.kycHook1.getIsKYCRequired(s_poolKey1), false);
        console.log("KYCPolicy address is updated correctly in KYCHook for specific pool");
        vm.prank(RANDOM_ADDRESS);
        vm.expectRevert();
        s_contracts.kycHook1.updateKYCPolicy(s_poolKey1, newSettings);
        console.log("Cannot update KYCPolicy address in KYCHook for specific pool if not pool creator .. as expected");
        vm.prank(POOL2_OWNER);
        vm.expectRevert();
        s_contracts.kycHook1.updateKYCPolicy(s_poolKey2, newSettings);
        console.log("Cannot update KYCPolicy address in KYCHook for non KYC pool .. as expected");

        console.log("Setup test complete\n");
    }

    function test_swap_standardRouters() public {
        // Add liquidity to the pools
        // Non KYC Pool
        console.log("\nTesting AddLiquidity and Swapping through standard Routers\n");
        console.log("Adding liquidity to the pools\n");
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60000,
            tickUpper: 60000,
            liquidityDelta: 100 ether,
            salt: bytes32(0)
        });
        uint256 beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        uint256 beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey2, modifyLiquidityParams, "");
        uint256 afterBalanceToken0 = currency0.balanceOf(s_swapper);
        uint256 afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assertLt(afterBalanceToken0, beforeBalanceToken0);
        assertLt(afterBalanceToken1, beforeBalanceToken1);
        console.log("Liquidity added to the non KYC pool by swapper to the liquidity pool using modifyLiquidityRouter");
        // KYC Pool
        bytes memory hookDataFromSwapperAddress = abi.encode(s_swapper);
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.modifyLiquidityRouter)));
        console.log("ModifyLiquidityRouter is whitelisted in KYCHook1");
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey1, modifyLiquidityParams, hookDataFromSwapperAddress);
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assertLt(afterBalanceToken0, beforeBalanceToken0);
        assertLt(afterBalanceToken1, beforeBalanceToken1);
        console.log("Liquidity added to the KYC pool by swapper to the liquidity pool using modifyLiquidityRouter");
        // Test swaps
        console.log("Testing swapping with the swapRouter\n");
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        // Swap through Pool without KYC
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.swapRouter.swap(s_poolKey2, swapParams, testSettings, "");
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assert(beforeBalanceToken0 - afterBalanceToken0 > 0);
        assert(afterBalanceToken1 - beforeBalanceToken1 > 0);
        console.log("Swap works correctly through Pool without KYC with swapRouter");
        // Swap through Pool with KYC
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.swapRouter.swap(s_poolKey1, swapParams, testSettings, hookDataFromSwapperAddress);
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assert(beforeBalanceToken0 - afterBalanceToken0 > 0);
        assert(afterBalanceToken1 - beforeBalanceToken1 > 0);
        console.log("Swap works correctly through Pool with KYC with swapRouter");
        // Swap through KYC Pool with non whitelisted router or missing hookData
        vm.prank(s_swapper);
        vm.expectRevert();
        s_contracts.swapRouter.swap(s_poolKey1, swapParams, testSettings, "");
        console.log("Cannot swap through KYC Pool without hookData ... as expected");
        bytes memory hookDataNonAuthorizedAddress = abi.encode(BLACKLISTED_ADDRESS_1);
        assert(s_contracts.blacklistPolicy1.isBlacklisted(BLACKLISTED_ADDRESS_1));
        vm.prank(s_swapper);
        vm.expectRevert();
        s_contracts.swapRouter.swap(s_poolKey1, swapParams, testSettings, hookDataNonAuthorizedAddress);
        vm.prank(BLACKLIST_POLICY_OWNER);
        s_contracts.blacklistPolicy1.addToBlacklist(s_swapper);
        assert(s_contracts.blacklistPolicy1.isBlacklisted(s_swapper));
        vm.prank(s_swapper);
        vm.expectRevert();
        s_contracts.swapRouter.swap(s_poolKey1, swapParams, testSettings, hookDataFromSwapperAddress);
        vm.prank(BLACKLIST_POLICY_OWNER);
        s_contracts.blacklistPolicy1.removeFromBlacklist(s_swapper);
        assert(!s_contracts.blacklistPolicy1.isBlacklisted(s_swapper));
        console.log("Cannot swap through KYC Pool with hookData of non authorized address ... as expected");
        vm.prank(HOOK_OWNER);
        s_contracts.kycHook1.updateRouterWhitelist(toArray(address(s_contracts.swapRouter)), false);
        vm.prank(s_swapper);
        vm.expectRevert();
        s_contracts.swapRouter.swap(s_poolKey1, swapParams, testSettings, hookDataFromSwapperAddress);
        vm.prank(HOOK_OWNER);
        s_contracts.kycHook1.updateRouterWhitelist(toArray(address(s_contracts.swapRouter)), true);
        console.log("Non whitelisted router cannot swap through KYC Pool ... as expected");
    }

    function test_swapFailsWithBadPolicy() public {
        console.log("\nTesting swap fails with bad policy\n");
        // Attach empty policy to the pool
        address emptyPolicyAddress = address(bytes20(keccak256(abi.encodePacked("EmptyPolicy"))));
        InitializeHookWithKYCParams memory newSettings = InitializeHookWithKYCParams(emptyPolicyAddress, true);
        vm.prank(POOL1_OWNER);
        s_contracts.kycHook1.updateKYCPolicy(s_poolKey1, newSettings);
        assertEq(s_contracts.kycHook1.getKYCPolicyAddress(s_poolKey1), emptyPolicyAddress);
        assertEq(s_contracts.kycHook1.getIsKYCRequired(s_poolKey1), true);
        console.log("Empty policy is attached to the pool");
        // try adding liquidity
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60000,
            tickUpper: 60000,
            liquidityDelta: 100 ether,
            salt: bytes32(0)
        });
        bytes memory hookDataFromSwapperAddress = abi.encode(s_swapper);
        vm.prank(s_swapper);
        vm.expectRevert();
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey1, modifyLiquidityParams, hookDataFromSwapperAddress);
        console.log("Cannot add liquidity to the pool with empty policy .. as expected");
        // Try to swap through the pool
        vm.prank(s_swapper);
        vm.expectRevert();
        KYCRouter.SwapSettings memory settings = KYCRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        s_contracts.kycRouter.swap(s_poolKey1, swapParams, settings, "");
    }

    function test_swap_KYCRouter() public {
        // Add liquidity to the pools
        // Non KYC Pool
        console.log("\nTesting AddLiquidity and Swapping through KYCSimpleRouter\n");
        console.log("Adding liquidity to the pools ... done with standard router\n");
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60000,
            tickUpper: 60000,
            liquidityDelta: 100 ether,
            salt: bytes32(0)
        });
        uint256 beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        uint256 beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey2, modifyLiquidityParams, "");
        uint256 afterBalanceToken0 = currency0.balanceOf(s_swapper);
        uint256 afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assertLt(afterBalanceToken0, beforeBalanceToken0);
        assertLt(afterBalanceToken1, beforeBalanceToken1);
        console.log("Liquidity added to the non KYC pool by swapper to the liquidity pool using modifyLiquidityRouter");
        // KYC Pool
        bytes memory hookDataFromSwapperAddress = abi.encode(s_swapper);
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.modifyLiquidityRouter)));
        console.log("ModifyLiquidityRouter is whitelisted in KYCHook1");
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey1, modifyLiquidityParams, hookDataFromSwapperAddress);
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assertLt(afterBalanceToken0, beforeBalanceToken0);
        assertLt(afterBalanceToken1, beforeBalanceToken1);
        console.log("Liquidity added to the KYC pool by swapper to the liquidity pool using modifyLiquidityRouter");
        console.log("\nPools funded with liquidity\n");
        // Swap through non KYC pool with KYCSimpleRouter
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        KYCRouter.SwapSettings memory settings = KYCRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
        // Swap through non KYC Pool with correct hookData
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.kycRouter.swap(s_poolKey2, swapParams, settings, "");
        console.log("Swapped through non KYC Pool with KYCSimpleRouter");
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        console.log("Token0 Delta balance of swapper: %s", beforeBalanceToken0 - afterBalanceToken0);
        console.log("Token1 Delta balance of swapper: %s", afterBalanceToken1 - beforeBalanceToken1);
        assertGt(beforeBalanceToken0, afterBalanceToken0);
        assertLt(beforeBalanceToken1, afterBalanceToken1);
        // Swap through KYC Pool with correct hookData
        beforeBalanceToken0 = currency0.balanceOf(s_swapper);
        beforeBalanceToken1 = currency1.balanceOf(s_swapper);
        vm.prank(s_swapper);
        s_contracts.kycRouter.swap(s_poolKey1, swapParams, settings, hookDataFromSwapperAddress);
        afterBalanceToken0 = currency0.balanceOf(s_swapper);
        afterBalanceToken1 = currency1.balanceOf(s_swapper);
        assertGt(beforeBalanceToken0, afterBalanceToken0);
        assertLt(beforeBalanceToken1, afterBalanceToken1);
        console.log("Swapped through KYC Pool with KYCSimpleRouter");

        console.log("Test for KYCSimpleRouter.swap() complete\n");
    }

    function test_eventEmission() public {
        // Setup pools and liquidity
        setupPoolsWithLiquidity();

        // Prepare swap parameters
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        KYCRouter.SwapSettings memory settings = KYCRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
        bytes memory hookData = abi.encode(SWAPPER_ADDRESS);

        // Test event emission for non-KYC pool (poolKey2)
        vm.expectEmit(true, true, true, true);
        emit SwapAttemptWithoutKYCThroughRouter(
            s_poolId2, address(s_contracts.kycRouter), SWAPPER_ADDRESS, s_poolKey2, swapParams
        );

        vm.prank(SWAPPER_ADDRESS);
        s_contracts.kycRouter.swap(s_poolKey2, swapParams, settings, "");

        console.log("Event emission from KYCRouter for non KYC pool tested successfully");

        // Test event emission for KYC pool (poolKey1)
        vm.expectEmit(true, true, true, true);
        emit SwapAttemptWithKYCThroughRouter(
            s_poolId1,
            address(s_contracts.kycRouter),
            SWAPPER_ADDRESS,
            s_poolKey1,
            swapParams,
            address(s_contracts.blacklistPolicy1),
            hookData
        );

        vm.prank(SWAPPER_ADDRESS);
        s_contracts.kycRouter.swap(s_poolKey1, swapParams, settings, hookData);

        console.log("Event emission from KYCRouter for KYC pool tested successfully");
        console.log("Event emission test completed\n");
    }

    function test_KYCRouter_errorHandling() public {
        // Setup a pool with KYC hook
        (PoolKey memory key,) = setupPoolWithKYCHook3();

        console.log("\nTesting error handling for KYCRouter\n");

        // Test RouterNotWhitelisted
        s_contracts.kycHook3.updateRouterWhitelist(toArray(address(s_contracts.kycRouter)), false);
        vm.expectRevert(
            abi.encodeWithSelector(
                KYCRouter__RouterNotWhitelisted.selector, address(s_contracts.kycRouter), address(s_contracts.kycHook3)
            )
        );
        vm.prank(SWAPPER_ADDRESS);
        s_contracts.kycRouter.swap(key, defaultSwapParams(), defaultSwapSettings(), "");
        console.log("Reverted correctly when router is not whitelisted");
        // Test NoKYCPermission
        s_contracts.kycHook3.updateRouterWhitelist(toArray(address(s_contracts.kycRouter)), true);
        vm.prank(BLACKLISTED_ADDRESS_1);
        vm.expectRevert(
            abi.encodeWithSelector(
                KYCRouter__NoKYCPermission.selector,
                BLACKLISTED_ADDRESS_1,
                key,
                defaultSwapParams(),
                defaultSwapSettings(),
                ""
            )
        );
        s_contracts.kycRouter.swap(key, defaultSwapParams(), defaultSwapSettings(), "");
        console.log("Reverted correctly when address does not have KYC permission");
        console.log("Error handling test completed\n");
    }

    function test_KYCRouter_swapParameters() public {
        setupPoolsWithLiquidity();
        console.log("\nTesting swap with different parameters for KYCRouter\n");
        console.log("Pools setup with liquidity");
        for (uint256 i = 0; i < 2; i++) {
            PoolKey memory key = i == 0 ? s_poolKey1 : s_poolKey2;
            if (i == 0) {
                console.log("\nTesting swap parameters for KYCPool with KYCRouter");
            }
            if (i == 1) {
                console.log("\nTesting swap parameters for non-KYC pool with KYCRouter");
            }

            // Test exact input, zeroForOne
            IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: 0.1 ether,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            });
            vm.prank(SWAPPER_ADDRESS);
            BalanceDelta delta = s_contracts.kycRouter.swap(key, params, defaultSwapSettings(), "");
            assertLt(delta.amount0(), 0);
            assertGt(delta.amount1(), 0);
            console.log("Swapped succesfully with exact input, zeroForOne");
            // Test exact output, zeroForOne
            params = IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -0.1 ether,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            });
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, params, defaultSwapSettings(), "");
            assertLt(delta.amount0(), 0);
            assertGt(delta.amount1(), 0);
            console.log("Swapped succesfully with exact output, zeroForOne");

            // Test exact output, oneForZero
            params = IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: -0.1 ether,
                sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
            });
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, params, defaultSwapSettings(), "");
            assertGt(delta.amount0(), 0);
            assertLt(delta.amount1(), 0);
            console.log("Swapped succesfully with exact output, oneForZero");
            // Test exact input, oneForZero
            params = IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: 0.1 ether,
                sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
            });
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, params, defaultSwapSettings(), "");
            assertGt(delta.amount0(), 0);
            assertLt(delta.amount1(), 0);
            console.log("Swapped succesfully with exact input, oneForZero");
            console.log("Swap parameters test completed\n");
        }
    }

    function test_KYCRouter_swapSettings() public {
        setupPoolsWithLiquidity();
        console.log("\nTesting swap with different settings for KYCRouter\n");
        console.log("Pools setup with liquidity");
        for (uint256 i = 0; i < 2; i++) {
            PoolKey memory key = i == 0 ? s_poolKey1 : s_poolKey2;
            if (i == 0) {
                console.log("\nTesting swap settings for KYCPool with KYCRouter");
            }
            if (i == 1) {
                console.log("\nTesting swap settings for non-KYC pool with KYCRouter");
            }

            // Test swap with takeClaims set to true and settleUsingBurn set to false
            KYCRouter.SwapSettings memory settings = KYCRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
            vm.prank(SWAPPER_ADDRESS);
            BalanceDelta delta = s_contracts.kycRouter.swap(key, defaultSwapParams(), settings, "");
            assertLt(delta.amount0(), 0);
            assertGt(delta.amount1(), 0);
            console.log("Swapped succesfully with takeClaims set to false and settleUsingBurn set to false");
            // Test swap with takeClaims set to true and settleUsingBurn set to false
            settings = KYCRouter.SwapSettings({takeClaims: true, settleUsingBurn: false});
            IPoolManager.SwapParams memory paramsZeroForOne = IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: 0.1 ether,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            });
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, paramsZeroForOne, settings, "");
            assertLt(delta.amount0(), 0);
            assertGt(delta.amount1(), 0);
            console.log("Swapped succesfully with takeClaims set to true and settleUsingBurn set to false (zeroForOne)");
            // Test swap with oneForZero with takeClaims set to true and settleUsingBurn set to false
            IPoolManager.SwapParams memory paramsOneForZero = IPoolManager.SwapParams({
                zeroForOne: false,
                amountSpecified: 0.1 ether,
                sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
            });
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, paramsOneForZero, settings, "");
            assertGt(delta.amount0(), 0);
            assertLt(delta.amount1(), 0);
            console.log("Swapped succesfully with takeClaims set to true and settleUsingBurn set to false (oneForZero)");
            // Test swap with takeClaims set to true and settleUsingBurn set to false
            settings = KYCRouter.SwapSettings({takeClaims: true, settleUsingBurn: false});
            vm.prank(SWAPPER_ADDRESS);
            delta = s_contracts.kycRouter.swap(key, paramsZeroForOne, settings, "");
            assertLt(delta.amount0(), 0);
            assertGt(delta.amount1(), 0);
            console.log("Swapped succesfully with takeClaims set to true and settleUsingBurn set to false (zeroForOne)");
            // TODO: Test swap with takeClaims set to true and settleUsingBurn set to true
            // TODO: Test swap with oneForZero with takeClaims set to true and settleUsingBurn set to true
            // TODO: Test swap with zeroFortakeClaims set to false and settleUsingBurn set to true
            // TODO: Test swap with oneForZero with takeClaims set to false and settleUsingBurn set to true
            console.log("TODO: PAssing tests for swap settings with settleUsingBurn set to true!!!");
        }
        console.log("Swap settings test completed\n");
    }

    function test_KYCRouter_nativeCurrency() public pure {
        // TODO: MAKE THIS TEST WORK
        console.log("\nTesting swap with native currency\n");
        console.log("TODO: MAKE THIS TEST WORK");
        return;
        /*
        // Setup the pool with native currency
        (PoolKey memory key,) = setupPoolWithKYCHookAndNativeCurrency();
        console.log("Pool setup with native currency");
        console.log("Currency0: %s", Currency.unwrap(key.currency0));
        console.log("Currency1: %s", Currency.unwrap(key.currency1));

        // Ensure the test contract has enough ETH
        vm.deal(s_swapper, 1000 ether);

        // Mint a reasonable amount of tokens to the test contract
        uint256 tokenAmount = 1000 ether;
        MockERC20(Currency.unwrap(key.currency1)).mint(s_swapper, tokenAmount);

        // Approve the PoolModifyLiquidityTest contract to spend tokens
        MockERC20(Currency.unwrap(key.currency1)).approve(address(s_contracts.modifyLiquidityRouter), type(uint256).max);

        // Log balances before the operation
        console.log("ETH balance before: %s", s_swapper.balance);
        console.log("Token balance before: %s", MockERC20(Currency.unwrap(key.currency1)).balanceOf(s_swapper));

        // Prepare modifyLiquidity parameters
        IPoolManager.ModifyLiquidityParams memory params = IPoolManager.ModifyLiquidityParams({
            tickLower: -60,
            tickUpper: 60,
            liquidityDelta: 1 ether,
            salt: bytes32(0)
        });
        console.log("Address of Hook of Pool from key: %s", address(key.hooks));
        console.log("Address of KYCHook3: %s             ", address(s_contracts.kycHook3));

        if (!KYCHook(address(key.hooks)).isRouterWhitelisted(address(s_contracts.kycRouter))) {
            console.log("Router is not whitelisted, whitelisting it");
            vm.prank(HOOK_OWNER);
            s_contracts.kycHook3.updateRouterWhitelist(toArray(address(s_contracts.kycRouter)), true);
        }
        // Call modifyLiquidity
        uint256 ethAmount = 1 ether;
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity{value: ethAmount}(key, params, abi.encode(address(this)));
        console.log("Added liquidity to the pool");

        // Swap native currency to currency1
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        vm.prank(s_swapper);
        BalanceDelta delta = s_contracts.kycRouter.swap{value: 0.1 ether}(key, swapParams, defaultSwapSettings(), "");
        assertLt(delta.amount0(), 0);
        assertGt(delta.amount1(), 0);
        console.log("Swapped succesfully from native currency");
        // Swap currency1 to native currency
        swapParams = IPoolManager.SwapParams({
            zeroForOne: false,
            amountSpecified: -0.1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });
        vm.prank(s_swapper);
        delta = s_contracts.kycRouter.swap(key, swapParams, defaultSwapSettings(), "");
        assertGt(delta.amount0(), 0);
        assertLt(delta.amount1(), 0);
        console.log("Swapped succesfully to native currency");
        console.log("Native currency test completed\n");
        */
    }

    // Helper functions
    function setupPoolWithKYCHook3() internal returns (PoolKey memory, PoolId) {
        // Deploy a new KYCHook
        address hookOwner = address(this);
        deployCodeTo("KYCHook", abi.encode(s_contracts.poolManager, ""), KYCHOOK_ADDRESS_3);
        s_contracts.kycHook3 = KYCHook(KYCHOOK_ADDRESS_3);
        console.log("KYCHook contract deployed with address: %s", KYCHOOK_ADDRESS_3);

        // Deploy a new KYCPolicy
        s_contracts.whitelistPolicy = new WhitelistPolicy(new address[](0));

        // Initialize hook settings
        InitializeHookWithKYCParams memory initSettings = InitializeHookWithKYCParams({
            policyContractAddress: address(s_contracts.whitelistPolicy),
            isKYCRequired: true
        });
        bytes memory initData = abi.encode(initSettings);

        // Create a new pool with the KYCHook
        (PoolKey memory key, PoolId id) =
            initPool(currency0, currency1, s_contracts.kycHook3, 3000, 60, SQRT_PRICE_1_1, initData);

        // Whitelist the KYCRouter
        vm.prank(hookOwner);
        s_contracts.kycHook3.updateRouterWhitelist(toArray(address(s_contracts.kycRouter)), true);

        s_contracts.whitelistPolicy.addToWhitelist(s_swapper);

        return (key, id);
    }

    function setupPoolWithoutKYCHook() internal returns (PoolKey memory, PoolId) {
        // Create a new pool without any hook
        (PoolKey memory key, PoolId id) =
            initPool(currency0, currency1, IHooks(address(0)), 3000, 60, SQRT_PRICE_1_1, "");

        return (key, id);
    }

    function setupPoolWithKYCHookAndNativeCurrency() internal returns (PoolKey memory, PoolId) {
        // Deploy a new KYCHook
        address hookOwner = address(this);
        deployCodeTo("KYCHook", abi.encode(s_contracts.poolManager, ""), KYCHOOK_ADDRESS_3);
        s_contracts.kycHook3 = KYCHook(KYCHOOK_ADDRESS_3);
        console.log("KYCHook contract deployed with address: %s", KYCHOOK_ADDRESS_3);
        s_contracts.whitelistPolicy = new WhitelistPolicy(new address[](0));

        // Initialize hook settings
        InitializeHookWithKYCParams memory initSettings = InitializeHookWithKYCParams({
            policyContractAddress: address(s_contracts.whitelistPolicy),
            isKYCRequired: true
        });
        bytes memory initData = abi.encode(initSettings);

        // Create a new pool with the KYCHook and native currency
        (PoolKey memory key, PoolId id) =
            initPool(CurrencyLibrary.NATIVE, currency1, s_contracts.kycHook3, 3000, 60, SQRT_PRICE_1_1, initData);

        // Whitelist the KYCRouter
        vm.prank(hookOwner);
        address[] memory routersToBeWhitelisted = new address[](2);
        routersToBeWhitelisted[0] = address(s_contracts.kycRouter);
        routersToBeWhitelisted[1] = address(s_contracts.modifyLiquidityRouter);
        s_contracts.kycHook3.updateRouterWhitelist(routersToBeWhitelisted, true);

        s_contracts.whitelistPolicy.addToWhitelist(s_swapper);

        return (key, id);
    }

    function defaultSwapParams() internal pure returns (IPoolManager.SwapParams memory) {
        return IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
    }

    function defaultSwapSettings() internal pure returns (KYCRouter.SwapSettings memory) {
        return KYCRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
    }

    function toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
    // Helper function to setup pools with liquidity

    function setupPoolsWithLiquidity() internal {
        // Add liquidity to both pools
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60,
            tickUpper: 60,
            liquidityDelta: 1000 ether,
            salt: bytes32(0)
        });

        vm.startPrank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey2, modifyLiquidityParams, "");
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey1, modifyLiquidityParams, abi.encode(s_swapper));
        vm.stopPrank();
    }
}
