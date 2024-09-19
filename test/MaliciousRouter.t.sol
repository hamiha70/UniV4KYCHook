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
import {MaliciousRouter} from "../src/routers/MaliciousRouter.sol";
import {KYCHook, InitializeHookWithKYCParams} from "../src/hooks/KYCHook.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {KYCEvents} from "../src/utils/events.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {console} from "forge-std/console.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";

contract MaliciousRouterTest is Test, Deployers, KYCEvents {
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
        MaliciousRouter maliciousRouter;
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
    address s_fakeSwapperAddress = address(RANDOM_ADDRESS);
    bytes s_fakeHookData = abi.encode(s_fakeSwapperAddress);

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
        routersToWhitelist[0] = address(s_contracts.maliciousRouter);
        s_contracts.kycHook1.updateRouterWhitelist(routersToWhitelist, true);

        // Deploy MaliciousRouter
        vm.prank(KYC_ROUTER_OWNER);
        s_contracts.maliciousRouter = new MaliciousRouter(s_contracts.poolManager);
        console.log("MaliciousRouter contract deployed with address: %s", address(s_contracts.maliciousRouter));

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
            address(s_contracts.maliciousRouter)
        ];
        for (uint256 i = 0; i < toApprove.length; i++) {
            vm.startPrank(s_swapper);
            MockERC20(Currency.unwrap(currency0)).approve(toApprove[i], type(uint256).max);
            MockERC20(Currency.unwrap(currency1)).approve(toApprove[i], type(uint256).max);
            vm.stopPrank();
            vm.startPrank(s_fakeSwapperAddress);
            MockERC20(Currency.unwrap(currency0)).approve(toApprove[i], type(uint256).max);
            MockERC20(Currency.unwrap(currency1)).approve(toApprove[i], type(uint256).max);
            vm.stopPrank();
        }
        console.log("Approved all Routers to spend on behalf of Swapper ... and the fake swapper");

        // Deal ETH and tokens to Swapper
        vm.deal(s_swapper, 1000 ether);
        vm.deal(s_fakeSwapperAddress, 1000 ether);
        MockERC20(Currency.unwrap(currency0)).mint(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(currency1)).mint(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(currency0)).mint(s_fakeSwapperAddress, 1000 ether);
        MockERC20(Currency.unwrap(currency1)).mint(s_fakeSwapperAddress, 1000 ether);
        console.log(
            "Swapper has %s of currency0 and %s of currency1 and %s ether",
            MockERC20(Currency.unwrap(currency0)).balanceOf(s_swapper),
            MockERC20(Currency.unwrap(currency1)).balanceOf(s_swapper),
            address(s_swapper).balance
        );
        console.log(
            "Fake swapper has %s of currency0 and %s of currency1 and %s ether",
            MockERC20(Currency.unwrap(currency0)).balanceOf(s_fakeSwapperAddress),
            MockERC20(Currency.unwrap(currency1)).balanceOf(s_fakeSwapperAddress),
            address(s_fakeSwapperAddress).balance
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
        routersToWhitelist2[0] = address(s_contracts.maliciousRouter);
        routersToWhitelist2[1] = address(s_contracts.swapRouter);
        routersToWhitelist2[2] = address(s_contracts.modifyLiquidityRouter);
        s_contracts.kycHook1.updateRouterWhitelist(routersToWhitelist2, true);
        vm.stopPrank();

        // Approve PoolManager on behalf of MaliciousRouter for both tokens
        vm.startPrank(KYC_ROUTER_OWNER);
        MockERC20(Currency.unwrap(currency0)).approve(address(s_contracts.poolManager), type(uint256).max);
        MockERC20(Currency.unwrap(currency1)).approve(address(s_contracts.poolManager), type(uint256).max);
        console.log("Approved PoolManager on behalf of MaliciousRouter for both tokens");
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
            MockERC20(Currency.unwrap(currency0)).allowance(s_swapper, address(s_contracts.maliciousRouter)),
            type(uint256).max
        );
        assertEq(
            MockERC20(Currency.unwrap(currency1)).allowance(s_swapper, address(s_contracts.maliciousRouter)),
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
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.maliciousRouter)));
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
        // Check the fake swapper address is not blacklisted
        assert(!s_contracts.blacklistPolicy1.isBlacklisted(s_fakeSwapperAddress));
        console.log("Fake swapper address is not blacklisted");
        // Check the fake swapper address conversion is correct
        assertEq(s_fakeHookData, abi.encode(s_fakeSwapperAddress));
        console.log("Fake swapper address conversion is correct");

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
        MaliciousRouter.SwapSettings memory settings = MaliciousRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        s_contracts.maliciousRouter.swap(s_poolKey1, swapParams, settings, "");
    }

    function test_swapCorrectSwapper_maliciousRouter_shouldSucceedAndEmitEventIfNotBlacklisted() public {
        // Add liquidity to the pools
        setupPoolsWithLiquidity();

        // Test swap through non-KYC pool
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        MaliciousRouter.SwapSettings memory settings = MaliciousRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});

        assert(!s_contracts.blacklistPolicy1.isBlacklisted(s_fakeSwapperAddress));
        console.log("Fake swapper is not blacklisted and should be able to swap without cheating");

        uint256 beforeBalanceToken0 = currency0.balanceOf(s_fakeSwapperAddress);
        uint256 beforeBalanceToken1 = currency1.balanceOf(s_fakeSwapperAddress);

        bytes memory correctHookData = abi.encode(s_fakeSwapperAddress);

        vm.prank(s_fakeSwapperAddress);
        vm.expectEmit(true, true, true, true);
        emit SwapAttemptThroughMaliciousRouter(
            s_poolId2,
            address(s_contracts.maliciousRouter),
            s_fakeSwapperAddress,
            s_poolKey2,
            swapParams,
            correctHookData
        );
        s_contracts.maliciousRouter.swap(s_poolKey2, swapParams, settings, correctHookData);
        console.log("Swap through non KYC Pool with MaliciousRouter emits correct event");

        uint256 afterBalanceToken0 = currency0.balanceOf(s_fakeSwapperAddress);
        uint256 afterBalanceToken1 = currency1.balanceOf(s_fakeSwapperAddress);

        assertGt(beforeBalanceToken0, afterBalanceToken0);
        assertLt(beforeBalanceToken1, afterBalanceToken1);
        console.log("Swapped through non KYC Pool with MaliciousRouter and correct information succededc ... as expected");

        // Test swap through KYC pool
        beforeBalanceToken0 = currency0.balanceOf(s_fakeSwapperAddress);
        beforeBalanceToken1 = currency1.balanceOf(s_fakeSwapperAddress);

        vm.prank(s_fakeSwapperAddress);
        vm.expectEmit(true, true, true, true);
        emit SwapAttemptThroughMaliciousRouter(
            s_poolId1,
            address(s_contracts.maliciousRouter),
            s_fakeSwapperAddress,
            s_poolKey1,
            swapParams,
            correctHookData
        );
        s_contracts.maliciousRouter.swap(s_poolKey1, swapParams, settings, correctHookData);

        afterBalanceToken0 = currency0.balanceOf(s_fakeSwapperAddress);
        afterBalanceToken1 = currency1.balanceOf(s_fakeSwapperAddress);

        assertGt(beforeBalanceToken0, afterBalanceToken0);
        assertLt(beforeBalanceToken1, afterBalanceToken1);
        console.log("Swapped through KYC Pool with MaliciousRouter and correct information ... as expected");
    }

    function test_swapFakedSwapper_maliciousRouter_withBlacklistedUser_shouldSucceedAndEmitEvent() public {
        setupPoolsWithLiquidity();

        // Blacklist the swapper
        vm.prank(BLACKLIST_POLICY_OWNER);
        s_contracts.blacklistPolicy1.addToBlacklist(s_swapper);
        assert(s_contracts.blacklistPolicy1.isBlacklisted(s_swapper));
        console.log("Swapper is blacklisted now");

        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.1 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        MaliciousRouter.SwapSettings memory settings = MaliciousRouter.SwapSettings({takeClaims: false, settleUsingBurn: false});

        vm.prank(s_swapper);
        vm.expectEmit(true, true, true, true);
        emit MaliciousSwapAttemptThroughKYCRouter(
            s_poolId1,
            address(s_contracts.maliciousRouter),
            s_swapper,
            s_poolKey1,
            swapParams,
            s_fakeSwapperAddress,
            address(s_contracts.blacklistPolicy1),
            s_fakeHookData
        );
        BalanceDelta delta = s_contracts.maliciousRouter.swap(s_poolKey1, swapParams, settings, s_fakeHookData);
        console.log("Swap through KYC Pool with MaliciousRouter emitted correct event for blacklisted user");

        // Check that the swap succeeds
        assert(delta.amount0() != 0 || delta.amount1() != 0);
        console.log("Swap through KYC Pool with MaliciousRouter succeeded for blacklisted user as expected ... due to faking a different address");
    }

    function setupPoolsWithLiquidity() private {
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60000,
            tickUpper: 60000,
            liquidityDelta: 100 ether,
            salt: bytes32(0)
        });
        bytes memory hookDataFromSwapperAddress = abi.encode(s_swapper);

        // Add liquidity to non-KYC pool
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey2, modifyLiquidityParams, "");

        // Add liquidity to KYC pool
        assert(s_contracts.kycHook1.isRouterWhitelisted(address(s_contracts.modifyLiquidityRouter)));
        vm.prank(s_swapper);
        s_contracts.modifyLiquidityRouter.modifyLiquidity(s_poolKey1, modifyLiquidityParams, hookDataFromSwapperAddress);
    }

    function toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}