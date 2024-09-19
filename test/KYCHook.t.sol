// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";

import {KYCHook, InitializeHookWithKYCParams} from "../src/hooks/KYCHook.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {BlackWhitelistPolicy} from "../src/policies/BlackWhitelistPolicy.sol";
import {Policy} from "../src/base/Policy.sol";
import {KYCPolicy} from "../src/base/KYCPolicy.sol";

import {TickMath} from "v4-core/libraries/TickMath.sol";
import {console} from "forge-std/console.sol";
import {KYCEvents} from "../src/utils/events.sol";

contract TestKYCHook is Test, Deployers, KYCEvents {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;
    using TickMath for int24;
    using TickMath for uint160;

    // Constants
    address constant HOOK_OWNER = address(bytes20(keccak256(abi.encodePacked("HookOwner"))));
    address constant POLICY_OWNER = address(bytes20(keccak256(abi.encodePacked("BlackWhitelistPolicyOwner"))));
    address constant RANDOM_ADDRESS = address(0x0234000);
    address constant USDC_BANNED_EXAMPLE = address(0x0AbF039DFf7FF57D7a290362b64FFcd82009E8a9);
    address constant USDC_ALLOWED_EXAMPLE = address(0x0aBf039dFF7FF57d7a290362B64FFcD82009E8a8);
    address constant EXAMPLE1 = address(0x0FEf039dff7FF57d7a290362B64Ffcd82009E8A7);
    address constant EXAMPLE2 = address(0x0abF039dfF7Ff57D7A290362B64FFcD82009e8A6);
    address constant EXAMPLE3 = address(0x0aBF039dff7FF57D7A290362B64Ffcd82009E8Aa);
    address constant EXAMPLE4 = address(0x0AbF039dfF7Ff57d7a290362B64FFcd82009e8aB);
    address constant EXPLICIT_WHITELISTED_EXAMPLE = address(0x0AbF039dFF7ff57D7A290362B64fFcD82009E8a5);
    address constant EXPLICIT_BLACKLISTED_EXAMPLE = address(0x0AbF039DFf7ff57D7a290362B64ffCD82009E8A4);
    address constant EXPLICIT_ALLOWED_EXAMPLE2 = address(0x0ABF039dFf7ff57D7A290362B64fFCD82009e8a3);
    address constant EXPLICIT_BANNED_EXAMPLE2 = address(0x0aBF039dFf7ff57D7a290362b64ffcd82009E8A2);
    address constant EXAMPLE_ON_BOTH_LISTS = address(0x0Abf039dFf7ff57D7a290362B64FfCD82009E8a1);
    address constant EXAMPLE_NOT_ON_ANY_LIST = address(0x0ABf039DfF7Ff57D7A290362b64ffCd82009e8a0);

    uint160 constant HOOK_OFFSET = uint160(12330815 * 2 ** 24); // distinguish from other hooks
    address constant HOOK_ADDRESS = address(
        uint160(
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
                | Hooks.AFTER_INITIALIZE_FLAG | HOOK_OFFSET
        )
    );
    // State variables
    address payable s_swapper = payable(address(0x1234567890123456789012345678901234567890));
    BlackWhitelistPolicy s_policy;
    WhitelistPolicy s_whitelistPolicy;
    BlacklistPolicy s_blacklistPolicy;
    KYCHook s_hook;
    IPoolManager s_poolManager;
    PoolSwapTest s_swapRouter;
    PoolModifyLiquidityTest s_modifyLiquidityRouter;
    Currency s_currency0;
    Currency s_currency1;
    address[] s_initialWhitelist;
    address[] s_initialBlacklist;

    function setUp() public {
        console.log("\nSetting up test\n");
        _initializeArrays();
        _deployV4Core();
        _deployAndMintCurrencies();
        _deployPolicies();
        _deployAndSetupHook();
        _dealTokensToSwapperAndAddressThis();
        _approveSwapperWithRouters();
        console.log("Setup complete\n");
    }

    function _initializeArrays() private {
        s_initialWhitelist = [EXPLICIT_WHITELISTED_EXAMPLE, EXAMPLE_ON_BOTH_LISTS];
        s_initialBlacklist = [EXPLICIT_BLACKLISTED_EXAMPLE, EXAMPLE_ON_BOTH_LISTS];
    }

    function _deployAndMintCurrencies() private {
        console.log("Deploying and mint 2 currencies");
        (s_currency0, s_currency1) = deployMintAndApprove2Currencies();
        console.log("Currency0: %s", Currency.unwrap(s_currency0));
        console.log("Currency1: %s", Currency.unwrap(s_currency1));
    }

    function _deployV4Core() private {
        console.log("Deploying v4-core");
        deployFreshManagerAndRouters();
        s_poolManager = IPoolManager(address(manager));
        s_swapRouter = swapRouter;
        s_modifyLiquidityRouter = modifyLiquidityRouter;
        console.log("PoolManager address: %s", address(manager));
        console.log("SwapRouter address: %s", address(s_swapRouter));
        console.log("ModifyLiquidityRouter address: %s", address(s_modifyLiquidityRouter));
        console.log("v4-core deployed\n");
    }

    function _deployPolicies() private {
        console.log("\nDeploying policies");
        _deployBlacklistPolicy();
        _deployWhitelistPolicy();
        _deployBlackWhitelistPolicy();
        console.log("Policies deployed\n");
    }

    function _deployBlacklistPolicy() private {
        s_blacklistPolicy = new BlacklistPolicy(s_initialBlacklist);
        console.log("BlacklistPolicy contract deployed with address: %s", address(s_blacklistPolicy));
    }

    function _deployWhitelistPolicy() private {
        s_whitelistPolicy = new WhitelistPolicy(s_initialWhitelist);
        console.log("WhitelistPolicy contract deployed with address: %s", address(s_whitelistPolicy));
    }

    function _deployBlackWhitelistPolicy() private {
        s_policy = new BlackWhitelistPolicy(s_initialWhitelist, s_initialBlacklist);
        console.log("BlackWhitelistPolicy contract deployed with address: %s", address(s_policy));
    }

    function _deployAndSetupHook() private {
        console.log("\nDeploying hook");
        //Deploy Blackwhitelist hook attached hook with the proper flags
        console.log("Hook address: %s", HOOK_ADDRESS);
        console.log("Deploying KYCHook with manager: %s", address(s_poolManager));

        //Deploy Whitelist hook attached hook with the proper flags
        vm.prank(HOOK_OWNER);
        deployCodeTo("KYCHook", abi.encode(address(s_poolManager), "KYCHook"), HOOK_ADDRESS);
        s_hook = KYCHook(HOOK_ADDRESS);
        console.log("KYCHook address: %s", HOOK_ADDRESS);

        // Use the new updateWhitelist function
        _whitelistRouters();
        console.log("Routers whitelisted with KYCHook");
        // Approve the hook to spend the tokens on behalf of the routers
    }

    function _dealTokensToSwapperAndAddressThis() private {
        console.log("Dealing native tokens to swapper");
        vm.deal(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(s_currency0)).mint(s_swapper, 1000 ether);
        MockERC20(Currency.unwrap(s_currency1)).mint(s_swapper, 1000 ether);
        console.log("Tokens minted to swapper");
        MockERC20(Currency.unwrap(s_currency0)).mint(address(this), 1000 ether);
        MockERC20(Currency.unwrap(s_currency1)).mint(address(this), 1000 ether);
        console.log("Tokens minted to addressThis");
    }

    function _approveSwapperWithRouters() private {
        console.log("Approving swapper with routers");
        address[2] memory toApprove = [address(swapRouter), address(modifyLiquidityRouter)];
        for (uint256 i = 0; i < toApprove.length; i++) {
            vm.startPrank(s_swapper);
            MockERC20(Currency.unwrap(s_currency0)).approve(toApprove[i], type(uint256).max);
            MockERC20(Currency.unwrap(s_currency1)).approve(toApprove[i], type(uint256).max);
            vm.stopPrank();
        }
        console.log("Swapper approved with routers: swapRouter and modifyLiquidityRouter");
    }

    function _whitelistRouters() private {
        vm.startPrank(HOOK_OWNER);
        address[] memory routersToWhitelist = new address[](3);
        routersToWhitelist[0] = address(swapRouter);
        routersToWhitelist[1] = address(modifyLiquidityRouter);
        routersToWhitelist[2] = RANDOM_ADDRESS;
        s_hook.updateRouterWhitelist(routersToWhitelist, true);
        console.log(
            "Routers whitelisted: %s, %s, %s", address(swapRouter), address(modifyLiquidityRouter), RANDOM_ADDRESS
        );
        vm.stopPrank();
    }

    function test_setup() public view {
        console.log("Testing setup");
        console.log("Hook owner: %s", s_hook.getHookOwner());
        console.log("Is SwapRouter whitelisted: %s", s_hook.isRouterWhitelisted(address(s_swapRouter)));
        console.log(
            "Is ModifyLiquidityRouter whitelisted: %s", s_hook.isRouterWhitelisted(address(s_modifyLiquidityRouter))
        );
        require(s_hook.isRouterWhitelisted(address(s_swapRouter)), "SwapRouter should be whitelisted");
        require(
            s_hook.isRouterWhitelisted(address(s_modifyLiquidityRouter)), "ModifyLiquidityRouter should be whitelisted"
        );
    }

    function test_hookNormalExecution() public {
        (PoolKey memory key, bytes memory hookData) = _setupPoolAndHookData();
        _testAddLiquidity(key, hookData);
        _testSwapping(key, hookData);
    }

    function test_eventEmission() public {
        (PoolKey memory key, bytes memory hookData) = _setupPoolAndHookData();
        
        // Test event emission for ModifyLiquidityThroughKYCHook
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -6000,
            tickUpper: 6000,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });

        s_whitelistPolicy.addToWhitelist(address(this));
        
        vm.expectEmit(true, true, true, true);
        emit ModifyLiquidityThroughKYCHook(
            key.toId(),
            address(modifyLiquidityRouter),
            address(this),
            key,
            modifyLiquidityParams,
            address(s_whitelistPolicy),
            hookData
        );
        modifyLiquidityRouter.modifyLiquidity(key, modifyLiquidityParams, hookData);

        // Test event emission for SwapThroughKYCHook
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({
            takeClaims: false,
            settleUsingBurn: false
        });

        vm.expectEmit(true, true, true, true);
        emit SwapThroughKYCHook(
            key.toId(),
            address(swapRouter),
            address(this),
            key,
            swapParams,
            address(s_whitelistPolicy),
            hookData
        );
        swapRouter.swap(key, swapParams, testSettings, hookData);
    }

    function _setupPoolAndHookData() private returns (PoolKey memory, bytes memory) {
        InitializeHookWithKYCParams memory initializeSettings =
            InitializeHookWithKYCParams(address(s_whitelistPolicy), true);
        address addressThis = address(this);
        PoolKey memory key;
        PoolId poolId;
        bytes memory initData = abi.encode(initializeSettings);
        (key, poolId) = initPool(currency0, currency1, s_hook, 3000, int24(60), SQRT_PRICE_1_1, initData);
        console.log("Pool initialized with WhitelistHook");
        bytes memory hookData = s_whitelistPolicy.hookDataFromMsgSender(addressThis);
        return (key, hookData);
    }

    function _testAddLiquidity(PoolKey memory key, bytes memory hookData) private {
        address addressThis = address(this);
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -6000,
            tickUpper: 6000,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });

        if (!s_hook.isRouterWhitelisted(address(s_modifyLiquidityRouter))) {
            console.log("Try adding liquidity through an non authorized Router (from hook perspective):", addressThis);
            vm.expectRevert();
            modifyLiquidityRouter.modifyLiquidity(key, modifyLiquidityParams, hookData);
            console.log("AddLiquidity was blocked as expected");
            vm.prank(HOOK_OWNER);
            address[] memory routersToWhitelist = new address[](1);
            routersToWhitelist[0] = address(s_modifyLiquidityRouter);
            s_hook.updateRouterWhitelist(routersToWhitelist, true);
        }

        console.log("Try adding liquidity through an not authorized original address in the policy:", addressThis);
        require(!s_whitelistPolicy.isWhitelisted(addressThis), "addressThis should not be whitelisted initially");
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(key, modifyLiquidityParams, hookData);
        console.log("AddLiquidity was blocked as expected as original sender is not whitelisted");

        s_whitelistPolicy.addToWhitelist(addressThis);
        require(s_whitelistPolicy.isWhitelisted(addressThis), "addressThis should be whitelisted now");
        console.log("Try adding liquidity through an authorized address:", addressThis);
        uint256 balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        modifyLiquidityRouter.modifyLiquidity(key, modifyLiquidityParams, hookData);
        uint256 balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        assertLt(balanceToken0After, balanceToken0Before, "Balance of token0 should have decreased");
        assertLt(balanceToken1After, balanceToken1Before, "Balance of token1 should have decreased");
        console.log("AddLiquidity successful by addressThis");
    }

    function _testSwapping(PoolKey memory key, bytes memory hookData) private {
        address addressThis = address(this);
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        console.log("\nTest Swapping\n");

        if (!s_hook.isRouterWhitelisted(address(s_swapRouter))) {
            console.log("Try swapping through an non authorized address:", addressThis);
            vm.expectRevert();
            swapRouter.swap(key, swapParams, testSettings, hookData);
            console.log("Swap was blocked as expected");
            vm.prank(HOOK_OWNER);
            address[] memory routersToWhitelist = new address[](1);
            routersToWhitelist[0] = address(s_swapRouter);
            s_hook.updateRouterWhitelist(routersToWhitelist, true);
        }

        console.log("Try swapping through an authorized address:", addressThis);
        require(s_whitelistPolicy.isWhitelisted(addressThis), "addressThis should be whitelisted");
        uint256 balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        swapRouter.swap(key, swapParams, testSettings, hookData);
        uint256 balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        assertLt(balanceToken0After, balanceToken0Before, "Balance of token0 should have decreased");
        assertGt(balanceToken1After, balanceToken1Before, "Balance of token1 should have decreased");
        console.log("Swap successful by addressThis");

        // Remove addressThis from whitelist
        s_whitelistPolicy.removeFromWhitelist(addressThis);
        require(!s_whitelistPolicy.isWhitelisted(addressThis), "addressThis should not be whitelisted now");
        // Try swapping again
        console.log("Try swapping through an non authorized address:", addressThis);
        vm.expectRevert();
        swapRouter.swap(key, swapParams, testSettings, hookData);
        console.log("Swap was blocked as expected");
    }
}
