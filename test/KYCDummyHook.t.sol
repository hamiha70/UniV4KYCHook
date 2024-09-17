// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";

import {KYCDummyHook} from "../src/hooks/KYCDummyHook.sol";
import {KYCDummyPolicy} from "../src/policies/KYCDummyPolicy.sol";
import {Policy} from "../src/base/Policy.sol";

import {TickMath} from "v4-core/libraries/TickMath.sol";

import {console} from "forge-std/console.sol";

contract TestKYCBasecHook is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;
    using TickMath for int24;
    using TickMath for uint160;

    KYCDummyHook hook;
    Policy policy;

    function setUp() public {
        //Deploy v4-core
        console.log("Deploying v4-core");
        deployFreshManagerAndRouters();

        //Deploy, mint tokens and approve all periphery contracts for two tokens
        console.log("Deploying and mint 2 currencies");
        deployMintAndApprove2Currencies();
        console.log("Currency0: %s", Currency.unwrap(currency0));
        console.log("Currency1: %s", Currency.unwrap(currency1));

        //Deploy dummy policy
        address policyAddress = address(bytes20(keccak256(abi.encodePacked("DummyPolicy"))));
        deployCodeTo("KYCDummyPolicy", abi.encode(manager, ""), policyAddress);
        policy = KYCDummyPolicy(policyAddress);
        console.log("Policy contract with address: %s", policyAddress);

        //Deploy the hook with the proper flags
        address hookAddress = address(uint160(Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG));
        //Note: constructor of KYCBaseHook takes arguments (IPoolManager _manager, string memory _uri, address _policyContractAddress)
        deployCodeTo("KYCDummyHook", abi.encode(manager, "", policyAddress), hookAddress);
        hook = KYCDummyHook(hookAddress);
        console.log("Hook address: %s", hookAddress);

        //Initialze a pool
        (key,) = initPool(currency0, currency1, hook, 3000, SQRT_PRICE_1_1, ZERO_BYTES);
        // Check pool parameters
        console.log("Poolkey:");
        console.log("Currency0: %s", Currency.unwrap(key.currency0));
        console.log("Currency1: %s", Currency.unwrap(key.currency1));
        console.log("Fee: %d", key.fee);
        console.log("TickSpacing: %d", key.tickSpacing);
        console.log("Hook: %s", address(key.hooks));

        console.log("Reading pool parameters from storage");

        (uint160 sqrtPriceX96, int24 currentTick, uint24 protocolFee, uint24 lpFee) = manager.getSlot0(key.toId());
        int24 currentTickCalculated = sqrtPriceX96.getTickAtSqrtPrice();
        uint160 sqrtPriceX96Calculated = currentTick.getSqrtPriceAtTick();
        console.log("sqrtPriceX96 (from memory): %d", sqrtPriceX96);
        console.log("sqrtPriceX96 (calculated):  %d", sqrtPriceX96Calculated);
        console.log("CurrentTick (from memory): %d", currentTick);
        console.log("CurrentTick (calculated):  %d", currentTickCalculated);
        console.log("ProtocolFee: %d", protocolFee);
        console.log("LpFee: %d", lpFee);

        // Need to approve hook address to spend the tokens as well!!!
        MockERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        MockERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);

        //Check balance of the 2 currencies
        uint256 balanceCurrency0 = MockERC20(Currency.unwrap(currency0)).balanceOf(address(this));
        uint256 balanceCurrency1 = MockERC20(Currency.unwrap(currency1)).balanceOf(address(this));
        uint256 liquidityProvidedDuringSetup = 100 ether;
        console.log("Currency0 balance: %d", balanceCurrency0);
        console.log("Currency1 balance: %d", balanceCurrency1);
        console.log("Balance 100 ether: %d", liquidityProvidedDuringSetup);

        // Add some liquidity
        console.log("Adding liquidity");

        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: 100 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );
        console.log("Setup complete");
    }

    function test_validateSwapAuthorization() public view {
        // Check validation funnctions
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        bool swapAuthorized = policy.validateSwapAuthorization(msg.sender, key, swapParams);
        assertEq(swapAuthorized, false, "Swap should not be authorized");

        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60,
            tickUpper: 60,
            liquidityDelta: 100 ether,
            salt: bytes32(0)
        });
        bool addLiquidityAuthorized = policy.validateAddLiquidityAuthorization(msg.sender, key, modifyLiquidityParams);
        assertEq(addLiquidityAuthorized, true, "Add liquidity should be authorized");
    }

    function test_beforeSwap() public {
        // set up swap paramters
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });

        // Initiate swap - should fail
        vm.expectRevert();
        swapRouter.swap(key, swapParams, testSettings, ZERO_BYTES);
    }

    function test_beforeAddLiquidity() public {
        // set up swap paramters
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -60,
            tickUpper: 60,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });

        // call beforeAddLiquidity
        modifyLiquidityRouter.modifyLiquidity(key, modifyLiquidityParams, ZERO_BYTES);
    }
}
