// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "v4-core/types/BalanceDelta.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolTestBase} from "v4-core/test/PoolTestBase.sol";
import {CurrencySettler} from "@uniswap/v4-core/test/utils/CurrencySettler.sol";
import {KYCEvents} from "../utils/events.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {KYCHook} from "../hooks/KYCHook.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";

// Errors
error LazyRouter__PolicyMisbehaving__CallToHookDataFromMsgSenderReverted();
error LazyRouter__KYCHookMisbehaving__CallToGetKYCPolicyAddressReverted();

//@dev This router is designed to work in conjunction with the KYCHook, but allows for lazy KYC checks.
//@dev The router exposes the swap(PoolKey, SwapParams, SwapSettings, hookData) function to any user EOA or contract that intends to swap.
//@dev The LazyRouter attempts to execute the swap without prior KYC checks.
//@dev If the pool has a KYCHook, the router will try to retrieve the KYCPolicy address and get hookData from the policy.
//@dev If retrieving the KYCPolicy or getting hookData fails, the router falls back to the original hookData.
//@dev The KYC checks are performed by the KYCHook during the swap execution, not by the LazyRouter beforehand.
//@dev The LazyRouter does not store any state with respect to KYCHooks or KYCPolicies. Those are retrieved from the relevant contracts based on the PoolKey.
//@dev The LazyRouter is implemented defensively, gracefully handling cases where the KYCPolicy or KYCHook do not adhere to the expected interface.
//@dev The LazyRouter emits an event for each swap attempt.
//@dev The LazyRouter is initialized with the address of the PoolManager and does not keep state related to Pools, KYCPolicies, or KYCHooks.
//@dev It attempts to retrieve the KYCPolicy address from the KYCHook based on the PoolKey, but proceeds with the swap even if this fails.
//@dev The LazyRouter is implemented as an extension of the PoolSwapRouter in v4-periphery, with modifications for lazy KYC checking.
contract LazyRouter is PoolTestBase, Ownable, KYCEvents {
    using CurrencySettler for Currency;
    using Hooks for IHooks;
    using PoolIdLibrary for PoolKey;

    constructor(IPoolManager _manager) Ownable(msg.sender) PoolTestBase(_manager) {}

    struct CallbackData {
        address sender;
        SwapSettings testSettings;
        PoolKey key;
        IPoolManager.SwapParams params;
        bytes hookData;
    }

    struct SwapSettings {
        bool takeClaims;
        bool settleUsingBurn;
    }

    function swap(
        PoolKey memory key,
        IPoolManager.SwapParams memory params,
        SwapSettings memory testSettings,
        bytes memory hookData
    ) external payable returns (BalanceDelta delta) {
        // Attempt swap without prior checks
        emit LazySwapAttemptThroughRouter(key.toId(), address(this), msg.sender, key, params);
        
        bytes memory hookDataFromSwapper;
        if (address(key.hooks) != address(0)) {
            KYCHook kycHook = KYCHook(address(key.hooks));
            try kycHook.getKYCPolicyAddress(key) returns (address kycPolicy) {
                try KYCPolicy(kycPolicy).hookDataFromMsgSender(msg.sender) returns (bytes memory data) {
                    hookDataFromSwapper = data;
                } catch {
                    // Fallback to original hookData if hookDataFromMsgSender fails
                    hookDataFromSwapper = hookData;
                }
            } catch {
                // Fallback to original hookData if getKYCPolicyAddress fails
                hookDataFromSwapper = hookData;
            }
        } else {
            hookDataFromSwapper = hookData;
        }

        delta = abi.decode(
            manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, hookDataFromSwapper))),
            (BalanceDelta)
        );
        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
        return delta;
    }

    function unlockCallback(bytes calldata rawData) external returns (bytes memory) {
        require(msg.sender == address(manager));

        CallbackData memory data = abi.decode(rawData, (CallbackData));

        (,, int256 deltaBefore0) = _fetchBalances(data.key.currency0, data.sender, address(this));
        (,, int256 deltaBefore1) = _fetchBalances(data.key.currency1, data.sender, address(this));

        require(deltaBefore0 == 0, "deltaBefore0 is not equal to 0");
        require(deltaBefore1 == 0, "deltaBefore1 is not equal to 0");

        BalanceDelta delta = manager.swap(data.key, data.params, data.hookData);

        (,, int256 deltaAfter0) = _fetchBalances(data.key.currency0, data.sender, address(this));
        (,, int256 deltaAfter1) = _fetchBalances(data.key.currency1, data.sender, address(this));

        if (data.params.zeroForOne) {
            if (data.params.amountSpecified < 0) {
                // exact input, 0 for 1
                require(
                    deltaAfter0 >= data.params.amountSpecified,
                    "deltaAfter0 is not greater than or equal to data.params.amountSpecified"
                );
                require(delta.amount0() == deltaAfter0, "delta.amount0() is not equal to deltaAfter0");
                require(deltaAfter1 >= 0, "deltaAfter1 is not greater than or equal to 0");
            } else {
                // exact output, 0 for 1
                require(deltaAfter0 <= 0, "deltaAfter0 is not less than or equal to zero");
                require(delta.amount1() == deltaAfter1, "delta.amount1() is not equal to deltaAfter1");
                require(
                    deltaAfter1 <= data.params.amountSpecified,
                    "deltaAfter1 is not less than or equal to data.params.amountSpecified"
                );
            }
        } else {
            if (data.params.amountSpecified < 0) {
                // exact input, 1 for 0
                require(
                    deltaAfter1 >= data.params.amountSpecified,
                    "deltaAfter1 is not greater than or equal to data.params.amountSpecified"
                );
                require(delta.amount1() == deltaAfter1, "delta.amount1() is not equal to deltaAfter1");
                require(deltaAfter0 >= 0, "deltaAfter0 is not greater than or equal to 0");
            } else {
                // exact output, 1 for 0
                require(deltaAfter1 <= 0, "deltaAfter1 is not less than or equal to 0");
                require(delta.amount0() == deltaAfter0, "delta.amount0() is not equal to deltaAfter0");
                require(
                    deltaAfter0 <= data.params.amountSpecified,
                    "deltaAfter0 is not less than or equal to data.params.amountSpecified"
                );
            }
        }

        if (deltaAfter0 < 0) {
            data.key.currency0.settle(manager, data.sender, uint256(-deltaAfter0), data.testSettings.settleUsingBurn);
        }
        if (deltaAfter1 < 0) {
            data.key.currency1.settle(manager, data.sender, uint256(-deltaAfter1), data.testSettings.settleUsingBurn);
        }
        if (deltaAfter0 > 0) {
            data.key.currency0.take(manager, data.sender, uint256(deltaAfter0), data.testSettings.takeClaims);
        }
        if (deltaAfter1 > 0) {
            data.key.currency1.take(manager, data.sender, uint256(deltaAfter1), data.testSettings.takeClaims);
        }

        return abi.encode(delta);
    }
}
