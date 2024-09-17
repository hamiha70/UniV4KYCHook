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
import {KYCHook} from "../Hooks/KYCHook.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";

// Errors
error KYCRouter__PolicyMisbehaving__CallToValidateSwapAuthorizationReverted();
error KYCRouter__PolicyMisbehaving__CallToHookDataFromMsgSenderReverted();
error KYCRouter__KYCHookMisbehaving__CallToGetKYCPolicyAddressReverted();
error KYCRouter__KYCHookMisbehaving__CallToGetIsRouterWhitelistedReverted(address kycHookAddress);
error KYCRouter__RouterNotWhitelisted(address router, address kycHookAddress);
error KYCRouter__NoKYCPermission(
    address user, PoolKey key, IPoolManager.SwapParams params, KYCRouter.SwapSettings settings, bytes hookData
);
error KYCRouter__KYCHookMisbehaving__CallToIsRouterWhitelistedReverted(address kycHookAddress);

//@dev This router is designed to work in conjunction with the KYCHook.
//@dev The router exposes the swap(PoolKey, SwapParams, SwapSettings, hookData) function to any user EOA or contract that intends to swap.
//@dev If the pool is not a KYCPool (i.e. does not implement a isKYCHook), the swap will be executed without any KYC checks directly with the PoolManager.
//@dev If the
//@dev The router relies on the KYCHook to determine if a given pool is a KYC pool and to retriev the KYCPolicy address.
//@dev The KYCRouter will then refer to the KYCPolicy to check if the msg.sender is authorized to swap.
//@dev if the user is not authorized to swap, the swap will be reverted.
//@dev if the user is authorized to swap, the swap will be executed with the PoolManager.
//@dev The KYCSwapper will encode the user address in the hookData ... so it is available to the hook functions.
//@dev The KYCRouter does not store any state with respect to KYCHooks or KYCPolicies... Those are rettieved from those contracts based on Poolkey
//@dev The KYCRouter is implemented defenisvely, and reverts gracefully if the KYCPolicy or the KYCHook do not adhere to the expected interface.
//@dev The KYCRouter emits events for each swap attempt, whether it is with KYC or without KYC.
//@dev The KYCRouter must be whitelisted by the KYCHook. Otherswise the Router will revert. (As the Hook would revert anyways)
//@dev The KYCRouter is initialized with the address of the PoolManager. It does not keep state to Pools, KYCPolicies or KYCHooks.
//@dev It retrieves the KYCPolicy address from the KYCHook based on the PoolKey.
//@dev The KYCRouter is implemented as an extension of the PoolSwapRouter in v4-periphery.
contract KYCRouter is PoolTestBase, Ownable, KYCEvents {
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
        if (address(key.hooks) == address(0)) {
            // There is not hook implemented for this pool ... so not a KYC Pool
            // Router just falls back to the PoolSwapTest functionality
            emit SwapAttemptWithoutKYCThroughRouter(key.toId(), address(this), msg.sender, key, params);
            delta = abi.decode(
                manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, hookData))),
                (BalanceDelta)
            );
            uint256 ethBalance = address(this).balance;
            if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
            return delta;
        }
        KYCHook kycHook = KYCHook(address(key.hooks));
        try kycHook.getIsKYCHook() returns (bool) {
            // If the hook is a KYC hook, then we need to check if the swapRouter is whitelisted
            try kycHook.isRouterWhitelisted(address(this)) returns (bool isWhitelisted) {
                // Case where the kycHook implements getIsRouterWhitelisted
                if (!isWhitelisted) {
                    revert KYCRouter__RouterNotWhitelisted(address(this), address(kycHook));
                }
            } catch {
                // Case where the kycHook does not implement getIsRouterWhitelisted
                // In this case the router is not behaving as expected ... therefore we revert
                revert KYCRouter__KYCHookMisbehaving__CallToGetIsRouterWhitelistedReverted(address(kycHook));
            }

            // If the hook is KYC hook, then we need to check if the swapper is authorized to swap
            try kycHook.getKYCPolicyAddress(key) returns (address kycPolicy) {
                // Case where kycHook implements getKYCPolicyAddress
                // check if the swapper is authorized to swap
                try KYCPolicy(kycPolicy).validateSwapAuthorization(msg.sender, key, params) returns (bool isAuthorized)
                {
                    // case where the policy has an implementation of validateSwapAuthorization
                    if (!isAuthorized) {
                        // Case where the swapper is not authorized to swap
                        revert KYCRouter__NoKYCPermission(msg.sender, key, params, testSettings, hookData);
                    } else {
                        // Case where the swapper is authorized to swap
                        try KYCPolicy(kycPolicy).hookDataFromMsgSender(msg.sender)
                        // Case where the policy has an implementation of hookDataFromMsgSender ... and executes it gracefully
                        returns (bytes memory hookDataFromSwapper) {
                            emit SwapAttemptWithKYCThroughRouter(
                                key.toId(), address(this), msg.sender, key, params, kycPolicy, hookDataFromSwapper
                            );
                            delta = abi.decode(
                                manager.unlock(
                                    abi.encode(CallbackData(msg.sender, testSettings, key, params, hookDataFromSwapper))
                                ),
                                (BalanceDelta)
                            );
                            uint256 ethBalance = address(this).balance;
                            if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
                            return delta;
                        } catch {
                            // Case where the KYCPolicy does not implement hookDataFromMsgSender ... or fails to execute it
                            revert KYCRouter__PolicyMisbehaving__CallToHookDataFromMsgSenderReverted();
                        }
                    }
                } catch {
                    // Case where the KPolicy does not implement validateSwapAuthorization ... or fails to execute it
                    revert KYCRouter__PolicyMisbehaving__CallToValidateSwapAuthorizationReverted();
                }
            } catch {
                // Case where the kycHook does not implement getKYCPolicyAddress
                revert KYCRouter__KYCHookMisbehaving__CallToGetKYCPolicyAddressReverted();
            }
        } catch {
            // Hook does not implement getIsKYCHook and therefore is not KYC hook ...
            // Router just falls back to the PoolSwapTest functionality
            emit SwapAttemptWithoutKYCThroughRouter(key.toId(), address(this), msg.sender, key, params);
            delta = abi.decode(
                manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, hookData))),
                (BalanceDelta)
            );
            uint256 ethBalance = address(this).balance;
            if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
            return delta;
        }
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
