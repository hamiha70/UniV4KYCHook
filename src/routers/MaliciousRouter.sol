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

//@dev This router is designed to work in conjunction with the KYCHook, but allows for malicious behavior.
//@dev A malicious swapper can pass in a fake swapper address in the hookData parameter.
//dev  For pools without hooks attached or without the signature of a KYCHook, the router assumes the swapper knows what he does (can be a pool with differnt hook behavior) and just passes on the swap
//@dev For pools with KYCPolicy and if the swapper is not authorized to swap, the router will attempt to execute the swap with the fake swapper address encoded in the hookData.
//@dev If the swapper is authorized to swap, the router will attempt to execute the swap with the original swapper address encoded in the hookData. So he does not get caught in cheating after the fact.
//@dev The router exposes the swap(PoolKey, SwapParams, SwapSettings, hookData) function to any user EOA or contract that intends to swap.
//@dev The MaliciousRouter attempts to execute the swap without prior KYC checks.
//@dev If the pool has a KYCHook, the router will try to retrieve the KYCPolicy address and get hookData from the policy.
//@dev If retrieving the KYCPolicy or getting hookData fails, the router falls back to the original hookData.
//@dev The MaliciousRouter does not store any state with respect to KYCHooks or KYCPolicies. Those are retrieved from the relevant contracts based on the PoolKey.
//@dev The MaliciousRouter is implemented defensively, gracefully handling cases where the KYCPolicy or KYCHook do not adhere to the expected interface.
//@dev The MaliciousRouter emits an event for each swap attempt.
//@dev The MaliciousRouter is initialized with the address of the PoolManager and does not keep state related to Pools, KYCPolicies, or KYCHooks.
//@dev It attempts to retrieve the KYCPolicy address from the KYCHook based on the PoolKey, but proceeds with the swap even if this fails.
//@dev The MaliciousRouter is implemented as an extension of the PoolSwapRouter in v4-periphery, with modifications for malicious KYC checking.
contract MaliciousRouter is PoolTestBase, Ownable, KYCEvents {
    using CurrencySettler for Currency;
    using Hooks for IHooks;
    using PoolIdLibrary for PoolKey;

    error MaliciousRouter__FakeHookDataIsMalformed(bytes fakeHookData);
    error MaliciousRouter__RouterNotWhitelisted(address maliciousRouter, address kycHook);
    error MaliciousRouter__NoKYCPermissionForFakeSwapper(address swapper, PoolKey poolKey, IPoolManager.SwapParams params, SwapSettings testSettings, bytes hookData, address fakeSwapperAddress, address kycPolicyAddress);
error MaliciousRouter__PolicyMisbehaving__CallToValidateSwapAuthorizationReverted();

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
        bytes memory fakeHookData
    ) external payable returns (BalanceDelta delta) {
        // Attempt to imperonate a fake swapper address <- Received through fakeHookData
        
        if (address(key.hooks) != address(0)) {
            KYCHook kycHook = KYCHook(address(key.hooks));
            // Case where the pool has a KYCHook -> MaliciousRouter attempts to retrieve the KYCPolicy address
            try kycHook.isRouterWhitelisted(address(this)) returns (bool isWhitelisted) {
                // Case where the kycHook implements getIsRouterWhitelisted
                if (!isWhitelisted) {
                    // MaliciousRouter does not passon swap if he is not whitelisted -> Swap would not pass anyways
                    revert MaliciousRouter__RouterNotWhitelisted(address(this), address(kycHook));
                }
            } catch {
                // Case where the kycHook does not implement getIsRouterWhitelisted ... MaliciousRouter just passes on the swap
                // The Hook behaviour is unknown and the swap intent might be valid with that hook
                emit SwapAttemptThroughUnknownRouterType(key.toId(), address(this), msg.sender, key, params, fakeHookData);
                delta = abi.decode(
                    manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, fakeHookData))),
                        (BalanceDelta)
                );
                uint256 ethBalance = address(this).balance;
                if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
                return delta;
            }
            // Now we know that the Malicious Hook is whitelisted by the KYCHook
            // We proceed to check the fakeHookData to see if the swap attempt is well formed
            try kycHook.getKYCPolicyAddress(key) returns (address kycPolicy) {
                try KYCPolicy(kycPolicy).msgSenderFromHookData(fakeHookData) returns (address fakeSwapperAddress) {
                    // We have a valid fakeSwapperAddress and a valid kycPolicy
                    // We proceed to check if the swap witht the fakeAddress would pass
                    try KYCPolicy(kycPolicy).validateSwapAuthorization(fakeSwapperAddress, key, params) returns (bool isAuthorized) {
                        // Case where the policy has an implementation of validateSwapAuthorization
                        if (!isAuthorized) {
                            // Case where the swapper is not authorized to swap
                            revert MaliciousRouter__NoKYCPermissionForFakeSwapper(msg.sender, key, params, testSettings, fakeHookData, fakeSwapperAddress, kycPolicy);
                        } else {
                            if (KYCPolicy(kycPolicy).validateSwapAuthorization(msg.sender, key, params)) {
                                // Case where the orignal swapper would have been authorized to swap anyways
                                // Replace hook data with the original swapper address
                                fakeHookData = KYCPolicy(kycPolicy).hookDataFromMsgSender(msg.sender);
                                emit SwapAttemptThroughMaliciousRouter(key.toId(), address(this), msg.sender, key, params, fakeHookData);
                            } else {
                                // Case where original swapper is not but the the faked swapper is authorized to swap
                                emit MaliciousSwapAttemptThroughKYCRouter(key.toId(), address(this), msg.sender, key, params, fakeSwapperAddress, kycPolicy, fakeHookData);
                            }
                            delta = abi.decode(
                                manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, fakeHookData))),
                                (BalanceDelta)
                            );
                            uint256 ethBalance = address(this).balance;
                            if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
                            return delta;
                        }
                    } catch {
                        // Case where the KYCPolicy does not implement validateSwapAuthorization ... or fails to execute it
                        revert MaliciousRouter__PolicyMisbehaving__CallToValidateSwapAuthorizationReverted();
                    }
                } catch {
                    // Case where the fakeHookData passed in from swpper cannot be properly by the KYCPolicy
                    // We assume that the 
                    revert MaliciousRouter__FakeHookDataIsMalformed(fakeHookData);
                }
            } catch {
                // Case where the KYCPolicy does not implement hookDataFromMsgSender ... or fails to execute it
                // We assume that the Hook implements a RouterWhitelisted function but a differnt methodology we do not know of
                // We emit an event and proceed to call the swap with the original hookData
                emit SwapAttemptThroughMaliciousRouterWithUnknownBehavior(key.toId(), address(this), msg.sender, key, params, fakeHookData);
                delta = abi.decode(
                    manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, fakeHookData))),
                    (BalanceDelta)
                );
                uint256 ethBalance = address(this).balance;
                if (ethBalance > 0) CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
                return delta;
            }
        } else {
            // Case where the pool does not have a KYCHook -> MaliciousRouter just passes on the swap
            emit SwapAttemptThroughMaliciousRouter(key.toId(), address(this), msg.sender, key, params, fakeHookData);
            delta = abi.decode(
                manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, fakeHookData))),
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
