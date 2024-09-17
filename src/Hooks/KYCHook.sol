// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {KYCEvents} from "../utils/events.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";
import {Policy} from "../base/Policy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import "forge-std/console.sol";

struct InitializeHookWithKYCParams {
    address policyContractAddress;
    bool isKYCRequired;
}

contract KYCHook is Ownable, BaseHook, KYCEvents {
    using PoolIdLibrary for PoolKey;

    // Errors
    error KYCHook__InvalidInitializeHookData(bytes hookData);
    error KYCHook__OnlyPoolCreatorCanUpdateKYCPolicy();
    error KYCHook__OnlyRegisterPoolsWithKYCRequired();
    error KYCHook__RouterNotWhitelisted(address router);
    error KYCHook__RouterAlreadyWhitelisted(address router);
    error KYCHook__PolicyMisbehaving__CallToMsgSenderFromHookDataReverted();
    error KYCHook__NoKYCPermission(address sender, address swapper);
    error KYCHook__InvalidPolicyAddress(address policyAddress);

    //State variables
    mapping(address => bool) private isWhitelistedRouters;
    mapping(PoolId => address) private policyAddress;
    mapping(PoolId => address) private poolCreator;
    // @dev: Todo: Check if isKYCRequired is really needed.
    // @dev: Might remove it and simplify InitializeHookWithKYCParams struct
    mapping(PoolId => bool) public isKYCRequired;
    string private name;
    address private hookOwner;
    bool private i_isKYCHook;

    // Constructor with whitelist initialization
    constructor(IPoolManager _manager, string memory _name) BaseHook(_manager) Ownable(msg.sender) {
        name = _name;
        hookOwner = msg.sender;
        i_isKYCHook = true;
    }

    // Whitelist Functions
    function updateRouterWhitelist(address[] memory _routers, bool _add) public onlyOwner {
        for (uint256 i = 0; i < _routers.length; i++) {
            if (_add) {
                if (isWhitelistedRouters[_routers[i]]) revert KYCHook__RouterAlreadyWhitelisted(_routers[i]);
                isWhitelistedRouters[_routers[i]] = true;
            } else {
                if (!isWhitelistedRouters[_routers[i]]) revert KYCHook__RouterNotWhitelisted(_routers[i]);
                isWhitelistedRouters[_routers[i]] = false;
            }
        }
    }

    function isRouterWhitelisted(address _router) public view returns (bool) {
        return isWhitelistedRouters[_router];
    }

    // BaseHook Functions overrides

    // Hook assumes that the router is passing in a request to swap tokens on behalf of a swapper
    // The swapper is the one who needs to be KYC verified
    // The router is the one who needs to be whitelisted. Whitelisting is done by the hookOwner
    // Critical design challeng is that the sender parameter pass on to the hook function is the router addresi
    // The hook does not have access to the original swapper address which it needs to validate
    // Workaround is to pass the swapper address in the hookData parameter. It needs to be added by the router
    // Therefore the router needs to be trusted to pass in the correct swapper address
    // The whitelisting is done to ensure that only trusted routers can call the hook

    function encodeInitializeHookData(InitializeHookWithKYCParams memory settings) public pure returns (bytes memory) {
        return abi.encode(settings);
    }

    function decodeInitializeHookData(bytes memory hookData) public view returns (InitializeHookWithKYCParams memory) {
        try this.decodeInitializeHookData_unsafe(hookData) returns (InitializeHookWithKYCParams memory settings) {
            return settings;
        } catch {
            revert KYCHook__InvalidInitializeHookData(hookData);
        }
    }

    function decodeInitializeHookData_unsafe(bytes memory hookData)
        public
        pure
        returns (InitializeHookWithKYCParams memory)
    {
        return abi.decode(hookData, (InitializeHookWithKYCParams));
    }

    // Hook Functions
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: true,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function beforeInitialize(address, PoolKey calldata, uint160, bytes calldata hookData)
        public
        virtual
        override
        onlyByPoolManager
        returns (bytes4)
    {
        InitializeHookWithKYCParams memory settings = decodeInitializeHookData(hookData);
        // Prerequisite for creating a pool with this hook is the need to specify a policy address
        if (settings.policyContractAddress == address(0)) {
            revert KYCHook__InvalidPolicyAddress(settings.policyContractAddress);
        }
        // Todo: Check if isKYCRequired is really needed. Might remove it and simplify InitializeHookWithKYCParams struct
        if (!settings.isKYCRequired) {
            revert KYCHook__OnlyRegisterPoolsWithKYCRequired();
        }
        return (this.beforeInitialize.selector);
    }

    function afterInitialize(address sender, PoolKey calldata key, uint160, int24, bytes calldata hookData)
        public
        virtual
        override
        onlyByPoolManager
        returns (bytes4)
    {
        // if this point is reached, beforeInitialize has already been called and returned successfully ... and the hookData checked
        InitializeHookWithKYCParams memory settings = decodeInitializeHookData_unsafe(hookData);
        PoolId poolId = key.toId();
        // Stroing policy address of the pool internally
        policyAddress[poolId] = settings.policyContractAddress;
        isKYCRequired[poolId] = settings.isKYCRequired;
        poolCreator[poolId] = sender;
        return (this.afterInitialize.selector);
    }

    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) public virtual override onlyByPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        // If KYC is not required, do not perform any checks
        if (!isKYCRequired[key.toId()]) {
            return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
        if (!isWhitelistedRouters[sender]) revert KYCHook__RouterNotWhitelisted(sender);
        try KYCPolicy(policyAddress[key.toId()]).msgSenderFromHookData(hookData) returns (address swapper) {
            if (!KYCPolicy(policyAddress[key.toId()]).validateSwapAuthorization(swapper, key, params)) {
                revert KYCHook__NoKYCPermission(sender, swapper);
            }
            emit SwapThroughKYCHook(key.toId(), sender, swapper, key, params, policyAddress[key.toId()], hookData);
        } catch {
            revert KYCHook__PolicyMisbehaving__CallToMsgSenderFromHookDataReverted();
        }

        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) public virtual override onlyByPoolManager returns (bytes4) {
        // If KYC is not required, do not perform any checks
        if (!isKYCRequired[key.toId()]) {
            return this.beforeAddLiquidity.selector;
        }
        if (!isWhitelistedRouters[sender]) revert KYCHook__RouterNotWhitelisted(sender);
        try KYCPolicy(policyAddress[key.toId()]).msgSenderFromHookData(hookData) returns (address liquidityProvider) {
            if (!KYCPolicy(policyAddress[key.toId()]).validateAddLiquidityAuthorization(liquidityProvider, key, params))
            {
                revert KYCHook__NoKYCPermission(sender, liquidityProvider);
            }
            emit ModifyLiquidityThroughKYCHook(
                key.toId(), sender, liquidityProvider, key, params, policyAddress[key.toId()], hookData
            );
        } catch {
            revert KYCHook__PolicyMisbehaving__CallToMsgSenderFromHookDataReverted();
        }

        return this.beforeAddLiquidity.selector;
    }

    function updateKYCPolicy(PoolKey calldata key, InitializeHookWithKYCParams memory settings) public virtual {
        // Check if pool creator is updating the policy ... also checks if pool is KYC in the hook ... reverts if not
        if (msg.sender != poolCreator[key.toId()]) revert KYCHook__OnlyPoolCreatorCanUpdateKYCPolicy();
        policyAddress[key.toId()] = settings.policyContractAddress;
        isKYCRequired[key.toId()] = settings.isKYCRequired;
    }

    function getKYCPolicyAddress(PoolKey calldata key) public view virtual returns (address) {
        return policyAddress[key.toId()];
    }

    function getPoolCreator(PoolKey calldata key) public view virtual returns (address) {
        return poolCreator[key.toId()];
    }

    // Todo: Check if this is needed
    function getIsKYCRequired(PoolKey calldata key) public view virtual returns (bool) {
        return isKYCRequired[key.toId()];
    }

    // Todo: Check if this is needed
    function getHookOwner() public view virtual returns (address) {
        return hookOwner;
    }

    function getIsKYCHook() public view virtual returns (bool) {
        return i_isKYCHook;
    }
}
