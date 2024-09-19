//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";

import {KYCDummyPolicy} from "../policies/KYCDummyPolicy.sol";

// Errors
error NoDummyPermission();

contract KYCDummyHook is BaseHook {
    address public policyContractAddress;

    // Constructor
    constructor(IPoolManager _manager, string memory, address _policyContractAddress) BaseHook(_manager) {
        policyContractAddress = _policyContractAddress;
    }

    // BaseHook Functions
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
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

    function beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata)
        external
        view
        override
        onlyByPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        bool permissionGranted = KYCDummyPolicy(policyContractAddress).validateSwapAuthorization(sender, key, params);
        if (!permissionGranted) {
            revert NoDummyPermission();
        }
        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata
    ) external view override onlyByPoolManager returns (bytes4) {
        bool permissionGranted =
            KYCDummyPolicy(policyContractAddress).validateAddLiquidityAuthorization(sender, key, params);

        if (!permissionGranted) {
            revert NoDummyPermission();
        }
        return (this.beforeAddLiquidity.selector);
    }
}
