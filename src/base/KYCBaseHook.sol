// SPDX-license identifier: MIT
pragma solidity ^0.8.0;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";

import {KYCPolicy} from "../base/KYCPolicy.sol";

// Errors
error NoKYCPermission(address router, address user);

contract KYCBaseHook is BaseHook {
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

    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) public view virtual override onlyByPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        address swapperAddress = KYCPolicy(policyContractAddress).msgSenderFromHookData(hookData);
        bool permissionGranted = KYCPolicy(policyContractAddress).validateSwapAuthorization(swapperAddress, key, params);
        if (!permissionGranted) {
            revert NoKYCPermission(sender, swapperAddress);
        }
        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) public view virtual override onlyByPoolManager returns (bytes4) {
        address liquidityProviderAddress = KYCPolicy(policyContractAddress).msgSenderFromHookData(hookData);
        bool permissionGranted =
            KYCPolicy(policyContractAddress).validateAddLiquidityAuthorization(liquidityProviderAddress, key, params);

        if (!permissionGranted) {
            revert NoKYCPermission(sender, liquidityProviderAddress);
        }
        return (this.beforeAddLiquidity.selector);
    }
}
