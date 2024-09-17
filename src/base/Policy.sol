// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

abstract contract Policy {
    function validateSwapAuthorization(
        address sender, 
        PoolKey calldata key, 
        IPoolManager.SwapParams calldata params
        )
        public
        view
        virtual
        returns (bool);

    function validateAddLiquidityAuthorization(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata params
    ) public view virtual returns (bool);
}
