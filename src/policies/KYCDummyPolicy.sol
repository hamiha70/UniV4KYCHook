// SPDX-license identifier: MIT
pragma solidity ^0.8.0;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

import {Policy} from "../base/Policy.sol";

contract KYCDummyPolicy is Policy {
    function validateSwapAuthorization(address, PoolKey calldata, IPoolManager.SwapParams calldata)
        public
        pure
        override
        returns (bool)
    {
        return false;
    }

    function validateAddLiquidityAuthorization(address, PoolKey calldata, IPoolManager.ModifyLiquidityParams calldata)
        public
        pure
        override
        returns (bool)
    {
        return true;
    }
}
