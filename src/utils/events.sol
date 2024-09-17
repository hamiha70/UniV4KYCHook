// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PoolKey} from "v4-core/types/PoolKey.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolId} from "v4-core/types/PoolId.sol";

abstract contract KYCEvents {

event SwapAttemptWithKYCThroughRouter(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    address kycPolicyAddress,
    bytes hookData
);

event SwapAttemptWithoutKYCThroughRouter(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params
);

event ModifyLiquidityAttemptWithKYCThroughRouter(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params,
    address kycPolicyAddress,
    bytes hookData
);

event ModifyLiquidityAttemptWithoutKYCThroughRouter(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params
);

event SwapThroughKYCHook(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    address kycPolicyAddress,
    bytes hookData
);

event ModifyLiquidityThroughKYCHook(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params,
    address kycPolicyAddress,
    bytes hookData
);

event LazySwapAttemptThroughRouter(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params
);

event LazyModifyLiquidityAttemptThroughRouter(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params
);

event MaliciousSwapAttemptThroughKYCHook(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    address fakeSwapperAddress,
    address kycPolicyAddress,
    bytes hookData
);

event MaliciousModifyLiquidityAttemptThroughKYCHook(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params,
    address fakeSwapperAddress,
    address kycPolicyAddress,
    bytes hookData
);

event SwapAttemptThroughUnknownRouterType(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    bytes hookData
);

event ModifyLiquidityAttemptThroughUnknownRouterType(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params,
    bytes hookData
);

event SwapAttemptThroughMaliciousRouter(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    bytes hookData
);

event ModifyLiquidityAttemptThroughMaliciousRouter(
    PoolId indexed poolId,
    address indexed modifyLiquidityRouterAddress,
    address indexed liquidityProvider,
    PoolKey poolKey,
    IPoolManager.ModifyLiquidityParams params,
    bytes hookData
);

event SwapAttemptThroughMaliciousRouterWithUnknownBehavior(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    bytes hookData
);

event MaliciousSwapAttemptThroughKYCRouter(
    PoolId indexed poolId,
    address indexed swapRouterAddress,
    address indexed swapper,
    PoolKey poolKey,
    IPoolManager.SwapParams params,
    address fakeSwapperAddress,
    address kycPolicyAddress,
    bytes hookData
);

}
