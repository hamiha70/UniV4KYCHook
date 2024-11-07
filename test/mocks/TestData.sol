// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {PoolKey} from "v4-core/types/PoolKey.sol";
import {HelperConfig, AnvilConstants, SepoliaEthereumConstants} from "../../script/HelperConfig.s.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {console} from "forge-std/console.sol";
import {PoolManager} from "v4-core/PoolManager.sol";

contract TestData {
    address public immutable TOKEN_0_ADDRESS;
    address public immutable TOKEN_1_ADDRESS;
    uint24 public constant TEST_FEE = 500;
    int24 public constant TEST_TICK_SPACING = 10;
    IHooks public KYC_HOOK;
    Currency public TOKEN_0;
    Currency public TOKEN_1;

    HelperConfig helperConfig;
    HelperConfig.NetworkConfig networkConfig;

    PoolKey public TEST_NON_KYC_POOL_KEY;
    PoolKey public TEST_KYC_POOL_KEY;

    PoolManager.ModifyLiquidityParams public TEST_MODIFY_LIQUIDITY_PARAMS;
    PoolManager.SwapParams public TEST_SWAP_PARAMS;

    constructor(HelperConfig.NetworkConfig memory _networkConfig) {
        networkConfig = _networkConfig;
        TOKEN_0 = networkConfig.erc20Contracts.pool_token0;
        TOKEN_1 = networkConfig.erc20Contracts.pool_token1;
        KYC_HOOK = networkConfig.hookContracts.kycHook;

        TEST_NON_KYC_POOL_KEY = PoolKey({
            currency0: TOKEN_0,
            currency1: TOKEN_1,
            fee: TEST_FEE,
            tickSpacing: TEST_TICK_SPACING,
            hooks: IHooks(address(0))
        });

        TEST_KYC_POOL_KEY = PoolKey({
            currency0: TOKEN_0,
            currency1: TOKEN_1,
            fee: TEST_FEE,
            tickSpacing: TEST_TICK_SPACING,
            hooks: KYC_HOOK
        });
    }

    function getTestNonKycPoolKey() public view returns (PoolKey memory) {
        return TEST_NON_KYC_POOL_KEY;
    }

    function getTestKycPoolKey() public view returns (PoolKey memory) {
        return TEST_KYC_POOL_KEY;
    }
}
