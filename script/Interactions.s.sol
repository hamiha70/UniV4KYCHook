// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";


contract InitPool is Script {

    function initPool(PoolManager poolManager, PoolKey memory poolKey, address initialDeployer, uint160 sqrtPriceX96, bytes memory hookData) public {
        vm.startBroadcast(initialDeployer);
        poolManager.initialize(poolKey, sqrtPriceX96, hookData);
        vm.stopBroadcast();
    }

    function run() external {
        address mostRecentlyDeployed = DevOpsTools.get_most_recent_deployment("PoolManager", block.chainid);
        PoolManager poolManager = PoolManager(payable(mostRecentlyDeployed));       
    }
}
