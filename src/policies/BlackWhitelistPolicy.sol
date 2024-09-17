// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Policy} from "../base/Policy.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {WhitelistPolicy} from "./WhitelistPolicy.sol";
import {BlacklistPolicy} from "./BlacklistPolicy.sol";

contract BlackWhitelistPolicy is WhitelistPolicy, BlacklistPolicy {
    // Contract has a whitelist and a blacklist
    // Whitelist overrides blacklist
    // If an address is in the whitelist, it is allowed to perform the action
    // If an address is in the blacklist, it is not allowed to perform the action unless it is in the whitelist
    // If an address is not in the whitelist or blacklist, it is allowed to perform the action

    constructor(address[] memory _whitelistAddresses, address[] memory _blacklistAddresses)
        WhitelistPolicy(_whitelistAddresses)
        BlacklistPolicy(_blacklistAddresses)
    {
        whitelistPolicyOwner = msg.sender;
        blacklistPolicyOwner = msg.sender;
        for (uint256 i = 0; i < _whitelistAddresses.length; i++) {
            whitelist[_whitelistAddresses[i]] = true;
        }
        for (uint256 i = 0; i < _blacklistAddresses.length; i++) {
            blacklist[_blacklistAddresses[i]] = true;
        }
    }

    function validateSwapAuthorization(address sender, PoolKey calldata, IPoolManager.SwapParams calldata)
        public
        view
        override(WhitelistPolicy, BlacklistPolicy)
        returns (bool)
    {
        if (isWhitelisted(sender)) {
            return true;
        }
        return !isBlacklisted(sender);
    }

    function validateAddLiquidityAuthorization(
        address sender,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata
    ) public view override(WhitelistPolicy, BlacklistPolicy) returns (bool) {
        if (isWhitelisted(sender)) {
            return true;
        }
        return !isBlacklisted(sender);
    }
}
