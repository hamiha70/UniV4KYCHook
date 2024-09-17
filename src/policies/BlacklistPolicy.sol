// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Policy} from "../base/Policy.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";

contract BlacklistPolicy is KYCPolicy {
    address blacklistPolicyOwner;
    mapping(address => bool) public blacklist;

    constructor(address[] memory _blacklistAddresses) {
        blacklistPolicyOwner = msg.sender;
        for (uint256 i = 0; i < _blacklistAddresses.length; i++) {
            blacklist[_blacklistAddresses[i]] = true;
        }
    }

    function addToBlacklist(address _address) public {
        require(msg.sender == blacklistPolicyOwner, "BlacklistPolicy: Only owner can add to blacklist");
        blacklist[_address] = true;
    }

    function addToBlacklist(address[] memory _addresses) public {
        require(msg.sender == blacklistPolicyOwner, "BlacklistPolicy: Only owner can add to blacklist");
        for (uint256 i = 0; i < _addresses.length; i++) {
            blacklist[_addresses[i]] = true;
        }
    }

    function removeFromBlacklist(address _address) public {
        require(msg.sender == blacklistPolicyOwner, "BlacklistPolicy: Only owner can remove from blacklist");
        blacklist[_address] = false;
    }

    function removeFromBlacklist(address[] memory _addresses) public {
        require(msg.sender == blacklistPolicyOwner, "BlacklistPolicy: Only owner can remove from blacklist");
        for (uint256 i = 0; i < _addresses.length; i++) {
            blacklist[_addresses[i]] = false;
        }
    }

    function isBlacklisted(address _address) public view returns (bool) {
        return blacklist[_address];
    }

    function validateSwapAuthorization(address sender, PoolKey calldata, IPoolManager.SwapParams calldata)
        public
        view
        virtual
        override
        returns (bool)
    {
        return !isBlacklisted(sender);
    }

    function validateAddLiquidityAuthorization(
        address sender,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata
    ) public view virtual override returns (bool) {
        return !isBlacklisted(sender);
    }
}
