// SPDX-license identifier: MIT
pragma solidity ^0.8.0;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";

contract WhitelistPolicy is KYCPolicy {
    address whitelistPolicyOwner;
    mapping(address => bool) public whitelist;

    constructor(address[] memory _withelistAddresses) {
        whitelistPolicyOwner = msg.sender;
        for (uint256 i = 0; i < _withelistAddresses.length; i++) {
            whitelist[_withelistAddresses[i]] = true;
        }
    }

    function addToWhitelist(address _address) public {
        require(msg.sender == whitelistPolicyOwner, "WhitelistPolicy: Only owner can add to whitelist");
        whitelist[_address] = true;
    }

    function addToWhitelist(address[] memory _addresses) public {
        require(msg.sender == whitelistPolicyOwner, "WhitelistPolicy: Only owner can add to whitelist");
        for (uint256 i = 0; i < _addresses.length; i++) {
            whitelist[_addresses[i]] = true;
        }
    }

    function removeFromWhitelist(address _address) public {
        require(msg.sender == whitelistPolicyOwner, "WhitelistPolicy: Only owner can remove from whitelist");
        whitelist[_address] = false;
    }

    function removeFromWhitelist(address[] memory _addresses) public {
        require(msg.sender == whitelistPolicyOwner, "WhitelistPolicy: Only owner can remove from whitelist");
        for (uint256 i = 0; i < _addresses.length; i++) {
            whitelist[_addresses[i]] = false;
        }
    }

    function isWhitelisted(address _address) public view returns (bool) {
        return whitelist[_address];
    }

    function validateSwapAuthorization(address swapperAddress, PoolKey calldata, IPoolManager.SwapParams calldata)
        public
        view
        virtual
        override
        returns (bool)
    {
        return isWhitelisted(swapperAddress);
    }

    function validateAddLiquidityAuthorization(
        address liquidityProviderAddress,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata
    ) public view virtual override returns (bool) {
        return isWhitelisted(liquidityProviderAddress);
    }
}
