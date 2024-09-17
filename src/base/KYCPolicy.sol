// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Policy} from "./Policy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
    
// Errors
error KYCPolicy__InvalidHookDataForMsgSender(bytes hookData);

abstract contract KYCPolicy {
    
    
    function msgSenderFromHookData(bytes calldata hookData) external view virtual returns (address) {
        try this.msgSenderFromHookData_unsafe(hookData) returns (address sender) {
            return sender;
        } catch {
            revert KYCPolicy__InvalidHookDataForMsgSender(hookData);
        }
    }

    function msgSenderFromHookData_unsafe(bytes calldata hookData) external view virtual returns (address) {
        return abi.decode(hookData, (address));
    }

    function hookDataFromMsgSender(address msgSender) external pure virtual returns (bytes memory) {
        return abi.encode(msgSender);
    }

    function validateSwapAuthorization(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params)
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
