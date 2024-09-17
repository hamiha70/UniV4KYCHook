// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";

import {KYCPolicy} from "../base/KYCPolicy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {console} from "forge-std/console.sol";

// Errors
error NoKYCPermission(address router, address user);
error InvalidPolicyAddress(address policyContractAddress);
error OnlyRegisterPoolsWithKYCRequired();
error PoolAlreadyInitialized();
error KYCHook__PolicyNotRegistered(address policyContractAddress);
error KYCHook__InvalidInitializeHookData(bytes hookData);
error KYCHook__PolicyMisbehaving__CallToMsgSenderFromHookDataReverted();

struct InitializeSettings {
    address policyContractAddress;
    bool isKYCRequired;
}

contract KYCHookMultiplePolicies is Ownable, BaseHook {
    using PoolIdLibrary for PoolKey;

    mapping(address => bool) public isKycPolicy;
    mapping(PoolId => address) public policyAddress;
    mapping(PoolId => address) public poolCreator;
    string public name;
    address public hookOwner;

    // Constructor
    constructor(IPoolManager _manager, string memory _name, address[] memory _policyContractAddresses)
        Ownable(msg.sender)
        BaseHook(_manager)
    {
        name = _name;
        hookOwner = msg.sender;
        console.log("KYCHookMultiplePolicies: Entering constructor");
        for (uint256 i = 0; i < _policyContractAddresses.length; i++) {
            console.log("KYCHookMultiplePolicies: constructor: Policy address: %s", _policyContractAddresses[i]);
            isKycPolicy[_policyContractAddresses[i]] = true;
        }
    }

    // Hook Functions
    function getHookPermissions() public pure virtual override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
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

    function beforeInitialize(address sender, PoolKey calldata key, uint160, bytes calldata hookData)
        public
        virtual
        override
        onlyByPoolManager
        returns (bytes4)
    {
        InitializeSettings memory settings = abi.decode(hookData, (InitializeSettings));
        if (!isKycPolicy[settings.policyContractAddress]) {
            revert InvalidPolicyAddress(settings.policyContractAddress);
        }
        if (!settings.isKYCRequired) {
            revert OnlyRegisterPoolsWithKYCRequired();
        }
        PoolId poolId = key.toId();
        if (policyAddress[poolId] != address(0)) {
            // Can happen even if a pool is initialized with a different policy. PoolId is determined by currency0, currency1, fee and tick spacing and hookAddres alone.
            revert PoolAlreadyInitialized();
        }
        poolCreator[key.toId()] = sender;
        policyAddress[poolId] = settings.policyContractAddress;
        return (this.beforeInitialize.selector);
    }

    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) public view virtual override onlyByPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        address swapperAddress = KYCPolicy(policyAddress[key.toId()]).msgSenderFromHookData(hookData);
        bool permissionGranted =
            KYCPolicy(policyAddress[key.toId()]).validateSwapAuthorization(swapperAddress, key, params);
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
        address liquidityProviderAddress = KYCPolicy(policyAddress[key.toId()]).msgSenderFromHookData(hookData);
        bool permissionGranted = KYCPolicy(policyAddress[key.toId()]).validateAddLiquidityAuthorization(
            liquidityProviderAddress, key, params
        );

        if (!permissionGranted) {
            revert NoKYCPermission(sender, liquidityProviderAddress);
        }
        return (this.beforeAddLiquidity.selector);
    }

    // HOOK INTERACTION FUNCTIONS

    // Only policies that are registered can be added to pools to be initalized with this hook
    // Precaution to not allow adding malicious policies as there is no restriciton on creating pools with this hook attached
    function addKycPolicy(address _policyContractAddress) public onlyOwner {
        isKycPolicy[_policyContractAddress] = true;
    }

    // ATTENTION: This function should be used with caution. It is used to remove a KYC policy from the hook.
    // This is useful when a KYC policy is no longer needed or when a KYC policy is found to be malicious.
    // Consequence is that the pool cannot be used any more for swapping and adding liquidity
    // Locked liquidity can still be removed - the hook does always allow this
    function removeKycPolicy(address _policyContractAddress) public virtual onlyOwner {
        isKycPolicy[_policyContractAddress] = false;
    }

    function updateKycPolicy(PoolKey calldata key, address _policyContractAddress) public virtual onlyOwner {
        require(policyAddress[key.toId()] != address(0), "KYCPolicy: Pool not registered");
        policyAddress[key.toId()] = _policyContractAddress;
    }

    function isKycPolicyRegistered(address _policyContractAddress) public view virtual returns (bool) {
        return isKycPolicy[_policyContractAddress];
    }
}
