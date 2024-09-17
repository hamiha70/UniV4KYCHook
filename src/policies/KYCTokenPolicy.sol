pragma solidity ^0.8.0;

import {Policy} from "../base/Policy.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {RetailKYC, RetailKYCInformation, IdDocumentsBundle} from "../base/RetailKYC.sol";
import {KYCPolicy} from "../base/KYCPolicy.sol";
import {KYCToken} from "../base/KYCToken.sol";

import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {console} from "forge-std/console.sol";

// import {FieldBundle, DocBundle, FieldBundleFunction, DocBundleFunction} from "./Bundle.sol";
import {RetailKYC, RetailKYCInformation, IdDocumentsBundle} from "../base/RetailKYC.sol";

import {KYCPolicy} from "../base/KYCPolicy.sol";
import {KYCToken} from "../base/KYCToken.sol";


contract KYCTokenPolicy is KYCPolicy {
    address private s_owner;
    RetailKYCInformation private s_policyStandard;
    KYCToken private s_kycToken;

    error KYCPolicy__OnlyOwnerCanUpdateKYCTokenContractAddress();
    error KYCPolicy__OnlyOwnerCanUpdatePolicyStandard();


    constructor(RetailKYCInformation memory _policyStandard, address _kycTokenAddress) {
            s_policyStandard = _policyStandard;
            s_kycToken = KYCToken(_kycTokenAddress);
            s_owner = msg.sender;
    }

    function getPolicyStandard() public view virtual returns (RetailKYCInformation memory) {
        return (s_policyStandard);
    }
    function getOwner() public view returns (address) {
        return s_owner;
    }

    function updatePolicyStandard(RetailKYCInformation memory newStandard) public  {
        if (msg.sender != s_owner) {
            revert KYCPolicy__OnlyOwnerCanUpdatePolicyStandard();
        }
        s_policyStandard = newStandard;
    }

    function getKYCTokenContractAddress() public view virtual returns (address) {
        return address(s_kycToken);
    }

    function UpdateKYCTokenContractAddress(address newKYCTokenAddress) public returns (bool success) {
        if (msg.sender != s_owner) {
            revert KYCPolicy__OnlyOwnerCanUpdateKYCTokenContractAddress();
        }
        s_kycToken = KYCToken(newKYCTokenAddress);
        return true;
    }


    function validateRetailKYCInformationAgainstRequirements(RetailKYCInformation memory given, RetailKYCInformation memory required) public pure returns (bool ) {
        bool photoId_fulfilled = required.PhotoId <= given.PhotoId;
        bool fullName_fulfilled = required.FullName <= given.FullName;
        bool dob_fulfilled = required.DoB <= given.DoB;
        bool address_fulfilled = required.Address <= given.Address;
        bool ssn_fulfilled = required.SS_Number <= given.SS_Number;
        bool passport_fulfilled = required.Passport_Number <= given.Passport_Number;
        bool driverLicense_fulfilled = required.DriverLicense_Number <= given.DriverLicense_Number;
        bool dOD_fulfilled = required.DoD_Number <= given.DoD_Number;
        bool id_count_fulfilled = required.Id_Count <= given.Id_Count;

        bool fulfilled = photoId_fulfilled && fullName_fulfilled && dob_fulfilled && address_fulfilled && ssn_fulfilled && passport_fulfilled && driverLicense_fulfilled && dOD_fulfilled && id_count_fulfilled;
        return fulfilled;
    }

    function validateSwapAuthorization(
        address swapperAddress,
        PoolKey calldata /* _key */,
        IPoolManager.SwapParams calldata /* _params */
    ) public view virtual override returns (bool) {
        uint256 swapperTokenId = s_kycToken.getTokenId(swapperAddress);
        RetailKYCInformation memory given = s_kycToken.getRetailKYCInformationFromTokenId(swapperTokenId);
        return validateRetailKYCInformationAgainstRequirements(given, s_policyStandard);
    }

    function validateAddLiquidityAuthorization(
        address lpAddress,
        PoolKey calldata /* _key */,
        IPoolManager.ModifyLiquidityParams calldata /* _params */
    ) public view virtual override returns (bool) {
        uint256 lpTokenId = s_kycToken.getTokenId(lpAddress);
        RetailKYCInformation memory given = s_kycToken.getRetailKYCInformationFromTokenId(lpTokenId);
        return validateRetailKYCInformationAgainstRequirements(given, s_policyStandard);
    }
}
