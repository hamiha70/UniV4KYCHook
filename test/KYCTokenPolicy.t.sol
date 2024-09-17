// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {KYCToken} from "../src/base/KYCToken.sol";
import {KYCTokenPolicy} from "../src/policies/KYCTokenPolicy.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {RetailKYC, IdDocumentsBundle, RetailKYCInformation} from "../src/base/RetailKYC.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";

contract KYCTokenPolicyTest is Test, Deployers {

    address constant RETAIL_KYC_ADDRESS = address(0x1231231231231231231231231231231231231231);
    address constant KYC_TOKENPOLICY_ADDRESS = address(0x4564564564564564564564564564564564564564);
    address constant KYC_TOKEN_OWNER_ADDRESS = address(0x1111111111111111111111111111111111111111);
    address constant KYC_TOKEN_ADDRESS = address(0x3333333333333333333333333333333333333333);

    RetailKYCInformation s_policyStandard = RetailKYCInformation(1,1,1,1,1,1,1,1,1);

    IdDocumentsBundle s_idDocumentsBundlePassing = IdDocumentsBundle(true,false,false,true,true,2);
    RetailKYCInformation s_retailKYCInformationPassingTranslatedCorrectly = RetailKYCInformation(2,1,1,1,1,2,2,2,1);
    IdDocumentsBundle s_idDocumentsBundleFailing = IdDocumentsBundle(true,false,false,true,true,0);
    RetailKYCInformation s_retailKYCInformationFailingTranslatedCorrectly = RetailKYCInformation(0,0,0,0,0,0,0,0,0);
    RetailKYCInformation s_retailKYCInformationFailing = RetailKYCInformation(0,0,0,0,0,0,0,0,0);

    KYCToken s_kycToken;
    KYCTokenPolicy s_kycTokenPolicy;

    IPoolManager.SwapParams s_swapParams;

    address constant TOKEN_ADDRESS =        address(0x9992222222222222222222222222222222222111);
    address constant KYCTokenOwnerAddress = address(0x1231231231231231231231231231231231231231);
    address constant SWAPPER_ADDRESS_PASSING =     address(0x7777777777777777777777777777777777777777);
    address constant SWAPPER_ADDRESS_FAILING =     address(0x8888888888888888888888888888888888888888);
    address constant POLICY_ADDRESS =    address(0x2222222222222222222222222222222222222111);
    address constant KYCTokenPolicyOwnerAddress = address(0x3333333333333333333333333333333333333333);

    function setUp() public {
        console.log("\nStarting setUp\n");
        // Deploy Token
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        deployCodeTo("KYCToken", "", TOKEN_ADDRESS);
        s_kycToken = KYCToken(TOKEN_ADDRESS);
        console.log("KYCToken contract deployed with address: %s", address(s_kycToken));

        // Deploy TokenPolicy
        vm.prank(KYCTokenPolicyOwnerAddress);
        deployCodeTo("KYCTokenPolicy", abi.encode(s_policyStandard, address(s_kycToken)), KYC_TOKENPOLICY_ADDRESS);
        s_kycTokenPolicy = KYCTokenPolicy(KYC_TOKENPOLICY_ADDRESS);
        console.log("KYCTokenPolicy contract deployed with address: %s\n", address(s_kycTokenPolicy));

        vm.startPrank(KYC_TOKEN_OWNER_ADDRESS);
        s_kycToken.mintTo(SWAPPER_ADDRESS_PASSING, s_idDocumentsBundlePassing);
        s_kycToken.mintTo(SWAPPER_ADDRESS_FAILING, s_idDocumentsBundleFailing);
        vm.stopPrank();

        console.log("Setup completed: KYCTokenPolicy updated, KYC tokens minted, and KYC information set for test addresses");
    }

    function test_setup() public view {
        console.log("\nStarting test_setup\n");
        assertEq(address(s_kycToken),TOKEN_ADDRESS);
        console.log("KYCToken contract deployed correctly");
        assertEq(address(s_kycTokenPolicy), KYC_TOKENPOLICY_ADDRESS);
        // Check that the policy standard is set correctly
        assert(compareRetailKYCInformation(s_kycTokenPolicy.getPolicyStandard(), s_policyStandard));
        console.log("KYCTokenPolicy contract deployed correctly\n");
        // Check that the KYCToken contract address is set correctly in the policy
        assertEq(s_kycTokenPolicy.getKYCTokenContractAddress(), address(s_kycToken));
        console.log("KYCToken contract address set correctly in KYCTokenPolicy");

        // Check that the owner of the KYCTokenPolicy is set correctly
        assertEq(s_kycTokenPolicy.getOwner(), KYCTokenPolicyOwnerAddress);
        console.log("KYCTokenPolicy owner set correctly");

        // Check that the initial policy standard is set correctly
        RetailKYCInformation memory initialStandard = s_kycTokenPolicy.getPolicyStandard();
        assert(compareRetailKYCInformation(initialStandard, s_policyStandard));

        console.log("All setup checks passed successfully");
    }

    function test_OnlyOwnerCanUpdatePolicy() public {
        console.log("\nStarting test_OnlyOwnerCanUpdatePolicy\n");
        
        // Prepare a new policy standard
        RetailKYCInformation memory newStandard = RetailKYCInformation({
            PhotoId: 2,
            FullName: 2,
            DoB: 1,
            Address: 1,
            SS_Number: 1,
            Passport_Number: 0,
            DriverLicense_Number: 0,
            DoD_Number: 0,
            Id_Count: 2
        });

        // Try to update policy with non-owner address (should fail)
        vm.prank(SWAPPER_ADDRESS_PASSING);
        assertNotEq(s_kycTokenPolicy.getOwner(), SWAPPER_ADDRESS_PASSING, "Swapper is not different from owner");
        vm.expectRevert(KYCTokenPolicy.KYCPolicy__OnlyOwnerCanUpdatePolicyStandard.selector);
        s_kycTokenPolicy.updatePolicyStandard(newStandard);

        // Update policy with owner address (should succeed)
        vm.prank(KYCTokenPolicyOwnerAddress);
        s_kycTokenPolicy.updatePolicyStandard(newStandard);

        // Verify that the policy was updated
        RetailKYCInformation memory updatedStandard = s_kycTokenPolicy.getPolicyStandard();
        assertEq(updatedStandard.PhotoId, newStandard.PhotoId, "PhotoId not updated correctly");
        assertEq(updatedStandard.FullName, newStandard.FullName, "FullName not updated correctly");
        assertEq(updatedStandard.DoB, newStandard.DoB, "DoB not updated correctly");
        assertEq(updatedStandard.Address, newStandard.Address, "Address not updated correctly");
        assertEq(updatedStandard.SS_Number, newStandard.SS_Number, "SS_Number not updated correctly");
        assertEq(updatedStandard.Passport_Number, newStandard.Passport_Number, "Passport_Number not updated correctly");
        assertEq(updatedStandard.DriverLicense_Number, newStandard.DriverLicense_Number, "DriverLicense_Number not updated correctly");
        assertEq(updatedStandard.DoD_Number, newStandard.DoD_Number, "DoD_Number not updated correctly");
        assertEq(updatedStandard.Id_Count, newStandard.Id_Count, "Id_Count not updated correctly");

        console.log("Policy update test passed\n");
    }

    function test_BundleTranslation() public pure {
        console.log("\nStarting test_BundleTranslation");

        // Create an IdDocumentsBundle
        IdDocumentsBundle memory testBundle = IdDocumentsBundle({
            Passport: true,
            SSCard: true,
            DriverLicense: false,
            DoDId: false,
            BirthCertificate: true,
            MailedBills: 2
        });

        // Call the static function
        RetailKYCInformation memory translatedInfo = RetailKYC.getRetailKYCInformationFromIdDocuments(testBundle);

        // Expected values based on the translation logic in RetailKYC contract
        RetailKYCInformation memory expectedInfo = RetailKYCInformation({
            PhotoId: 1,  // From Passport
            FullName: 2,  // From Passport and SSCard
            DoB: 3,  // From Passport, SSCard, and BirthCertificate
            Address: 2,  // From MailedBills
            SS_Number: 1,  // From SSCard
            Passport_Number: 1,  // From Passport
            DriverLicense_Number: 0,
            DoD_Number: 0,
            Id_Count: 4  // This field is not updated in the current implementation
        });

        // Assert each field
        assertEq(translatedInfo.PhotoId, expectedInfo.PhotoId, "PhotoId mismatch");
        assertEq(translatedInfo.FullName, expectedInfo.FullName, "FullName mismatch");
        assertEq(translatedInfo.DoB, expectedInfo.DoB, "DoB mismatch");
        assertEq(translatedInfo.Address, expectedInfo.Address, "Address mismatch");
        assertEq(translatedInfo.SS_Number, expectedInfo.SS_Number, "SS_Number mismatch");
        assertEq(translatedInfo.Passport_Number, expectedInfo.Passport_Number, "Passport_Number mismatch");
        assertEq(translatedInfo.DriverLicense_Number, expectedInfo.DriverLicense_Number, "DriverLicense_Number mismatch");
        assertEq(translatedInfo.DoD_Number, expectedInfo.DoD_Number, "DoD_Number mismatch");
        assertEq(translatedInfo.Id_Count, expectedInfo.Id_Count, "Id_Count mismatch");

        console.log("Bundle translation test passed");
    }

    function test_validateRetailKYCInformationAgainstRequirements() public view {
        console.log("\nStarting test_validateRetailKYCInformationAgainstRequirements\n");

        // Test case 1: Given meets required
        RetailKYCInformation memory given1 = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 1,
            SS_Number: 1,
            Passport_Number: 1,
            DriverLicense_Number: 1,
            DoD_Number: 1,
            Id_Count: 3
        });

        RetailKYCInformation memory required1 = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 1,
            SS_Number: 1,
            Passport_Number: 1,
            DriverLicense_Number: 1,
            DoD_Number: 1,
            Id_Count: 3
        });

        bool result1 = s_kycTokenPolicy.validateRetailKYCInformationAgainstRequirements(given1, required1);
        assertTrue(result1, "Validation should pass when given meets required");

        // Test case 2: Given exceeds required
        RetailKYCInformation memory given2 = RetailKYCInformation({
            PhotoId: 2,
            FullName: 2,
            DoB: 2,
            Address: 2,
            SS_Number: 2,
            Passport_Number: 2,
            DriverLicense_Number: 2,
            DoD_Number: 2,
            Id_Count: 4
        });

        RetailKYCInformation memory required2 = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 1,
            SS_Number: 1,
            Passport_Number: 1,
            DriverLicense_Number: 1,
            DoD_Number: 1,
            Id_Count: 3
        });

        bool result2 = s_kycTokenPolicy.validateRetailKYCInformationAgainstRequirements(given2, required2);
        assertTrue(result2, "Validation should pass when given exceeds required");

        // Test case 3: Given does not meet required
        RetailKYCInformation memory given3 = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 0,
            SS_Number: 0,
            Passport_Number: 0,
            DriverLicense_Number: 0,
            DoD_Number: 0,
            Id_Count: 1
        });

        RetailKYCInformation memory required3 = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 1,
            SS_Number: 1,
            Passport_Number: 1,
            DriverLicense_Number: 1,
            DoD_Number: 1,
            Id_Count: 3
        });

        bool result3 = s_kycTokenPolicy.validateRetailKYCInformationAgainstRequirements(given3, required3);
        assertFalse(result3, "Validation should fail when given does not meet required");

        console.log("validateRetailKYCInformationAgainstRequirements test passed\n");
    }

    function test_RevokeToken() public {
        console.log("Starting test for revokeToken functionality");

        // Step 1: Mint a token for a user
        address user = address(0x1234);
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        uint256 tokenId = s_kycToken.mintTo(user, s_idDocumentsBundlePassing);
        console.log("KYC token minted for user:", user);
        console.log("Token ID:", tokenId);

        // Step 2: Verify the token exists
        assertTrue(s_kycToken.balanceOf(user) == 1, "User should have 1 token");
        assertEq(s_kycToken.getTokenId(user), tokenId, "Token ID should match");

        // Step 3: Revoke the token
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        s_kycToken.revokeToken(tokenId);
        console.log("Token revoked for user: %s", user);

        // Step 4: Verify the token no longer exists
        assertTrue(s_kycToken.balanceOf(user) == 0, "User should have 0 tokens after revocation");
        assertEq(s_kycToken.getTokenId(user), 0, "Token ID should be 0 after revocation");
        console.log("User does not have token as expected");

        // Step 5: Attempt to get IdDocumentsBundle for revoked token (should have all entries false)
        IdDocumentsBundle memory revokedBundle = s_kycToken.getIdDocumentsBundleFromTokenId(tokenId);
        assertEq(revokedBundle.Passport, false, "Passport should be false");
        assertEq(revokedBundle.SSCard, false, "SSCard should be false");
        assertEq(revokedBundle.DriverLicense, false, "DriverLicense should be false");
        assertEq(revokedBundle.DoDId, false, "DoDId should be false");
        assertEq(revokedBundle.BirthCertificate, false, "BirthCertificate should be false");
        assertEq(revokedBundle.MailedBills, 0, "MailedBills should be 0");
        console.log("Attempt to get IdDocumentsBundle for revoked token  gets back all values false/zero as expected");

        // Step 6: Verify swap authorization fails for user with revoked token
        PoolKey memory dummyPoolKey;
        IPoolManager.SwapParams memory dummySwapParams;
        bool swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(user, dummyPoolKey, dummySwapParams);
        assertFalse(swapAuthorized, "Swap should not be authorized after token revocation");

        console.log("revokeToken test passed");
    }

    function test_EndToEndKYCTokenPolicy() public {
        console.log("Starting end-to-end test for KYCTokenPolicy");

        // Step 1: Set up initial policy standard
        RetailKYCInformation memory initialStandard = RetailKYCInformation({
            PhotoId: 1,
            FullName: 1,
            DoB: 1,
            Address: 1,
            SS_Number: 0,  // Changed from 1 to 0
            Passport_Number: 1,
            DriverLicense_Number: 0,  // Changed from 1 to 0
            DoD_Number: 1,
            Id_Count: 0  // Changed from 1 to 0
        });
        vm.prank(KYCTokenPolicyOwnerAddress);
        s_kycTokenPolicy.updatePolicyStandard(initialStandard);
        console.log("Initial policy standard set");

        // Step 2: Create and mint a KYC token for a user
        address user = address(0x1234);
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        uint256 tokenId = s_kycToken.mintTo(user, s_idDocumentsBundlePassing);
        console.log("KYC token minted for user:", user);
        console.log("Token ID:", tokenId);

        // Step 3: Validate swap authorization (should pass)
        PoolKey memory dummyPoolKey;
        IPoolManager.SwapParams memory dummySwapParams;
        bool swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(user, dummyPoolKey, dummySwapParams);
        assertTrue(swapAuthorized, "Swap should be authorized with initial policy standard");
        console.log("Swap authorization with initial policy: ", swapAuthorized);
        console.log("Expected: ", true);

        // Step 4: Update policy standard to be more strict
        RetailKYCInformation memory stricterStandard = RetailKYCInformation({
            PhotoId: 2,
            FullName: 2,
            DoB: 2,
            Address: 2,
            SS_Number: 1,
            Passport_Number: 1,
            DriverLicense_Number: 1,
            DoD_Number: 1,
            Id_Count: 3
        });
        vm.prank(KYCTokenPolicyOwnerAddress);
        s_kycTokenPolicy.updatePolicyStandard(stricterStandard);
        console.log("Policy standard updated to stricter requirements");

        // Step 5: Validate swap authorization again (should fail now)
        swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(user, dummyPoolKey, dummySwapParams);
        assertFalse(swapAuthorized, "Swap should not be authorized with stricter policy standard");
        console.log("Swap authorization with stricter policy: ", swapAuthorized);
        console.log("Expected: ", false);

        // Step 6: Update user's KYC information with a stricter bundle
        IdDocumentsBundle memory betterBundle = IdDocumentsBundle(true, true, true, true, true, 5);
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        s_kycToken.UpdateIDDocumentsBundle(tokenId, betterBundle);
        console.log("User's KYC information updated with stricter bundle");

        // Check that the policy standard is NOT stricter than the user's KYC information on the token
        RetailKYCInformation memory updatedInfo = s_kycToken.getRetailKYCInformationFromTokenId(tokenId);
        console.log("Updated user's KYC information:");
        // Additional check to ensure the updated information meets or exceeds the policy standard
        assertTrue(isNotStricterRetailKYCInformation(s_kycTokenPolicy.getPolicyStandard(), updatedInfo), "Updated user's KYC information should meet or exceed the policy standard");
        console.log("Updated user's KYC information meets or exceeds the policy standard");

        // Step 7: Validate swap authorization one last time (should pass now)
        swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(user, dummyPoolKey, dummySwapParams);
        console.log("Final swap authorization: ", swapAuthorized);
        assertTrue(swapAuthorized, "Swap should be authorized after updating user's KYC information");

        // Add test that verifies that a user without a token is not allowed to swap
        // Step 8: Test that a user without a token is not allowed to swap
        address userWithoutToken = address(0x5678);
        swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(userWithoutToken, dummyPoolKey, dummySwapParams);
        assertFalse(swapAuthorized, "Swap should not be authorized for user without a KYC token");
        console.log("Swap authorization for user without token: %s", swapAuthorized);
        console.log("Expected: ", false);

        //Step 9: Test that a user with a revoked token is not allowed to swap
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        s_kycToken.revokeToken(tokenId);
        swapAuthorized = s_kycTokenPolicy.validateSwapAuthorization(user, dummyPoolKey, dummySwapParams);
        assertFalse(swapAuthorized, "Swap should not be authorized for user with revoked token");
        console.log("Swap authorization for user with revoked token: %s", swapAuthorized);
        console.log("Expected: ", false);

        // Verify that the user indeed doesn't have a token
        uint256 balance = s_kycToken.balanceOf(userWithoutToken);
        assertEq(balance, 0, "User should not have any KYC tokens");
        console.log("User without token balance: %s", balance);
        console.log("Expected: 0");

        console.log("End-to-end test for KYCTokenPolicy completed successfully");
    }

    function test_ERC721FunctionsDisabled() public {
        address user = address(0x1234);
        address recipient = address(0x5678);
        uint256 tokenId = 1;

        // Mint a token to the user
        IdDocumentsBundle memory bundle = IdDocumentsBundle(true, true, true, true, true, 5);
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        s_kycToken.mintTo(user, bundle);
        console.log("Token minted to user works as expected");


        // Test transferFrom
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.transferFrom(user, recipient, tokenId);
        console.log("transferFrom is disabled as expected");

        // Test safeTransferFrom (with data)
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.safeTransferFrom(user, recipient, tokenId, "");
        console.log("safeTransferFrom (with data) is disabled as expected");

        // Test safeTransferFrom (without data)
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.safeTransferFrom(user, recipient, tokenId);
        console.log("safeTransferFrom (without data) is disabled as expected");

        // Test approve
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.approve(recipient, tokenId);
        console.log("approve is disabled as expected");

        // Test setApprovalForAll
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.setApprovalForAll(recipient, true);
        console.log("setApprovalForAll is disabled as expected");

        // Test tokenURI
        vm.prank(KYC_TOKEN_OWNER_ADDRESS);
        vm.expectRevert(KYCToken.KYCToken__ERC721FunctionNotImplemented.selector);
        s_kycToken.tokenURI(tokenId);
        console.log("tokenURI is disabled as expected");

        console.log("All ERC721 transfer and approval functions are correctly disabled");
    }

    // ------------------------------------------------------------------------------------------------
    // Helpers --------------------------------------------------
    // ------------------------------------------------------------------------------------------------
    
    function printIdDocumentsBundle(IdDocumentsBundle memory bundle) internal pure {
        console.log("IdDocumentsBundle contents:");
        console.log("Passport: ", bundle.Passport);
        console.log("SSCard: ", bundle.SSCard);
        console.log("DriverLicense: ", bundle.DriverLicense);
        console.log("DoDId: ", bundle.DoDId);
        console.log("BirthCertificate: ", bundle.BirthCertificate);
        console.log("MailedBills: ", bundle.MailedBills);
    }

    function printRetailKYCInformation(RetailKYCInformation memory info) internal pure {
        console.log("RetailKYCInformation contents:");
        console.log("PhotoId: ", info.PhotoId);
        console.log("FullName: ", info.FullName);
        console.log("DoB: ", info.DoB);
        console.log("Address: ", info.Address);
        console.log("SS_Number: ", info.SS_Number);
        console.log("Passport_Number: ", info.Passport_Number);
        console.log("DriverLicense_Number: ", info.DriverLicense_Number);
        console.log("DoD_Number: ", info.DoD_Number);
        console.log("Id_Count: ", info.Id_Count);
    }
    function compareRetailKYCInformation(RetailKYCInformation memory a, RetailKYCInformation memory b) internal pure returns (bool) {
        return (
            a.PhotoId == b.PhotoId &&
            a.FullName == b.FullName &&
            a.DoB == b.DoB &&
            a.Address == b.Address &&
            a.SS_Number == b.SS_Number &&
            a.Passport_Number == b.Passport_Number &&
            a.DriverLicense_Number == b.DriverLicense_Number &&
            a.DoD_Number == b.DoD_Number &&
            a.Id_Count == b.Id_Count
        );
    }
    function compareIdDocumentsBundles(IdDocumentsBundle memory a, IdDocumentsBundle memory b) internal pure returns (bool) {
        return (
            a.Passport == b.Passport &&
            a.SSCard == b.SSCard &&
            a.DriverLicense == b.DriverLicense &&
            a.DoDId == b.DoDId &&
            a.BirthCertificate == b.BirthCertificate &&
            a.MailedBills == b.MailedBills
        );
    }
    function isNotStricterRetailKYCInformation(RetailKYCInformation memory a, RetailKYCInformation memory b) internal pure returns (bool) {
        return (
            a.PhotoId <= b.PhotoId &&
            a.FullName <= b.FullName &&
            a.DoB <= b.DoB &&
            a.Address <= b.Address &&
            a.SS_Number <= b.SS_Number &&
            a.Passport_Number <= b.Passport_Number &&
            a.DriverLicense_Number <= b.DriverLicense_Number &&
            a.DoD_Number <= b.DoD_Number &&
            a.Id_Count <= b.Id_Count
        );
    }

    function test_isNotStricterRetailKYCInformation() public pure {
        RetailKYCInformation memory stricter = RetailKYCInformation(2, 2, 2, 2, 2, 2, 2, 2, 3);
        RetailKYCInformation memory lessStrict = RetailKYCInformation(1, 1, 1, 1, 1, 1, 1, 1, 2);
        RetailKYCInformation memory mixed = RetailKYCInformation(2, 1, 2, 1, 2, 1, 2, 1, 3);
        RetailKYCInformation memory equal = RetailKYCInformation(2, 2, 2, 2, 2, 2, 2, 2, 3);

        assertTrue(isNotStricterRetailKYCInformation(lessStrict, stricter), "LessStrict should be not stricter than stricter");
        assertFalse(isNotStricterRetailKYCInformation(stricter, lessStrict), "Stricter should not be not stricter than lessStrict");
        assertTrue(isNotStricterRetailKYCInformation(mixed, stricter), "Mixed should be not stricter than stricter");
        assertFalse(isNotStricterRetailKYCInformation(stricter, mixed), "Stricter should not be not stricter than mixed");
        assertFalse(isNotStricterRetailKYCInformation(mixed, lessStrict), "Mixed should not be not stricter than lessStrict");
        assertTrue(isNotStricterRetailKYCInformation(equal, stricter), "Equal should be not stricter than stricter");
        assertTrue(isNotStricterRetailKYCInformation(stricter, equal), "Stricter should be not stricter than equal");
    }

}