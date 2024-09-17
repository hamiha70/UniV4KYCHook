// SPDX-License-Identifier:
pragma solidity ^0.8.10;

import {ERC721} from "solmate/src/tokens/ERC721.sol";
// import {Strings} from "solmate/src/utils/Strings.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {RetailKYC} from "./RetailKYC.sol";
import {IdDocumentsBundle, RetailKYCInformation} from "./RetailKYC.sol";


// import {FieldBundle,DocBundle,FieldBundleFunction,DocBundleFunction} from "../src/Bundle.sol";
//import {KYCPolicyToken} from "./KYCPolicyToken.sol";

error KYCToken__AlreadyExistentOwner(address recipient);
error KYCToken__OnlyContractOwner(address owner);
error KYCToken__NonExistentUser();


contract KYCToken is ERC721, Ownable {
    using RetailKYC for IdDocumentsBundle;
    // using Strings for uint256;
    address private s_KYCTokenContractOwner;
    uint256 private s_currentTokenId;
    mapping(address user => uint256 tokenId) private s_ownedTokens;
    mapping(uint256 tokenId => IdDocumentsBundle) internal s_idDocumentsBundles;

    constructor() ERC721("Retail KYC Token", "KYCT") Ownable(msg.sender) {
        s_KYCTokenContractOwner=msg.sender;
    }

    function mintTo(address recipient, IdDocumentsBundle memory idDocumentsBundle) public payable onlyOwner returns (uint256) {
        if (balanceOf(recipient) > 0) {   // Each owner can have no more than one document profile
            revert KYCToken__AlreadyExistentOwner(recipient);
        }
        uint256 newTokenId = s_currentTokenId + 1;
        s_currentTokenId = newTokenId;
        _safeMint(recipient, newTokenId);
        s_ownedTokens[recipient] =newTokenId;
        s_idDocumentsBundles[newTokenId] = idDocumentsBundle;
        return(newTokenId);
    }
    function revokeToken(uint256 tokenId) public onlyOwner {
        if (ownerOf(tokenId) == address(0)) {
            revert KYCToken__NonExistentUser();
        }
        address tokenOwner = ownerOf(tokenId);
        _burn(tokenId);
        delete s_ownedTokens[tokenOwner];
        delete s_idDocumentsBundles[tokenId];
    }

    function UpdateIDDocumentsBundle(uint256 tokenId, IdDocumentsBundle memory newdocbundle) public onlyOwner returns (bool){
        if (ownerOf(tokenId) == address(0)) {
            revert KYCToken__NonExistentUser();
        }
        s_idDocumentsBundles[tokenId]=newdocbundle;
        return(true);
    }

    function getTokenId(address user) public view virtual returns (uint256 tokenId) {
        // returning zero means 
        return s_ownedTokens[user]; // Changed 'owner' to 'user'
    }

   function getIdDocumentsBundleFromTokenId(uint256 tokenId) public view virtual
        returns (IdDocumentsBundle memory docs) {
            return s_idDocumentsBundles[tokenId];
    }

    function getRetailKYCInformationFromTokenId(uint256 tokenId) public view virtual
        returns (RetailKYCInformation memory info) {
            IdDocumentsBundle memory docs = s_idDocumentsBundles[tokenId];
            return RetailKYC.getRetailKYCInformationFromIdDocuments(docs);
    }

    //  Disable all the virtual transfer functions etc. fromm inherited ERC721
    error KYCToken__ERC721FunctionNotImplemented();

    function transferFrom(address, address, uint256) public virtual override {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

    function safeTransferFrom(address /* _from */, address /* _to */, uint256 /* _tokenId */, bytes calldata /* _data */) public virtual override {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

    function safeTransferFrom(address, address, uint256) public virtual override {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

    function approve(address, uint256) public virtual override {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

    function setApprovalForAll(address, bool) public virtual override {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

    function tokenURI(uint256) public view virtual override returns (string memory) {
        revert KYCToken__ERC721FunctionNotImplemented();
    }

}