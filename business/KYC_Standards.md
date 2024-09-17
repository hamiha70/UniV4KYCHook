# Token Based KYC Hook #

### Objective ###

_Develop a Hook contract that would condition execution of swaps and liquidity provision on appropriate KYF certifications verified via KYC Soulebound tokens (KYC-SBT)_

### Motivation ###

KYC – Know Your Customer is a regulation standard in the financial industry by which organizations are required to verify the identity of a customer and evaluate the suitability and risks of maintaining a business relationship with the customer. While there is not a single criterion by which an identity is verified, organization must demonstrate due diligence in the verification process.

In traditional finance, identity is typically verified through national or local government certified documents with or without a photo, as well as evidence linking the identity to an organization bank account. Once identity is verified, a customer is given access to the institution and its systems, transactions through the institution are recorded and linked to identity of the transacting entity. Organizations are expected to track customer activity and report any suspected illicit activity but otherwise protect the privacy of their customers.

One of the inhibitions for the wider the use of decentralized exchanges such as Uniswap, is the lack of a KYC framework through which organizations perform due diligence evaluation of business relationships. On the compliance level there is a need for a set of standards for diligence identity verification and evaluation of a business relationship in a P2P system. On the technological side there is a need for framework through which KYC constraints are enforced in a decentralized context.  


### Specification ###

In this project we develop the technology for enforcing KYC constraints on a UniswapV4 based marketplace through a specialized Hook contract. We make the following assumptions on the compliance frameworks under which this hook operates

1. In a P2P system it is the responsibility of the parties to set a standard of KYC compliance, and verify their counter parties meet this standard

2. It is the due diligence responsibility of the parties to verify their counterparties parties provide KYC information, and that this information is recorded and made available to law enforcement under appropriate circumstances, but it is not their responsibility to collect and record this information.

3. Government mandated regulation requires identity verification through government issued documents or documents that can be linked to government issued documents, which are verified by the government or by a government authorized entity, and thus by nature the verification process must be centralized[^1].

With these assumptions we develop a framework where parties provide verification information to a compliance entity that records the data and mints a soulbound KYC NFT token (KYC-SBT) linked to a wallet address. A hook contract then uses these tokens to confirm mutual KYC compliance between swap transaction initiators and liquidity providers they are matched against.

### Identification Standards ###

We assume a compliance entity that is able to verify all documents and extract relevant information. Fulfilling KYC requirements depends only on providing sufficient documentation for each one of the identity fields

|               |Passport       | SS Card       | Driver License | DoD ID       | Mailed Bill   | Birth Certificate |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| Photo ID      |     X         |               |       X       |      X        |               |               |
| Name          |     X         |      X        |       X       |      X        |        X      |      x        |
| DoB           |     X         |      X        |       X       |               |               |      x        |
| Address       |               |               |       X       |               |        X      |               |
| SS#           |               |      X        |               |               |               |               |
| Passport #    |     X         |               |               |               |               |               |
| Drv Lic #     |               |               |       X       |               |               |               |
| DoD Id #      |               |               |               |       X       |               |               |



Thus, for instance a compliance standard may require photo id verified by one document,  name, address, DoB by two documents and one of the id numbers, SS, passport or driver license be verified by one document. This would imply that a passport, birth certificate and two bills would meet the slandered as well as a driver license, birth certificate and a bill.  

### Soulbound Token ###

A soulbound token is a non fungable non transferable token that is used to attest to the documents provided to the compliance entity by the owner of an address.

The token stores the types of documents provided to the compliance entity and a proof of storage but does not store any identifying information.

The KYC-SBT smart contract provides authorized entities (such as pool manager contracts) token id , ownership and stored information. Stored information may be updated as required and KYC tokens may be revoked (In case certain documents are revealed to be insufficient or counterfeit).


[^1]: Under this assumption even a biometric based identifier must be linked to some government issued birth certificate that verifies a person with the underlying biometric measures exists in the eyes of the government