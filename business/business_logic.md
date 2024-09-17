# KYC Business Logic #

## Entities 

| Entity                | Objective     | Ownes         |
| -------------         | ------------- | ------------- |
| Swapper               |     X         |  KYC NFT token             |
| Liquidity provider    |     X         |  KYC NFT token       |
| KYC provider          |     X         |  KYCToken contract       |
| Pool                  |               |  K             |

## Key Terms
- __KYC data__ - And data that is relevant to the KYC process, documents pro


## Entities
KYC provider - Ownes the KYCToken contract, able to mint new KYC tokens and update or burn existing tokens
Pool - An owned contract, 

## KYC Business Rules ##

### KYC Provission Rules ###
1. User provdes documents providing evidence of identity from a list of accepted documents (passport, driving license, Social security etc.)
2. KYC providers verifies the validity of the documents and mints a new KYC token withe a list of verified documents.
3. User may provide additional documents at a later date or request to retract existing documents
4. KYC provider update the KYC token by adding or retracting documents, when this hapens an event providing full information must be emmited
5. Only the current document profile is maintained in the token data, however event emmisions must enable extracting a full history of the user document profile from the blockchain
6. The KYC must maintain seperatly a full history of user document profile
7.  KYC provider must maintain full control of the KYCToken contract
8. It is the responsability of the KYC provider to determin which fields of identity is supported by each docyument, and provide weights for the DocID matrix.


|               |Passport       | SS Card       | Driver License | DoD ID       | Mailed Bill   | Birth Certificate |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| Photo ID      |     1         |               |       1       |      1        |               |               |
| Name          |     1         |      1        |       1       |      1        |        1      |      1        |
| DoB           |     1         |      1        |       1       |               |               |      1        |
| Address       |               |               |       1       |               |        1      |               |
| SS#           |               |      1        |               |               |               |               |
| Passport #    |     1         |               |               |               |               |               |
| Drv Lic #     |               |               |       1       |               |               |               |
| DoD Id #      |               |               |               |       1       |               |               |


9. 

