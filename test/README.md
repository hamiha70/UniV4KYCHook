# Testing #

### Deployments ###

#### $\textcolor{red}{Easy~~Deployment}$ ####


|   $\textcolor{blue}{Contract}$    |  $\textcolor{blue}{version}$         |  $\textcolor{blue}{reference}$    |
| ------------  | -------------     |------------   |
| Pool Manager  |  v4-core          |_poolManager_    |
| ERC-721       | KYC token         |_kycToken_       |
| Policy        | PolicyToken       |_kycPolicyToken_ |
| Hook          | Easy              |_kycEasyHook_    |
| Router (whitelisted)| Easy  |_kycEasyRouter_  |
| Router (whitelisted)| v4-periphery|_kycEasyRouter_  |
| ERC-20        | Currency          |_token0/1_       |


#### $\textcolor{red}{AvantGuard~~Deployment}$ ####

|   $\textcolor{blue}{Contract}$    |  $\textcolor{blue}{version}$         |  $\textcolor{blue}{reference}$    |
| ------------  | -------------     |------------   |
| Pool Manager  |  v4-core          |_poolManager_    |
| ERC-721       | KYC token         |_kycToken_       |
| Policy        | PolicyToken       |_kycPolicyToken_ |
| Hook          | Easy              |_kycEasyHook_    |
| Router (whitelisted)| AvantGuard   |_kycAvantGuardRouter_  |
| Router (whitelisted)| v4-periphery|_kycEasyRouter_  |
| ERC-20        | Currency          |_token0/1_       |


## Test Scenarios ##

### $\textcolor{red}{[T1] - Easy~~KYC}$ ###
- Deployment
    - Easy deployment
    - two pools, one initialized with a hook attached to a KYC policy and one with a policy free hook
    - two swappers, one KYC complient one not
- Transactions
    - swappers, each in turn submit a swap via easy routers to each pool
- Expected Result

| Swaper #      | Swapper KYC   | Pool Hook Policy   | Router   | $\Delta$   |   event     |
| ------------- | ------------- |-----------    |----------|------------|------------ |
| 1             |     no        |   none        | Easy     |     yes    |   swap      |
| 2             |     yes       |   none        | Easy     |     yes    |   swap      |
| 1             |     no        |   KYC Policy  | Easy     |     no     |   HOOK_REV  |
| 2             |     yes       |   KYC Policy  | Easy     |     yes    |   swap      |

### $\textcolor{red}{[T2] - AvantGuard~~KYC}$ ###
- Deployment
    - Avantguard deployment
    - two pools, one initialized with a hook attached to a KYC policy and one with a policy free hook
    - two swappers, one KYC complient one not
- Transactions
    - swappers, each in turn submit a swap via v4-periphery and easy routers to each pool
- Expected Result

| Swaper #      | Swapper KYC   | Pool Hook Policy   |     Router        | $\Delta$           |   event     |
| ------------- | ------------- |-----------    |-------------------|----------------   |------------ |
| 1             |     no        |   KYC Policy  |v4-periphery       |       yes         |   swap  |
| 2             |     yes       |   KYC Policy  |v4-periphery       |       yes         |   swap      |
| 1             |     no        |   none        |Easy               |       yes          |   RTR_REV   |
| 2             |     yes       |   none        |Easy               |       yes         |   swap      |
| 1             |     no        |   KYC Policy  |Easy               |       no          |   RTR_REV   |
| 2             |     yes       |   KYC Policy  |Easy               |       yes         |   swap      |

### $\textcolor{red}{[T3] - Easy~~Blacklisting}$ ###
- Deployment
    - Standard deployment
    - blacklist of addresses
    - four swappers, two blacklisted three not blacklisted
- Transactions
    - swappers,each in turn submit a swap via v4-periphery Easy and Avantguard routers
- Expected Result

| Swaper #      | Swapper KYC | Blacklist |      Router       | $\Delta$          |   event     |
| ------------- | ------------- | ----------|-------------------|----------------   |------------ |
| 1             |     yes       |  no       |v4-periphery       |       yes         |   swap      |
| 2             |     yes       |  yes      |v4-periphery       |       yes         |   swap      |
| 3             |     no        |  yes      |v4-periphery       |       yes         |   swap      |
| 4             |     no        |  no       |v4-periphery       |       yes         |   swap      |
| 1             |     yes       |  no       |Easy               |       yes         |   swap      |
| 2             |     yes       |  yes      |Easy               |       no          |   HOOK_REV  |
| 3             |     no        |  yes      |Easy               |       no          |   RTR_REV   |
| 4             |     no        |  no       |Easy               |       no          |   RTR_REV   |


### $\textcolor{red}{[T4] - Dynamic~~Whitelisting}$ ###
    - Deployment
        - Easy deployment
        - Easy Router initially not whitelisted
        - two swappers, one KYC compient with pool, one not
    - Transactions
        - Phase 1
            - Easy router removed from whitelist       
            - swappers,each in turn submit a swap via easy router 
        - Phase 2
            - Easy router added to whitelist       
            - swappers,each in turn submit a swap via easy router 
        - Phase 3
            - Easy router removed from whitelist       
            - swappers,each in turn submit a swap via easy router 
    - Expected result

| Swaper #      | Swapper KYC |       Phase       | $\Delta$          |   event   |
| ------------- | ------------- |-------------------|----------------   |-----------|
| 1             |     yes       |       1           |       no          | HOOK_REV  |
| 2             |     no        |       1           |       no          | RTR_REV   |
| 1             |     yes       |       2           |       yes         |   swap    |
| 2             |     no        |       2           |       no          | RTR_REV   |
| 1             |     yes       |       3           |       no          | HOOK_REV  |
| 2             |     no        |       3           |       no          | RTR_REV   |
