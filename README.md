New Read me
# KYC Hook based on Burnable ERC5484

## Overview

KYC Hook is a smart contract system for enabling KYC functionality for Uniswap V4 Hooks. Goal is to restrict interaction with Uniswap V4 pools to those who have successfully passed a KYC procedure. 
Addresses who are associated with a KYC whitelisted party are issued a non-transferrable token (Buranble ERC5484 token standard)

## Features
- **Provide V4 Uniswap Hook** when enabled by a Uniswap V4 Pool, unlocks KYC functionality
- **Mint and Burn authorization tokens** utilizing the `EvidenzRevealableConsensualSBT` implemntation of the Burnable ERC5484 token standard 
- **End-to-end KYC use case** on blockchain

### Requirements
To run the `KYCHookWithERC5484Burnable` contract and associated development tools, ensure the following versions are installed:

- **foundry**: Version `0.2.0` or later.

## Installations

```bash
forge install Uniswap/v4-periphery
forge install https://github.com/Prometheus-X-association/3videnz-RevealableConsensualSBT
```

### Compile the smart contracts:

```bash
forge build
```
### Run tests:

```bash
forge test
```

## Deployment

TODO

## Smart Contracts

TODO

## Acknowledgements

`EvidenzRevealableConsensualSBT` from https://github.com/Prometheus-X-association/3videnz-RevealableConsensualSBT
