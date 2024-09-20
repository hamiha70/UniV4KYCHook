# Project Setup and Deployment

This document outlines the technical prerequisites and deployment steps for the project.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation.html) (includes `forge`, `anvil`, and `cast`)
- [Node.js and npm](https://nodejs.org/en/download/)
- [Make](https://www.gnu.org/software/make/)
- github configuration with ssh keys recommended
- Funds for gas fees (use a faucet for testnet deployments on ETHEREUM SEPOLIA)

## Installation

1. Clone the repository
2. Install project dependencies:

```bash
make install
```

This will install Chainlink Brownie Contracts, Brevis Contracts and other necessary dependencies.

## Environment Setup

1. Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

2. Fill in the required values in the `.env` file if you want to deploy to Sepolia Testnet:

```bash
ETHEREUM_SEPOLIA_RPC_URL=
ETHERSCAN_API_KEY=
ETHERSCAN_SEPOLIA_URL=
ANVIL_RPC_URL=http://localhost:8545
SEPOLIA_ACCOUNT_ADDRESS_[1..10]=
SEPOLIA_ACCOUNT_PRIVATE_KEY_[1..10]=
```

## Compilation

Compile the contracts:

```bash
make build
```

## Testing

Run the test suite:

```bash
make test
```

For a gas report:

```bash
make snapshot
```

## Deployment

### Local Deployment (Anvil)

Start a local Anvil chain:

```bash
make anvil
```

In a new terminal, deploy the contracts:

```bash
make deploy-fund-approve ARGS="--network anvil"
```

### Testnet Deployment (Sepolia)

Deploy to Sepolia testnet:

```bash
make deploy-fund-approve ARGS="--network sepolia-live"
```

## Interacting with Deployed Contracts

Use the following commands to interact with deployed contracts:

- Approve routers for swappers: `make approve-routers-for-swapper`
- Create a muddy pool: `make create-muddy-pool`
- Create a clear pool: `make create-clear-pool`
- Add liquidity: `make add-liquidity`
- Remove liquidity: `make remove-liquidity`
- Perform a swap: `make swap`
- Collect fees: `make collect-fees`
- Whitelist a router: `make whitelist-router`
- Remove a whitelisted router: `make remove-whitelist-router`
- Add a policy: `make add-policy`
- Add ID documents to a token: `make add-IdDocs-to-token`
- Add a token: `make add-token`
- Remove a token: `make remove-token`

For each command, you can specify the network by adding `ARGS="--network <network-name>"`.

## Dependencies

- [Chainlink Brownie Contracts](https://github.com/smartcontractkit/chainlink-brownie-contracts)
- [Brevis Contracts](https://github.com/brevis-network/brevis-contracts)
- [Uniswap V4 Periphery](https://github.com/Uniswap/v4-periphery)
- [Cyfrin Foundry Devops](https://github.com/Cyfrin/foundry-devops)

## Additional Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Chainlink Documentation](https://docs.chain.link/)
