# Add directories or file patterns to ignore during indexing (e.g. foo/ or *.csv)

-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil 

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

help:
	@echo "Usage:"
	@echo "  make deploy [ARGS=...]\n    example: make deploy ARGS=\"--network sepolia\""
	@echo ""
	@echo "  make fund [ARGS=...]\n    example: make fund ARGS=\"--network sepolia\""

all: clean remove install update build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :; forge install https://github.com/Uniswap/v4-periphery --no-commit 

# Update Dependencies
update:; forge update

build:; forge build

test :; forge test 

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

# NETWORK_ARGS_SEP := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_KEY) --broadcast
NETWORK_ARGS_SEP_FORKED_CURRENT := --fork-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) 
NETWORK_ARGS_SEP_FORKED_CLEAN := --fork-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --fork-block-number 6699900
NETWORK_ARGS_SEP_BROADCAST := --rpc-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --broadcast
NETWORK_ARGS_SEP_BROADCAST_ETHERSCAN := --rpc-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --broadcast --verify --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv

# ifeq ($(findstring --network sepolia,$(ARGS)),--network sepolia)
# 	NETWORK_ARGS := --rpc-url $(SEPOLIA_RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv
# endif
DEPLOY_CONTRACT_SCRIPT := script/Deployments.s.sol:DeployContracts
# Deploy to Sepolia fork
deploy-fork-current:
	@forge script $(DEPLOY_CONTRACT_SCRIPT) $(NETWORK_ARGS_SEP_FORKED_CURRENT)

# State before first deployments of this project
deploy-fork-clean:
	@forge script $(DEPLOY_CONTRACT_SCRIPT) $(NETWORK_ARGS_SEP_FORKED_CLEAN)

deploy-live:
	@forge script $(DEPLOY_CONTRACT_SCRIPT) $(NETWORK_ARGS_SEP_BROADCAST_ETHERSCAN)

deploy-live-unverified:
	@forge script $(DEPLOY_CONTRACT_SCRIPT) $(NETWORK_ARGS_SEP_BROADCAST)

CONTRACT_ADDRESS :=0x92aa8e722d0f801f682f33387dfbc9521ed1b880 # KYCHook on sepolia
CONTRACT_NAME := KYCHook
CHAIN_ID := 11155111
verify-contract:
	@forge verify-contract --chain-id $(CHAIN_ID) --etherscan-api-key $(ETHERSCAN_API_KEY) --num-of-optimizations 1000000 $(CONTRACT_ADDRESS) $(CONTRACT_NAME)

# deploy-sepolia-hookcontracts-forked:
# 	@forge script script/DeployContracts.s.sol:DeployContracts $(NETWORK_ARGS) --fork-url $(ETHEREUM_SEPOLIA_RPC_URL)
# 	@forge script script/Interactions.s.sol:Interactions $(NETWORK_ARGS) --fork-url $(ETHEREUM_SEPOLIA_RPC_URL)
# 	@forge script script/DeployContracts.s.sol:DeployContracts $(NETWORK_ARGS) --fork-url $(ETHEREUM_SEPOLIA_RPC_URL)

# Deploy to sepolia forked
# SEPOLIA_FORKED_NETWORK ARGS = --rpc-url 
# forge script script/DeployContracts.s.sol:DeployContracts --fork-url $ETHEREUM_SEPOLIA_RPC_URL

# Deploying to Sepolia

