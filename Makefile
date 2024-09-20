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

install :; forge install https://github.com/Uniswap/v4-periphery --no-commit && forge install cyfrin/foundry-devops --no-commit && forge install chainlink/chainlink-brownie-contracts --no-commit

# Update Dependencies
update:; forge update

build:; forge build

test :; forge test 

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

# DEFAUL network arguments for local anvil node


BLOCK_NUMBER_CLEAN := $(SEPOLIA_CLEAN_BLOCK) # 6699900
NETWORK_ARGS_SEP_FORKED_CLEAN := --fork-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --fork-block-number $(BLOCK_NUMBER_CLEAN)
NETWORK_ARGS_SEP_FORKED_CURRENT := --fork-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) 
NETWORK_ARGS_SEP_BROADCAST := --rpc-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --broadcast
NETWORK_ARGS_SEP_BROADCAST_ETHERSCAN := --rpc-url $(ETHEREUM_SEPOLIA_RPC_URL) --private-key $(SEPOLIA_ACCOUNT_PRIVATE_KEY_2) --broadcast --verify --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv

# for use with anvil ... non NETWORK_ARGS
# --network sepolia-fork-clean ... for use with sepolia forked clean state, i.e. block number before first deployment of this project
# --network sepolia-fork-current ... for use with sepolia forked current state, i.e. block number after first deployment of this project
# --network sepolia-live ... for use with sepolia live network
NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_KEY) --broadcast
ifeq ($(findstring --network sepolia-fork-clean,$(ARGS)),--network sepolia-fork-clean)
	NETWORK_ARGS := $(NETWORK_ARGS_SEP_FORKED_CLEAN)
else ifeq ($(findstring --network sepolia-fork-current,$(ARGS)),--network sepolia-fork-current)
	NETWORK_ARGS := $(NETWORK_ARGS_SEP_FORKED_CURRENT)
else ifeq ($(findstring --network-sepolia-live,$(ARGS)),--network sepolia)
	NETWORK_ARGS := --rpc-url $(SEPOLIA_RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify --etherscan-api-key $(ETHERSCAN_API_KEY) -vvvv
endif
deploy-fund-approve:
	@forge script script/DeployContracts.s.sol:DeployContracts $(NETWORK_ARGS)

# Interactions with the deployed contracts
approve-routers-for-swapper:;
	@forge script script/Interactions.s.sol:ApproveRoutersForSwappers --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
create-muddy-pool:;
	@forge script script/Interactions.s.sol:CreateMuddyPool --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
create-clear-pool:;
	@forge script script/Interactions.s.sol:CreateClearPool --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
add-liquidity:;
	@forge script script/Interactions.s.sol:AddLiquidity --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
remove-liquidity:;
	@forge script script/Interactions.s.sol:RemoveLiquidity --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
swap:;
	@forge script script/Interactions.s.sol:Swap --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
collect-fees:;
	@forge script script/Interactions.s.sol:CollectFees --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)

whitelist-router:;
	@forge script script/Interactions.s.sol:WhitelistRouter --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
remove-whitelist-router:;
	@forge script script/Interactions.s.sol:RemoveWhitelistRouter --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
add-policy:;
	@forge script script/Interactions.s.sol:AddPolicy --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
add-IdDocs-to-token:;
	@forge script script/Interactions.s.sol:AddIdDocsToToken --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
add-token:;
	@forge script script/Interactions.s.sol:AddToken --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)
remove-token:;
	@forge script script/Interactions.s.sol:RemoveToken --sender $(SENDER_ADDRESS) $(NETWORK_ARGS)



