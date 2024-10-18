// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {DeployContracts} from "../../script/Deployments.s.sol";
import {HelperConfig, AnvilConstants, SepoliaEthereumConstants, EnvLookups} from "../../script/HelperConfig.s.sol";
import {Currency} from "v4-core/types/Currency.sol";

contract DeploymentTest is Test, AnvilConstants, SepoliaEthereumConstants, EnvLookups {
    HelperConfig helperConfig;
    HelperConfig.NetworkConfig networkConfigBeforeDeployment;
    HelperConfig.NetworkConfig networkConfigAfterDeployment;

    function setUp() public {
        console.log("Deploying contracts on chain %s", block.chainid);
        helperConfig = new HelperConfig();
        networkConfigBeforeDeployment = helperConfig.getLocalNetworkConfig();
        console.log("Network config before deployment:");
        helperConfig.printNetworkConfig(networkConfigBeforeDeployment);
        DeployContracts deployments = new DeployContracts();
        networkConfigAfterDeployment = deployments.run();
        console.log("Network config after deployment:");
        helperConfig.printNetworkConfig(networkConfigAfterDeployment);
        console.log("Balances of the relevant accounts after deployment:");
        helperConfig.printETHBalances(networkConfigAfterDeployment);
        console.log("Setup complete on chain %s", block.chainid);
    }

    function test_Deployment_fundsAccounts() public {
        if (block.chainid == ANVIL_CHAIN_ID) {
            uint256 swapperBalance = address(networkConfigAfterDeployment.users.swapper).balance;
            assertEq(swapperBalance, 10000 ether);
            uint256 liquidityProviderBalance = address(networkConfigAfterDeployment.users.liquidityProvider).balance;
            assertEq(liquidityProviderBalance, 10000 ether);
            uint256 rogueUserBalance = address(networkConfigAfterDeployment.users.rogueUser).balance;
            assertEq(rogueUserBalance, 10000 ether);
            uint256 poolKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolKYCOwner).balance;
            assertEq(poolKYCOwnerBalance, 10000 ether);
            uint256 poolNonKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner).balance;
            assertEq(poolNonKYCOwnerBalance, 10000 ether);
            uint256 tokenPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner).balance;
            assertEq(tokenPolicyOwnerBalance, 10000 ether);
            uint256 usdcBlacklistPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner).balance;
            assertEq(usdcBlacklistPolicyOwnerBalance, 10000 ether);
            uint256 kycHookOwnerBalance = address(networkConfigAfterDeployment.activeOwners.kycHookOwner).balance;
            assertEq(kycHookOwnerBalance, 10000 ether);
        }
        if (block.chainid == ETHEREUM_SEPOLIA_CHAIN_ID) {
            uint256 swapperBalance = address(networkConfigAfterDeployment.users.swapper).balance;
            assertGt(swapperBalance, 0);
            uint256 liquidityProviderBalance = address(networkConfigAfterDeployment.users.liquidityProvider).balance;
            assertGt(liquidityProviderBalance, 0);
            uint256 rogueUserBalance = address(networkConfigAfterDeployment.users.rogueUser).balance;
            assertGt(rogueUserBalance, 0);
            uint256 poolKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolKYCOwner).balance;
            assertGt(poolKYCOwnerBalance, 0);
            uint256 poolNonKYCOwnerBalance = address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner).balance;
            assertGt(poolNonKYCOwnerBalance, 0);
            uint256 tokenPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner).balance;
            assertGt(tokenPolicyOwnerBalance, 0);
            uint256 usdcBlacklistPolicyOwnerBalance = address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner).balance;
            assertGt(usdcBlacklistPolicyOwnerBalance, 0);
            uint256 kycHookOwnerBalance = address(networkConfigAfterDeployment.activeOwners.kycHookOwner).balance;
            assertGt(kycHookOwnerBalance, 0);
        }
    }

    function test_netWorkConfig_Is_UpdatedAfterDeployment() public {
        if (block.chainid == ANVIL_CHAIN_ID) {
            assertTrue(address(networkConfigAfterDeployment.uniswapV4Contracts.poolManager) != address(0));

            assertTrue(address(networkConfigAfterDeployment.routerContracts.kycRouter) != address(0));
            assertTrue(address(networkConfigAfterDeployment.routerContracts.maliciousRouter) != address(0));
            assertTrue(address(networkConfigAfterDeployment.routerContracts.carelessRouter) != address(0));
            assertTrue(address(networkConfigAfterDeployment.routerContracts.swapRouter) != address(0));
            assertTrue(address(networkConfigAfterDeployment.routerContracts.modifyLiquidityRouter) != address(0));

            assertTrue(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token0) != address(0));
            assertTrue(Currency.unwrap(networkConfigAfterDeployment.erc20Contracts.pool_token1) != address(0));
            assertTrue(address(networkConfigAfterDeployment.erc20Contracts.usdc_token) != address(0));
            assertTrue(address(networkConfigAfterDeployment.erc20Contracts.link_token) != address(0));

            assertTrue(address(networkConfigAfterDeployment.policyContracts.kycTokenPolicy) != address(0));
            assertTrue(address(networkConfigAfterDeployment.policyContracts.kycToken) != address(0));

            assertTrue(address(networkConfigAfterDeployment.activeOwners.poolKYCOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.poolNonKYCOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.tokenPolicyOwner) != address(0));
            // assertTrue(address(networkConfigAfterDeployment.activeOwners.usdcBlacklistPolicyOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.kycHookOwner) != address(0));
            // assertTrue(address(networkConfigAfterDeployment.activeOwners.kycHook_byWhitelistOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.kycRouterOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.maliciousRouterOwner) != address(0));
            assertTrue(address(networkConfigAfterDeployment.activeOwners.carelessRouterOwner) != address(0));
        }
    }
}
