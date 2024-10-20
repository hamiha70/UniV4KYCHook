// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {KYCHook} from "../src/hooks/KYCHook.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {KYCRouter} from "../src/routers/KYCRouter.sol";
import {MaliciousRouter} from "../src/routers/MaliciousRouter.sol";
import {LazyRouter} from "../src/routers/LazyRouter.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {KYCPolicy} from "../src/base/KYCPolicy.sol";
import {KYCTokenPolicy} from "../src/policies/KYCTokenPolicy.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {RetailKYC, RetailKYCInformation, IdDocumentsBundle} from "../src/base/RetailKYC.sol";
import {KYCToken} from "../src/base/KYCToken.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {console} from "forge-std/console.sol";

import "@openzeppelin/contracts/utils/Strings.sol";

abstract contract CodeConstants {
    using RetailKYC for IdDocumentsBundle;
    // Chain IDs and related constants --------------------------------------------------------------------------------//
    // Sepolia
    uint256 public constant ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant ETHEREUM_SEPOLIA_KYC_HOOK_DEPLOYMENT_BLOCK = 6699900;
    // Anvil
    uint256 public constant ANVIL_CHAIN_ID = 31337;
    uint256 public constant ANVIL_KYC_HOOK_DEPLOYMENT_BLOCK = 1000;
    address public constant ANVIL_DEPLOYER_KEY = address(0x0);
    // KYCHook flags --------------------------------------------------------------------------------------------------//
    uint160 public constant KYC_HOOK_FLAGS = Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG
        | Hooks.BEFORE_INITIALIZE_FLAG | Hooks.AFTER_INITIALIZE_FLAG;
    uint160 public constant ANVIL_HOOK_OFFSET = 23484 * 2 ** 24;
    address public constant KYC_HOOK_ADDRESS_ANVIL = address(uint160(KYC_HOOK_FLAGS | ANVIL_HOOK_OFFSET));
    // CHAINLINK ADDRESSES ------------------------------------------------------------------------------------------//
    // Swap Parameters -----------------------------------------------------------------------------------------------//

    // Pool initialization Parameters --------------------------------------------------------------------------------//

    uint160 public constant SQRT_PRICE_1_1 = 79228162514264337593543950336;
    // Swapper Initial Documents Bundle ------------------------------------------------------------------------------//
    IdDocumentsBundle public SWAPPER_INITIAL_DOCUMENTS_BUNDLE = IdDocumentsBundle({
        Passport: true,
        SSCard: true,
        DriverLicense: true,
        DoDId: true,
        BirthCertificate: true,
        MailedBills: 3
    });
    IdDocumentsBundle public LIQUIDITY_PROVIDER_INITIAL_DOCUMENTS_BUNDLE = IdDocumentsBundle({
        Passport: true,
        SSCard: true,
        DriverLicense: true,
        DoDId: true,
        BirthCertificate: true,
        MailedBills: 12
    });
    IdDocumentsBundle public ROGUE_USER_INITIAL_DOCUMENTS_BUNDLE = IdDocumentsBundle({
        Passport: false,
        SSCard: false,
        DriverLicense: true,
        DoDId: false,
        BirthCertificate: false,
        MailedBills: 0
    });
    // Initial Consumer KYC Standard ------------------------------------------------------------------------------//
    RetailKYCInformation public INITIAL_CONSUMER_KYC_STANDARD = ROGUE_USER_INITIAL_DOCUMENTS_BUNDLE.getRetailKYCInformationFromIdDocuments();
    RetailKYCInformation public STRICTER_CONSUMER_KYC_STANDARD = SWAPPER_INITIAL_DOCUMENTS_BUNDLE.getRetailKYCInformationFromIdDocuments();
}

// Contains the mapping of the funded addresses on the different chains to roles in the KYC excosystem
abstract contract EnvLookups is CodeConstants {
    mapping(uint256 chainId => mapping(string role => string envVar)) public envAddr;
    mapping(uint256 chainId => mapping(string role => string envVar)) public envPrivKey;

    constructor() {
        envAddr[ANVIL_CHAIN_ID]["initialDeployer"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["poolKYCOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["poolNonKYCOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["tokenPolicyOwner"] = "ANVIL_ACCOUNT_ADDRESS_7";
        envAddr[ANVIL_CHAIN_ID]["tokenOwner"] = "ANVIL_ACCOUNT_ADDRESS_6";
        envAddr[ANVIL_CHAIN_ID]["usdcBlacklistPolicyOwner"] = "ANVIL_ACCOUNT_ADDRESS_7";
        envAddr[ANVIL_CHAIN_ID]["kycHookOwner"] = "ANVIL_ACCOUNT_ADDRESS_3";
        envAddr[ANVIL_CHAIN_ID]["kycHook_byWhitelistOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["kycRouterOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["maliciousRouterOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["carelessRouterOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["swapRouterOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["modifyLiquidityRouterOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["brevisRequestOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["brevisProofOwner"] = "ANVIL_ACCOUNT_ADDRESS_2";
        envAddr[ANVIL_CHAIN_ID]["swapper"] = "ANVIL_ACCOUNT_ADDRESS_4";
        envAddr[ANVIL_CHAIN_ID]["liquidityProvider"] = "ANVIL_ACCOUNT_ADDRESS_8";
        envAddr[ANVIL_CHAIN_ID]["rogueUser"] = "ANVIL_ACCOUNT_ADDRESS_5";

        envPrivKey[ANVIL_CHAIN_ID]["initialDeployer"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["poolKYCOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["poolNonKYCOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["tokenPolicyOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_7";
        envPrivKey[ANVIL_CHAIN_ID]["tokenOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_6";
        envPrivKey[ANVIL_CHAIN_ID]["usdcBlacklistPolicyOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_7";
        envPrivKey[ANVIL_CHAIN_ID]["kycHookOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_3";
        envPrivKey[ANVIL_CHAIN_ID]["kycHook_byWhitelistOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["kycRouterOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["maliciousRouterOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["carelessRouterOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["swapRouterOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["modifyLiquidityRouterOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["brevisRequestOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["brevisProofOwner"] = "ANVIL_ACCOUNT_PRIVATE_KEY_2";
        envPrivKey[ANVIL_CHAIN_ID]["swapper"] = "ANVIL_ACCOUNT_PRIVATE_KEY_4";
        envPrivKey[ANVIL_CHAIN_ID]["liquidityProvider"] = "ANVIL_ACCOUNT_PRIVATE_KEY_8";
        envPrivKey[ANVIL_CHAIN_ID]["rogueUser"] = "ANVIL_ACCOUNT_PRIVATE_KEY_5"; 
    
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["initialDeployer"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["poolKYCOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["poolNonKYCOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenPolicyOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_7";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_6";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["usdcBlacklistPolicyOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_7";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHookOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_3";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHook_byWhitelistOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycRouterOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["maliciousRouterOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["carelessRouterOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["swapRouterOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["modifyLiquidityRouterOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisRequestOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisProofOwner"] = "SEPOLIA_ACCOUNT_ADDRESS_2";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["swapper"] = "SEPOLIA_ACCOUNT_ADDRESS_4";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["liquidityProvider"] = "SEPOLIA_ACCOUNT_ADDRESS_8";
        envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["rogueUser"] = "SEPOLIA_ACCOUNT_ADDRESS_5";

        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["initialDeployer"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["poolKYCOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["poolNonKYCOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenPolicyOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_7"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_6"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["usdcBlacklistPolicyOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_7"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHookOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_3"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHook_byWhitelistOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["kycRouterOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["maliciousRouterOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["carelessRouterOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["swapRouterOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["modifyLiquidityRouterOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisRequestOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisProofOwner"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_2"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["swapper"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_4"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["liquidityProvider"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_8"; 
        envPrivKey[ETHEREUM_SEPOLIA_CHAIN_ID]["rogueUser"] = "SEPOLIA_ACCOUNT_PRIVATE_KEY_5"; 
    }
}

abstract contract AnvilConstants {
    // CONTROLLED ADRRESSES ----------------------------------------------- //
    // DEPLOYED CONTRACTS ------------------------------------------------- //
    // Hooks
    address public constant KYC_HOOK_ANVIL = address(0x0);
    address public constant KYC_HOOK_BY_WHITELIST_ANVIL = address(0x0);
    // Routers
    address public constant KYC_ROUTER_ANVIL = address(0x0);
    address public constant MALICIOUS_ROUTER_ANVIL = address(0x0);
    address public constant CARELESS_ROUTER_ANVIL = address(0x0);
    address public constant SWAP_ROUTER_ANVIL = address(0x0);
    address public constant MODIFY_LIQUIDITY_ROUTER_ANVIL = address(0x0);
    // Policies
    address public constant TOKEN_POLICY_ANVIL = address(0x0);
    address public constant USDC_BLACKLIST_POLICY_ANVIL = address(0x0);
    // Tokens ERC20
    address public constant LINK_TOKEN_ANVIL = address(0x0);
    address public constant USDC_TOKEN_ANVIL = address(0x0);
    // Brevis
    address public constant BREVIS_REQUEST_ANVIL = address(0x0);
    address public constant BREVIS_PROOF_ANVIL = address(0x0);
    // Uniswap V4
    address public constant POOL_MANAGER_ANVIL = address(0x0);
    // Chainlink
    address public constant CHAINLINK_REQUEST_ANVIL = address(0x0);
    address public constant CHAINLINK_PROOF_ANVIL = address(0x0);

    address public constant CREATE2_DEPLOYER_ANVIL = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);
    uint256 public constant CONTROLED_GAS_LIMIT_POOL_MANAGER_DEPLOYMENT_ANVIL = 30_000_000;
}

abstract contract SepoliaEthereumConstants {
    // CONTROLLED ADRRESSES ----------------------------------------------- //
    // DEPLOYED CONTRACTS ------------------------------------------------- //
    // Hooks
    address public constant KYC_HOOK_SEPOLIA = address(0x92aA8E722d0f801f682f33387dFbC9521ed1b880);
    address public constant KYC_HOOK_BY_WHITELIST_SEPOLIA = address(0x0);
    // Routers
    address public constant KYC_ROUTER_SEPOLIA = address(0x8B9c277cEbF7290EDF10c3151a956FCFb42D031F);
    address public constant MALICIOUS_ROUTER_SEPOLIA = address(0x3c1749B8435b46B4Ab9DEFE0c3b32AD93Ef04c17);
    address public constant CARELESS_ROUTER_SEPOLIA = address(0x852b9e444823253Dfa5402d95766795637c68663);
    address public constant SWAP_ROUTER_SEPOLIA = address(0x81913C096c94eB5fD3634219BcDc557D9DA46C74);
    address public constant MODIFY_LIQUIDITY_ROUTER_SEPOLIA = address(0x74d6eFc23e63D9B5AE79F207598e8E65911cf549);
    // Policies
    address public constant TOKEN_POLICY_SEPOLIA = address(0x967293ADcC54b2A3982d76D26eD9E694cc6d8377);
    address public constant TOKEN_SEPOLIA = address(0x8198c6877F26D1d683A588AF0c5f72BdBa0242e5);
    address public constant USDC_BLACKLIST_POLICY_SEPOLIA = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
    // Tokens ERC20
    address public constant LINK_TOKEN_SEPOLIA = address(0x779877A7B0D9E8603169DdbD7836e478b4624789);
    address public constant USDC_TOKEN_SEPOLIA = address(0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238);
    address public constant POOL_TOKEN_0_SEPOLIA = address(0x2CEbC29106112a2C59e20818DaACDcc1322ACB3e);
    address public constant POOL_TOKEN_1_SEPOLIA = address(0xd76Cde845063Ab7925Be67D73537B1D1F045207A);
    // Brevis
    address public constant BREVIS_REQUEST_SEPOLIA = address(0x841ce48F9446C8E281D3F1444cB859b4A6D0738C);
    address public constant BREVIS_PROOF_SEPOLIA = address(0xea80589a5f3A45554555634525deFF2EcB6CC4FF);
    // Uniswap V4
    address public constant POOL_MANAGER_SEPOLIA = address(0xe4C3f51fB478DD18852111d77aa1160083ca6304);
    // Chainlink
    address public constant CHAINLINK_REGISTRY_SEPOLIA = address(0x86EFBD0b6736Bed994962f9797049422A3A8E8Ad); // Added Registry Address
    address public constant CHAINLINK_REGISTRAR_SEPOLIA = address(0xb0E49c5D0d05cbc241d68c05BC5BA1d1B7B72976); // Added Registrar Address

    address public constant CREATE2_DEPLOYER_SEPOLIA = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);
    uint256 public constant CONTROLED_GAS_LIMIT_POOL_MANAGER_DEPLOYMENT_SEPOLIA = 30_000_000;
}



contract HelperConfig is Script, CodeConstants, SepoliaEthereumConstants, AnvilConstants, EnvLookups {
    using PoolIdLibrary for PoolKey;
    // Errors ------------------------------------------------------------ //
    error HelperConfig__UnkownNetwork();
    error HelperConfig__NotImplemented();

    // Types ------------------------------------------------------------- //
    struct HookContracts {
        KYCHook kycHook;
    }
    /* KYCHook_byWhitelist kycHook_byWhitelist; */

    struct RouterContracts {
        KYCRouter kycRouter;
        MaliciousRouter maliciousRouter;
        LazyRouter carelessRouter;
        PoolSwapTest swapRouter;
        PoolModifyLiquidityTest modifyLiquidityRouter;
    }

    struct PolicyContracts {
        /* BlacklistPolicy usdcBlacklistPolicy; */
        KYCTokenPolicy kycTokenPolicy;
        KYCToken kycToken;
        RetailKYCInformation initialRetailKYCInformation;
    }

    struct ERC20Contracts {
        Currency pool_token0;
        Currency pool_token1;
        MockERC20 link_token;
        MockERC20 usdc_token;
    }

    struct BrevisContracts {
        address brevisRequest;
        address brevisProof;
    }

    struct UniswapV4Contracts {
        IPoolManager poolManager;
    }

    struct ChainlinkContracts {
        address chainlinkRequest;
        address chainlinkProof;
    }

    struct Pool {
        PoolKey key;
        bytes hookData;
        uint160 sqrtPriceX96;
    }

    struct ActiveOwners {
        // Initial Deployer
        address payable initialDeployer;
        // Pool
        address payable poolKYCOwner;
        address payable poolNonKYCOwner;
        // Policies
        address payable tokenPolicyOwner;
        address payable tokenOwner;
        address payable usdcBlacklistPolicyOwner;
        // Hooks
        address payable kycHookOwner;
        address payable kycHook_byWhitelistOwner;
        // Brevis
        address payable brevisRequestOwner;
        address payable brevisProofOwner;
        // KYCRouters
        address payable kycRouterOwner;
        address payable maliciousRouterOwner;
        address payable carelessRouterOwner;
        address payable swapRouterOwner;
        address payable modifyLiquidityRouterOwner;
    }

    struct Users {
        address payable swapper;
        address payable liquidityProvider;
        address payable rogueUser;
    }

    struct NetworkConfig {
        HookContracts hookContracts;
        RouterContracts routerContracts;
        PolicyContracts policyContracts;
        ERC20Contracts erc20Contracts;
        BrevisContracts brevisContracts;
        UniswapV4Contracts uniswapV4Contracts;
        ChainlinkContracts chainlinkContracts;
        ActiveOwners activeOwners;
        Users users;
        Pool kycPool;
        Pool nonKycPool;
        address deployer;
    }
    /* KYCToken kycToken; */

    // State variables ---------------------------------------------------- //
    NetworkConfig public s_localNetworkConfig;
    mapping(uint256 chainId => NetworkConfig) public s_networkConfigs;

    // Constructor --------------------------------------------------------- //
    constructor() {
        if (block.chainid == ETHEREUM_SEPOLIA_CHAIN_ID) {
            if (block.number <= ETHEREUM_SEPOLIA_KYC_HOOK_DEPLOYMENT_BLOCK) {
                s_networkConfigs[ETHEREUM_SEPOLIA_CHAIN_ID] = getCleanSepoliaEthereumNetworkConfig();
                s_localNetworkConfig = s_networkConfigs[ETHEREUM_SEPOLIA_CHAIN_ID];
            } else {
                s_networkConfigs[ETHEREUM_SEPOLIA_CHAIN_ID] = getDeployedSepoliaEthereumNetworkConfig();
                s_localNetworkConfig = s_networkConfigs[ETHEREUM_SEPOLIA_CHAIN_ID];
            }
        } else if (block.chainid == ANVIL_CHAIN_ID) {
            if (block.number <= ANVIL_KYC_HOOK_DEPLOYMENT_BLOCK) {
                s_networkConfigs[ANVIL_CHAIN_ID] = getCleanAnvilNetworkConfig();
                s_localNetworkConfig = s_networkConfigs[ANVIL_CHAIN_ID];
            } else {
                s_networkConfigs[ANVIL_CHAIN_ID] = getDeployedAnvilNetworkConfig();
                s_localNetworkConfig = s_networkConfigs[ANVIL_CHAIN_ID];
            }
        }
    }

    // Getters for the network config ---------------------------------------- //
    function getLocalNetworkConfig() public view returns (NetworkConfig memory) {
        return s_localNetworkConfig;
    }

    // Helpers to assemble the network config for the different chains and histories ----- //

    function getCleanSepoliaEthereumNetworkConfig() public view returns (NetworkConfig memory config) {
        console.log("Getting clean Sepolia Ethereum Network Config");
        // Brevis
        config.brevisContracts.brevisRequest = BREVIS_REQUEST_SEPOLIA;
        config.brevisContracts.brevisProof = BREVIS_PROOF_SEPOLIA;
        // Chainlink
        // ActiveOwners
        config.activeOwners.initialDeployer = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["initialDeployer"]));
        config.activeOwners.poolKYCOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["poolKYCOwner"]));
        config.activeOwners.poolNonKYCOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["poolNonKYCOwner"]));
        config.activeOwners.tokenPolicyOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenPolicyOwner"]));
        config.activeOwners.tokenOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["tokenOwner"]));
        config.activeOwners.usdcBlacklistPolicyOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["usdcBlacklistPolicyOwner"]));
        config.activeOwners.kycHookOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHookOwner"]));
        config.activeOwners.kycHook_byWhitelistOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycHook_byWhitelistOwner"]));
        config.activeOwners.kycRouterOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["kycRouterOwner"]));
        config.activeOwners.maliciousRouterOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["maliciousRouterOwner"]));
        config.activeOwners.carelessRouterOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["carelessRouterOwner"]));
        config.activeOwners.swapRouterOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["swapRouterOwner"]));
        config.activeOwners.modifyLiquidityRouterOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["modifyLiquidityRouterOwner"]));
        config.activeOwners.brevisRequestOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisRequestOwner"]));
        config.activeOwners.brevisProofOwner = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["brevisProofOwner"]));
        // Users
        config.users.swapper = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["swapper"]));
        config.users.liquidityProvider = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["liquidityProvider"]));
        config.users.rogueUser = payable(vm.envAddress(envAddr[ETHEREUM_SEPOLIA_CHAIN_ID]["rogueUser"]));
        // Already deployed ERC20
        config.erc20Contracts.link_token = MockERC20(LINK_TOKEN_SEPOLIA);
        config.erc20Contracts.usdc_token = MockERC20(USDC_TOKEN_SEPOLIA);
        // Brevis
        config.brevisContracts.brevisRequest = BREVIS_REQUEST_SEPOLIA;
        config.brevisContracts.brevisProof = BREVIS_PROOF_SEPOLIA;

        return config;
    }

    function getDeployedSepoliaEthereumNetworkConfig() public view returns (NetworkConfig memory) {
        console.log("Getting deployed Sepolia Ethereum Network Config");
        // Incremental to the clean config
        NetworkConfig memory config = getCleanSepoliaEthereumNetworkConfig();

        // Uniswap V4
        config.uniswapV4Contracts.poolManager = IPoolManager(POOL_MANAGER_SEPOLIA);
        // Hooks
        config.hookContracts.kycHook = KYCHook(KYC_HOOK_SEPOLIA);
        // Routers
        config.routerContracts.kycRouter = KYCRouter(KYC_ROUTER_SEPOLIA);
        config.routerContracts.maliciousRouter = MaliciousRouter(MALICIOUS_ROUTER_SEPOLIA);
        config.routerContracts.carelessRouter = LazyRouter(CARELESS_ROUTER_SEPOLIA);
        config.routerContracts.swapRouter = PoolSwapTest(SWAP_ROUTER_SEPOLIA);
        config.routerContracts.modifyLiquidityRouter = PoolModifyLiquidityTest(MODIFY_LIQUIDITY_ROUTER_SEPOLIA);
        // Policy
        config.policyContracts.kycTokenPolicy = KYCTokenPolicy(TOKEN_POLICY_SEPOLIA);
        config.policyContracts.kycToken = KYCToken(TOKEN_SEPOLIA);
        config.policyContracts.initialRetailKYCInformation = RetailKYC.getRetailKYCInformationFromIdDocuments(ROGUE_USER_INITIAL_DOCUMENTS_BUNDLE);
        // ERC20
        config.erc20Contracts.pool_token0 = Currency.wrap(POOL_TOKEN_0_SEPOLIA);
        config.erc20Contracts.pool_token1 = Currency.wrap(POOL_TOKEN_1_SEPOLIA);
        config.erc20Contracts.link_token = MockERC20(LINK_TOKEN_SEPOLIA);
        config.erc20Contracts.usdc_token = MockERC20(USDC_TOKEN_SEPOLIA);
        // Pool
        config.kycPool.key = PoolKey(Currency.wrap(POOL_TOKEN_0_SEPOLIA), Currency.wrap(POOL_TOKEN_1_SEPOLIA), 3000, 60, IHooks(KYC_HOOK_SEPOLIA));
        config.kycPool.hookData = bytes("");
        config.kycPool.sqrtPriceX96 = 0;
        config.nonKycPool.key = PoolKey(Currency.wrap(POOL_TOKEN_0_SEPOLIA), Currency.wrap(POOL_TOKEN_1_SEPOLIA), 3000, 60, IHooks(address(0)));
        config.nonKycPool.hookData = bytes("");
        config.nonKycPool.sqrtPriceX96 = 0;
        // Deployer
        config.deployer = CREATE2_DEPLOYER_SEPOLIA;
        return config;
    }

    function getCleanAnvilNetworkConfig() public view returns (NetworkConfig memory config) {
        console.log("Getting clean Anvil Network Config");
        // Brevis
        // TODO: Replace with Mock deployments
        config.brevisContracts.brevisRequest = BREVIS_REQUEST_ANVIL;
        config.brevisContracts.brevisProof = BREVIS_PROOF_ANVIL;
        // Chainlink
        // ActiveOwners
        config.activeOwners.initialDeployer = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["initialDeployer"]));
        config.activeOwners.poolKYCOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["poolKYCOwner"]));
        config.activeOwners.poolNonKYCOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["poolNonKYCOwner"]));
        config.activeOwners.tokenPolicyOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["tokenPolicyOwner"]));
        config.activeOwners.tokenOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["tokenOwner"]));
        config.activeOwners.usdcBlacklistPolicyOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["usdcBlacklistPolicyOwner"]));
        config.activeOwners.kycHookOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["kycHookOwner"]));
        config.activeOwners.kycHook_byWhitelistOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["kycHook_byWhitelistOwner"]));
        config.activeOwners.kycRouterOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["kycRouterOwner"]));
        config.activeOwners.maliciousRouterOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["maliciousRouterOwner"]));
        config.activeOwners.carelessRouterOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["carelessRouterOwner"]));
        config.activeOwners.swapRouterOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["swapRouterOwner"]));
        config.activeOwners.modifyLiquidityRouterOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["modifyLiquidityRouterOwner"]));
        config.activeOwners.brevisRequestOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["brevisRequestOwner"]));
        config.activeOwners.brevisProofOwner = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["brevisProofOwner"]));
        // Users
        config.users.swapper = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["swapper"]));
        config.users.liquidityProvider = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["liquidityProvider"]));
        config.users.rogueUser = payable(vm.envAddress(envAddr[ANVIL_CHAIN_ID]["rogueUser"]));
        
        return config;
    }

    function getDeployedAnvilNetworkConfig() public view returns (NetworkConfig memory config) {
        console.log("Getting deployed Anvil Network Config");
        config = getCleanAnvilNetworkConfig();
        // Uniswap V4
        config.uniswapV4Contracts.poolManager = IPoolManager(address(0x0));
        // Hooks
        config.hookContracts.kycHook = KYCHook(address(0x0));
        // Routers  
        config.routerContracts.kycRouter = KYCRouter(address(0x0));
        config.routerContracts.maliciousRouter = MaliciousRouter(address(0x0));
        config.routerContracts.carelessRouter = LazyRouter(address(0x0));
        config.routerContracts.swapRouter = PoolSwapTest(address(0x0));
        config.routerContracts.modifyLiquidityRouter = PoolModifyLiquidityTest(address(0x0));
        // Policy
        config.policyContracts.kycTokenPolicy = KYCTokenPolicy(address(0x0));
        config.policyContracts.kycToken = KYCToken(address(0x0));
        config.policyContracts.initialRetailKYCInformation = RetailKYC.getRetailKYCInformationFromIdDocuments(ROGUE_USER_INITIAL_DOCUMENTS_BUNDLE);
        // ERC20
        config.erc20Contracts.pool_token0 = Currency.wrap(address(0x0));
        config.erc20Contracts.pool_token1 = Currency.wrap(address(0x0));
        config.erc20Contracts.link_token = MockERC20(address(0x0));
        config.erc20Contracts.usdc_token = MockERC20(address(0x0));
        // Pool
        config.kycPool.key = PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0,0, IHooks(address(0)));
        config.kycPool.hookData = bytes("");
        config.kycPool.sqrtPriceX96 = 0;
        config.nonKycPool.key = PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0, 0, IHooks(address(0)));
        config.nonKycPool.hookData = bytes("");
        config.nonKycPool.sqrtPriceX96 = 0;
        // Deployer
        config.deployer = CREATE2_DEPLOYER_ANVIL;
        return config;
    }

    function printNetworkConfig(HelperConfig.NetworkConfig memory config) public view {
        console.log("\nNetwork Configuration for chainid:", block.chainid);
        console.log("block number:", block.number);
        console.log("------------------------------------");
        console.log("\nERC20 Contracts:");
        console.log("  LINK Token:", address(config.erc20Contracts.link_token));
        console.log("  USDC Token:", address(config.erc20Contracts.usdc_token));
        console.log("  Pool Token 0:", Currency.unwrap(config.erc20Contracts.pool_token0));
        console.log("  Pool Token 1:", Currency.unwrap(config.erc20Contracts.pool_token1));
        
        console.log("\nUniswap V4 Contracts:");
        console.log("  Pool Manager:", address(config.uniswapV4Contracts.poolManager));
        
        console.log("\nRouter Contracts:");
        console.log("  KYC Router:", address(config.routerContracts.kycRouter));
        console.log("  Malicious Router:", address(config.routerContracts.maliciousRouter));
        console.log("  Careless Router:", address(config.routerContracts.carelessRouter));
        console.log("  Swap Router:", address(config.routerContracts.swapRouter));
        console.log("  Modify Liquidity Router:", address(config.routerContracts.modifyLiquidityRouter));

        console.log("\nPolicy Contracts:");
        console.log("  KYC Token Policy:", address(config.policyContracts.kycTokenPolicy));
        console.log("  KYC Token:", address(config.policyContracts.kycToken));
        
        console.log("\nHook Contracts:");
        console.log("  KYC Hook:", address(config.hookContracts.kycHook));
        
        console.log("\nBrevis Contracts:");
        console.log("  Brevis Request:", address(config.brevisContracts.brevisRequest));
        console.log("  Brevis Proof:", address(config.brevisContracts.brevisProof));

        console.log("\nChainlink Contracts:");
        console.log("  Chainlink Request:", address(config.chainlinkContracts.chainlinkRequest));
        console.log("  Chainlink Proof:", address(config.chainlinkContracts.chainlinkProof));

        console.log("\nPools:");
        console.log("  KYC Pool PoolId:");
        printPoolKey(config.kycPool.key);
        console.log("  Non KYC Pool PoolId:");
        printPoolKey(config.nonKycPool.key);

        console.log("\nActive Owners:");
        console.log("  Pool KYC Owner:", config.activeOwners.poolKYCOwner);
        console.log("  Pool Non KYC Owner:", config.activeOwners.poolNonKYCOwner);
        console.log("  Token Policy Owner:", config.activeOwners.tokenPolicyOwner);
        console.log("  USDC Blacklist Policy Owner:", config.activeOwners.usdcBlacklistPolicyOwner);
        console.log("  KYC Hook Owner:", config.activeOwners.kycHookOwner);
        console.log("  KYC Hook by Whitelist Owner:", config.activeOwners.kycHook_byWhitelistOwner);
        console.log("  KYC Router Owner:", config.activeOwners.kycRouterOwner);
        console.log("  Malicious Router Owner:", config.activeOwners.maliciousRouterOwner);
        console.log("  Careless Router Owner:", config.activeOwners.carelessRouterOwner);

        console.log("\nUsers:");
        console.log("  Swapper:", config.users.swapper);
        console.log("  Liquidity Provider:", config.users.liquidityProvider);
        console.log("  Rogue User:", config.users.rogueUser);
        console.log("------------------------------------");
    }

    function printETHBalances(HelperConfig.NetworkConfig memory config) public view {
        address[] memory addresses = new address[](18);  // Adjust size as needed
        string[] memory labels = new string[](18); //

        addresses[0] = config.activeOwners.initialDeployer;
        labels[0] = "InitialDeployer";
        addresses[1] = config.activeOwners.poolKYCOwner;
        labels[1] = "PoolKYCOwner";
        addresses[2] = config.activeOwners.poolNonKYCOwner;
        labels[2] = "PoolNonKYCOwner";
        addresses[3] = config.activeOwners.tokenPolicyOwner;
        labels[3] = "TokenPolicyOwner";
        addresses[4] = config.activeOwners.tokenOwner;  
        labels[4] = "TokenOwner";
        addresses[5] = config.activeOwners.usdcBlacklistPolicyOwner;
        labels[5] = "USDCBlacklistPolicyOwner";
        addresses[6] = config.activeOwners.kycHookOwner;
        labels[6] = "KYCHookOwner";
        addresses[7] = config.activeOwners.kycHook_byWhitelistOwner;
        labels[7] = "KYCHook_byWhitelistOwner";
        addresses[8] = config.activeOwners.kycRouterOwner;
        labels[8] = "KYCRouterOwner";
        addresses[9] = config.activeOwners.maliciousRouterOwner;
        labels[9] = "MaliciousRouterOwner";
        addresses[10] = config.activeOwners.carelessRouterOwner;
        labels[10] = "CarelessRouterOwner";
        addresses[11] = config.activeOwners.swapRouterOwner;
        labels[11] = "SwapRouterOwner";
        addresses[12] = config.activeOwners.modifyLiquidityRouterOwner;
        labels[12] = "ModifyLiquidityRouterOwner";
        addresses[13] = config.activeOwners.brevisRequestOwner;
        labels[13] = "BrevisRequestOwner";
        addresses[14] = config.activeOwners.brevisProofOwner;
        labels[14] = "BrevisProofOwner";
        addresses[15] = config.users.swapper;
        labels[15] = "Swapper";
        addresses[16] = config.users.liquidityProvider;
        labels[16] = "LiquidityProvider";
        addresses[17] = config.users.rogueUser;
        labels[17] = "RogueUser";

        console.log("ETH Balances:");
        for (uint i = 0; i < addresses.length; i++) {
            uint256 balanceWei = addresses[i].balance;
            uint256 balanceEther = balanceWei / 1e18;
            uint256 decimalPart = (balanceWei % 1e18) / 1e14;
            
            string memory balanceStr = string(abi.encodePacked(
                Strings.toString(balanceEther),
                ".",
                leftPadZeros(Strings.toString(decimalPart), 4)
            ));
            
            uint256 spaces = 20 - bytes(balanceStr).length;
            string memory paddedBalance = string(abi.encodePacked(
                new string(spaces),
                balanceStr
            ));
            
            console.log(string(abi.encodePacked(
                paddedBalance,
                " ETH  ",
                Strings.toHexString(uint160(addresses[i]), 20), // Convert address to hex string
                " ",
                labels[i]
            )));
        }
        console.log("\n");
    }

    function leftPadZeros(string memory s, uint256 targetLength) private pure returns (string memory) {
        bytes memory bStr = bytes(s);
        if (bStr.length >= targetLength) return s;
        
        bytes memory bZero = bytes("0");
        bytes memory result = new bytes(targetLength);
        uint j = targetLength;
        uint i = bStr.length;
        while (j > 0) {
            j--;
            if (i > 0) {
                i--;
                result[j] = bStr[i];
            } else {
                result[j] = bZero[0];
            }
        }
        return string(result);
    }
    
    function printPoolKey(PoolKey memory key) internal pure{
        console.log("PoolKey:");
        console.log("  Token0:", Currency.unwrap(key.currency0));
        console.log("  Token1:", Currency.unwrap(key.currency1));
        console.log("  Fee:", key.fee);
        console.log("  TickSpacing:", key.tickSpacing);
        console.log("  Hooks:", address(key.hooks));
    }
}