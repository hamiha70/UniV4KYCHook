// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {KYCHook} from "../src/hooks/KYCHook.sol";
/* import {KYCHook_byWhitelist} from "../src/Hooks/KYCHook_byWhitelistc.sol"; */
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {KYCRouter} from "../src/routers/KYCRouter.sol";
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

abstract contract CodeConstants {
    uint256 public constant ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant ETHEREUM_MAINNET_CHAIN_ID = 1;
    uint256 public constant ANVIL_CHAIN_ID = 31337;

    address public constant ANVIL_DEPLOYER_KEY = address(0x0);

    uint160 public constant KYC_HOOK_FLAGS = Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG
        | Hooks.BEFORE_INITIALIZE_FLAG | Hooks.AFTER_INITIALIZE_FLAG;
    uint160 public constant KYC_HOOK_BY_WHITELIST_FLAGS = Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG;
    uint160 public constant ANVIL_HOOK_OFFSET = 23484 * 2 ** 24;
    address public constant KYC_HOOK_ADDRESS_ANVIL = address(uint160(KYC_HOOK_FLAGS | ANVIL_HOOK_OFFSET));
    address public constant KYC_HOOK_BY_WHITELIST_ADDRESS_ANVIL =
        address(uint160(Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | ANVIL_HOOK_OFFSET));
    uint160 public constant SQRT_PRICE_1_1 = 79228162514264337593543950336;
}

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
    address public constant KYC_HOOK_SEPOLIA = address(0x0);
    address public constant KYC_HOOK_BY_WHITELIST_SEPOLIA = address(0x0);
    // Routers
    address public constant KYC_ROUTER_SEPOLIA = address(0x0);
    address public constant MALICIOUS_ROUTER_SEPOLIA = address(0x0);
    address public constant CARELESS_ROUTER_SEPOLIA = address(0x0);
    address public constant SWAP_ROUTER_SEPOLIA = address(0x0);
    address public constant MODIFY_LIQUIDITY_ROUTER_SEPOLIA = address(0x0);
    // Policies
    address public constant TOKEN_POLICY_SEPOLIA = address(0x0);
    address public constant USDC_BLACKLIST_POLICY_SEPOLIA = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    // Tokens ERC20
    address public constant LINK_TOKEN_SEPOLIA = 0x779877A7B0D9E8603169DdbD7836e478b4624789;
    address public constant USDC_TOKEN_SEPOLIA = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    // Brevis
    address public constant BREVIS_REQUEST_SEPOLIA = 0x841ce48F9446C8E281D3F1444cB859b4A6D0738C;
    address public constant BREVIS_PROOF_SEPOLIA = 0xea80589a5f3A45554555634525deFF2EcB6CC4FF;

    address public constant CHAINKINK_AUTOMATION_REGISTY_SEPOLIA = 0x694AA1769357215DE4FAC081bf1f309aDC325306; // To be verified

    address public constant CREATE2_DEPLOYER_SEPOLIA = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);
    uint256 public constant CONTROLED_GAS_LIMIT_POOL_MANAGER_DEPLOYMENT_SEPOLIA = 30_000_000;
}



contract HelperConfig is Script, CodeConstants, SepoliaEthereumConstants, AnvilConstants {
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
        KYCRouter maliciousRouter;
        KYCRouter carelessRouter;
        PoolSwapTest swapRouter;
        PoolModifyLiquidityTest modifyLiquidityRouter;
    }

    struct PolicyContracts {
        /* BlacklistPolicy usdcBlacklistPolicy; */
        KYCTokenPolicy kycTokenPolicy;
        KYCToken kycToken;
        RetailKYCInformation consumerKYCStandard;
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
        // Pool
        address payable poolKYCOwner;
        address payable poolNonKYCOwner;
        // Policies
        address payable tokenPolicyOwner;
        address payable usdcBlacklistPolicyOwner;
        // Hooks
        address payable kycHookOwner;
        address payable kycHook_byWhitelistOwner;
        // KYCRouters
        address payable kycRouterOwner;
        address payable maliciousRouterOwner;
        address payable carelessRouterOwner;
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
        s_networkConfigs[ETHEREUM_SEPOLIA_CHAIN_ID] = NetworkConfig({
            hookContracts: HookContracts({
                /* kycHook_byWhitelist: KYCHook_byWhitelist(address(0x0)), */
                kycHook: KYCHook(address(0x0))
            }),
            routerContracts: RouterContracts({
                kycRouter: KYCRouter(address(0x0)),
                maliciousRouter: KYCRouter(address(0x0)),
                carelessRouter: KYCRouter(address(0x0)),
                swapRouter: PoolSwapTest(address(0x0)),
                modifyLiquidityRouter: PoolModifyLiquidityTest(address(0x0))
            }),
            policyContracts: PolicyContracts({
                /* usdcBlacklistPolicy: BlacklistPolicy(address(0x0)), */
                kycTokenPolicy: KYCTokenPolicy(address(0x0)),
                kycToken: KYCToken(address(0x0)),
                consumerKYCStandard: RetailKYCInformation(0, 0, 0, 0, 0, 0, 0, 0, 0)
            }),
            erc20Contracts: ERC20Contracts({
                pool_token0: Currency.wrap(address(0x0)),
                pool_token1: Currency.wrap(address(0x0)),
                link_token: MockERC20(address(0x0)),
                usdc_token: MockERC20(address(0x0))
            }),
            brevisContracts: BrevisContracts({brevisRequest: address(0x0), brevisProof: address(0x0)}),
            uniswapV4Contracts: UniswapV4Contracts({poolManager: IPoolManager(address(0x0))}),
            chainlinkContracts: ChainlinkContracts({chainlinkRequest: address(0x0), chainlinkProof: address(0x0)}),
            activeOwners: ActiveOwners({
                poolKYCOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2")),
                poolNonKYCOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2")),
                tokenPolicyOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_7")),
                usdcBlacklistPolicyOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_7")),
                kycHookOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_3")),
                kycHook_byWhitelistOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2")),
                kycRouterOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2")),
                maliciousRouterOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2")),
                carelessRouterOwner: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_2"))
            }),
            users: Users({
                swapper: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_4")),
                liquidityProvider: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_8")),
                rogueUser: payable(vm.envAddress("SEPOLIA_ACCOUNT_ADDRESS_5"))
            
            }),
            kycPool: Pool({
                key: PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0,0, IHooks(address(0))),
                hookData: bytes(""),
                sqrtPriceX96: 0
            }),
            nonKycPool: Pool({
                key: PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0, 0, IHooks(address(0))),
                hookData: bytes(""),
                sqrtPriceX96: 0
            }),
            deployer: CREATE2_DEPLOYER_SEPOLIA
        });
        s_networkConfigs[ANVIL_CHAIN_ID] = NetworkConfig({
            hookContracts: HookContracts({
                /* kycHook_byWhitelist: KYCHook_byWhitelist(address(0x0)), */
                kycHook: KYCHook(address(0x0))
            }),
            routerContracts: RouterContracts({
                kycRouter: KYCRouter(address(0x0)),
                maliciousRouter: KYCRouter(address(0x0)),
                carelessRouter: KYCRouter(address(0x0)),
                swapRouter: PoolSwapTest(address(0x0)),
                modifyLiquidityRouter: PoolModifyLiquidityTest(address(0x0))
            }),
            policyContracts: PolicyContracts({
                /* usdcBlacklistPolicy: BlacklistPolicy(address(0x0)), */
                kycTokenPolicy: KYCTokenPolicy(address(0x0)),
                kycToken: KYCToken(address(0x0)),
                consumerKYCStandard: RetailKYCInformation(0, 0, 0, 0, 0, 0, 0, 0, 0)
            }),
            erc20Contracts: ERC20Contracts({
                pool_token0: Currency.wrap(address(0x0)),
                pool_token1: Currency.wrap(address(0x0)),
                link_token: MockERC20(address(0x0)),
                usdc_token: MockERC20(address(0x0))
            }),
            brevisContracts: BrevisContracts({brevisRequest: BREVIS_REQUEST_ANVIL, brevisProof: BREVIS_PROOF_ANVIL}),
            uniswapV4Contracts: UniswapV4Contracts({poolManager: IPoolManager(address(0x0))}),
            chainlinkContracts: ChainlinkContracts({chainlinkRequest: address(0x0), chainlinkProof: address(0x0)}),
            activeOwners: ActiveOwners({
                poolKYCOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2")),
                poolNonKYCOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2")),
                tokenPolicyOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_7")),
                usdcBlacklistPolicyOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_7")),
                kycHookOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_3")),
                kycHook_byWhitelistOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2")),
                kycRouterOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2")),
                maliciousRouterOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2")),
                carelessRouterOwner: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_2"))
            }),
            users: Users({
                swapper: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_4")),
                liquidityProvider: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_8")),
                rogueUser: payable(vm.envAddress("ANVIL_ACCOUNT_ADDRESS_5"))
            
            }),
            kycPool: Pool({
                key: PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0,0, IHooks(address(0))),
                hookData: bytes(""),
                sqrtPriceX96: 0
            }),
            nonKycPool: Pool({
                key: PoolKey(Currency.wrap(address(0x0)), Currency.wrap(address(0x0)), 0, 0, IHooks(address(0))),
                hookData: bytes(""),
                sqrtPriceX96: 0
            }),
            deployer: CREATE2_DEPLOYER_ANVIL
        });
    }
    // Getters ------------------------------------------------------------- //

    function getLocalNetworkConfigABIEncoded() public view returns (bytes memory) {
        return abi.encode(s_localNetworkConfig);
    }

    function getNetworkConfigABIEncoded(uint256 chainId) public view returns (bytes memory) {
        return abi.encode(s_networkConfigs[chainId]);
    }

    function getNetworkConfig(uint256 chainId) public view returns (NetworkConfig memory) {
        return s_networkConfigs[chainId];
    }

    // Functions ----------------------------------------------------------- //
}
