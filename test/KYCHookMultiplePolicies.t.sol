// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";

import {KYCHookMultiplePolicies, InitializeSettings} from "../src/hooks/KYCHookMultiplePolicies.sol";
import {BlacklistPolicy} from "../src/policies/BlacklistPolicy.sol";
import {WhitelistPolicy} from "../src/policies/WhitelistPolicy.sol";
import {BlackWhitelistPolicy} from "../src/policies/BlackWhitelistPolicy.sol";
import {Policy} from "../src/base/Policy.sol";
import {KYCPolicy} from "../src/base/KYCPolicy.sol";

import {TickMath} from "v4-core/libraries/TickMath.sol";
import {console} from "forge-std/console.sol";

contract TestKYCHookMultiplePolicies is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;
    using TickMath for int24;
    using TickMath for uint160;

    BlackWhitelistPolicy policy;
    WhitelistPolicy whitelistPolicy;
    BlacklistPolicy blacklistPolicy;

    address policyAddress;
    address whitelistPolicyAddress;
    address blacklistPolicyAddress;

    KYCHookMultiplePolicies hook;
    PoolId[] poolIds = new PoolId[](3);
    PoolKey poolKey_WhitelistPolicy;
    PoolKey poolKey_BlacklistPolicy;
    PoolKey poolKey_BlackWhitelistPolicy;

    address policyOwner = address(bytes20(keccak256(abi.encodePacked("BlackWhitelistPolicyOwner"))));
    address randomAddress = address(0x0234000);

    // Some addresses for blacklist and whitelist to use in tests
    address constant usdc_banned_example = address(0x0AbF039DFf7FF57D7a290362b64FFcd82009E8a9);
    address constant usdc_allowed_example = address(0x0aBf039dFF7FF57d7a290362B64FFcD82009E8a8);
    address constant example1 = address(0x0FEf039dff7FF57d7a290362B64Ffcd82009E8A7);
    address constant example2 = address(0x0abF039dfF7Ff57D7A290362B64FFcD82009e8A6);
    address constant example3 = address(0x0aBF039dff7FF57D7A290362B64Ffcd82009E8Aa);
    address constant example4 = address(0x0AbF039dfF7Ff57d7a290362B64FFcd82009e8aB);
    address constant explicit_allowed_example = address(0x0ABF039dFf7ff57D7A290362B64fFCD82009e8a3);
    address constant explicit_banned_example = address(0x0abF039dfF7Ff57D7A290362B64FFcD82009e8A6);
    address constant explicit_whitelisted_example = address(0x0AbF039dFF7ff57D7A290362B64fFcD82009E8a5);
    address constant explicit_blacklisted_example = address(0x0AbF039DFf7ff57D7a290362B64ffCD82009E8A4);
    address constant explicit_banned_example2 = address(0x0aBF039dFf7ff57D7a290362b64ffcd82009E8A2);
    address constant example_on_both_lists = address(0x0Abf039dFf7ff57D7a290362B64FfCD82009E8a1);
    address constant example_not_on_any_list = address(0x0ABf039DfF7Ff57D7A290362b64ffCd82009e8a0);
    address[] initialWhitelist = [explicit_whitelisted_example, example_on_both_lists];
    address[] initialBlacklist = [explicit_blacklisted_example, example_on_both_lists];
    address[] more_examples_full = [example1, example2, example3, example4];
    address[] more_examples_partial = [example1, example2];

    function setUp() public {
        //Deploy v4-core
        console.log("Deploying v4-core");
        deployFreshManagerAndRouters();
        console.log("PoolManager is %s", address(manager));
        console.log("Address(this) is %s", address(this));

        //Deploy, mint tokens and approve all periphery contracts for two tokens
        console.log("Deploying and mint 2 currencies");
        deployMintAndApprove2Currencies();
        console.log("Currency0: %s", Currency.unwrap(currency0));
        console.log("Currency1: %s", Currency.unwrap(currency1));

        //Deploy policies
        console.log("\nDeploying policies");
        //Deploy WhitelistPolicy
        whitelistPolicyAddress = address(bytes20(keccak256(abi.encodePacked("WhitelistPolicy"))));
        deployCodeTo("WhitelistPolicy", abi.encode(initialWhitelist), whitelistPolicyAddress);
        whitelistPolicy = WhitelistPolicy(whitelistPolicyAddress);
        console.log("WhitelistPolicy contract deployed with address     : %s", whitelistPolicyAddress);
        //Deploy BlacklistPolicy
        blacklistPolicyAddress = address(bytes20(keccak256(abi.encodePacked("BlacklistPolicy"))));
        deployCodeTo("BlacklistPolicy", abi.encode(initialBlacklist), blacklistPolicyAddress);
        blacklistPolicy = BlacklistPolicy(blacklistPolicyAddress);
        console.log("BlacklistPolicy contract deployed with addres      : %s", blacklistPolicyAddress);
        //Deploy BlackWhitelist policy
        policyAddress = address(bytes20(keccak256(abi.encodePacked("BlackWhitelistPolicy"))));
        deployCodeTo("BlackWhitelistPolicy", abi.encode(initialWhitelist, initialBlacklist), policyAddress);
        policy = BlackWhitelistPolicy(policyAddress);
        console.log("BlackwhitelistPolicy contract deployed with address: %s", policyAddress);

        //Deploy hooks with differnt addresses
        console.log("\nDeploying hook with 3 policies");
        //Deploy KYCHookMultiplePolicies with all policies
        uint160 hookOffset = uint160(1081523411 * 2 ** 22); // distinguish from other hooks
        address hookAddress = address(
            uint160(
                Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_INITIALIZE_FLAG | hookOffset
            )
        );
        //Note: constructor of KYCBaseHook takes arguments (IPoolManager _manager, string memory _uri, address _policyContractAddress)
        address[] memory policyAddresses = new address[](3);
        policyAddresses[0] = address(whitelistPolicy);
        policyAddresses[1] = address(blacklistPolicy);
        policyAddresses[2] = address(policy);
        deployCodeTo(
            "src/hooks/KYCHookMultiplePolicies.sol:KYCHookMultiplePolicies", 
            abi.encode(manager, "", policyAddresses), hookAddress
            );
        // deployCodeTo("KYCHookMultiplePolicies", abi.encode(manager, "", policyAddresses), hookAddress);
        hook = KYCHookMultiplePolicies(hookAddress);
        console.log("Hook address: %s", hookAddress);
        //Deploy Pools with the 3 policies
        bytes memory hookData;
        PoolKey memory key;
        InitializeSettings[3] memory settings;
        uint24[3] memory fees;
        fees[0] = 500;
        fees[1] = 3000;
        fees[2] = 100;
        settings[0] = InitializeSettings({policyContractAddress: address(whitelistPolicy), isKYCRequired: true});
        settings[1] = InitializeSettings({policyContractAddress: address(blacklistPolicy), isKYCRequired: true});
        settings[2] = InitializeSettings({policyContractAddress: address(policy), isKYCRequired: true});

        for (uint256 i = 0; i < 3; i++) {
            hookData = abi.encode(settings[i]);
            (key, poolIds[i]) = initPool(currency0, currency1, hook, fees[i], int24(60), SQRT_PRICE_1_1, hookData);
            console.log("Pool is instialized with fee %d", key.fee);
            if (i == 0) {
                poolKey_WhitelistPolicy =
                    PoolKey(key.currency0, key.currency1, key.fee, key.tickSpacing, IHooks(address(hook)));
            } else if (i == 1) {
                poolKey_BlacklistPolicy =
                    PoolKey(key.currency0, key.currency1, key.fee, key.tickSpacing, IHooks(address(hook)));
            } else {
                poolKey_BlackWhitelistPolicy =
                    PoolKey(key.currency0, key.currency1, key.fee, key.tickSpacing, IHooks(address(hook)));
            }
        }
        //Approve hook to spend tokensc
        MockERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        MockERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);

        console.log("\nSetup done\n");
    }

    function test_setup() public view {
        //Check that all policies are set up correctly
        assertEq(hook.isKycPolicy(address(whitelistPolicy)), true);
        assertEq(hook.isKycPolicy(address(blacklistPolicy)), true);
        assertEq(hook.isKycPolicy(address(policy)), true);
        console.log("Policy Addresses are set correctly");
        assertEq(hook.policyAddress(poolIds[0]), address(whitelistPolicy));
        assertEq(hook.policyAddress(poolIds[1]), address(blacklistPolicy));
        assertEq(hook.policyAddress(poolIds[2]), address(policy));
        console.log("Policy Addresses are correctly stored against PoolId");
        assertEq(hook.poolCreator(poolIds[0]), address(this));
        assertEq(hook.poolCreator(poolIds[1]), address(this));
        assertEq(hook.poolCreator(poolIds[2]), address(this));
        console.log("PoolCreator is correctly set to address(this)");
        uint24[] memory fees = new uint24[](3);
        fees[0] = 500;
        fees[1] = 3000;
        fees[2] = 100;
        PoolKey[] memory poolKeys = new PoolKey[](3);
        for (uint256 i = 0; i < 3; i++) {
            poolKeys[i] = PoolKey({
                currency0: currency0,
                currency1: currency1,
                fee: fees[i],
                tickSpacing: int24(60),
                hooks: IHooks(address(hook))
            });
        }
        assertEq(PoolId.unwrap(poolIds[0]), PoolId.unwrap(poolKeys[0].toId()));
        assertEq(PoolId.unwrap(poolIds[1]), PoolId.unwrap(poolKeys[1].toId()));
        assertEq(PoolId.unwrap(poolIds[2]), PoolId.unwrap(poolKeys[2].toId()));
        console.log("PoolIds are correctly set to PoolKeys");
        console.log("Setup test passed\n");
    }

    function test_WhitelistPolicy() public {
        // Check Whitelist Policy independant of usage inside Hook
        console.log("Testing WhitelistPolicy");
        // Check Policy initialization
        assertEq(whitelistPolicy.isWhitelisted(explicit_whitelisted_example), true, "Should be whitelisted");
        assertEq(whitelistPolicy.isWhitelisted(explicit_blacklisted_example), false, "Should not be whitelisted");
        assertEq(whitelistPolicy.isWhitelisted(example_on_both_lists), true, "Should be whitelisted");
        assertEq(whitelistPolicy.isWhitelisted(example_not_on_any_list), false, "Should not be whitelisted");
        //Check adding and removing single address after initialization
        assertEq(
            whitelistPolicy.isWhitelisted(explicit_allowed_example),
            false,
            "Should not be whitelisted after initialization"
        );
        whitelistPolicy.addToWhitelist(explicit_allowed_example);
        assertEq(whitelistPolicy.isWhitelisted(explicit_allowed_example), true, "Should be whitelisted after adding");
        // Check removing single non-whitelisted address - should have no effect
        whitelistPolicy.removeFromWhitelist(example_not_on_any_list);
        assertEq(
            whitelistPolicy.isWhitelisted(example_not_on_any_list), false, "Should not be whitelisted after removing"
        );
        // Check adding already whitelisted address - should have no effect
        whitelistPolicy.addToWhitelist(example_on_both_lists);
        assertEq(whitelistPolicy.isWhitelisted(example_on_both_lists), true, "Should be whitelisted after adding again");
        // Check add and remove empty list in batch
        whitelistPolicy.addToWhitelist(new address[](0));
        assertEq(
            whitelistPolicy.isWhitelisted(example_on_both_lists),
            true,
            "Should be whitelisted after adding empty list in batch"
        );
        whitelistPolicy.removeFromWhitelist(new address[](0));
        assertEq(
            whitelistPolicy.isWhitelisted(example_on_both_lists),
            true,
            "Should be whitelisted after removing empty list in batch"
        );
        // Check adding and removing addresses in batch
        whitelistPolicy.addToWhitelist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                whitelistPolicy.isWhitelisted(more_examples_full[i]), true, "Should be whitelisted after adding batch"
            );
        }
        whitelistPolicy.removeFromWhitelist(more_examples_partial);
        for (uint256 i = 0; i < more_examples_partial.length; i++) {
            assertEq(
                whitelistPolicy.isWhitelisted(more_examples_partial[i]),
                false,
                "Should not be whitelisted after removing batch"
            );
        }
        whitelistPolicy.removeFromWhitelist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                whitelistPolicy.isWhitelisted(more_examples_full[i]),
                false,
                "Should not be whitelisted after removing batch"
            );
        }
        // Check Authorization functions
        require(
            whitelistPolicy.isWhitelisted(example_on_both_lists),
            "Assert before testing validateSwapAuthorization: Should be whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            whitelistPolicy.validateSwapAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            true,
            "Whitelisted Swap should be authorized"
        );
        require(
            !whitelistPolicy.isWhitelisted(example_not_on_any_list),
            "Assert before testing validateSwapAuthorization: Should not be whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            whitelistPolicy.validateSwapAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            false,
            "Not whitelisted Swap should not be authorized"
        );
        require(
            whitelistPolicy.isWhitelisted(example_on_both_lists),
            "Assert before testing validateAddLiquidityAuthorization: Should be whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            whitelistPolicy.validateAddLiquidityAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            true,
            "Whitelisted AddLiquidity should be authorized"
        );
        //Case where address is not on any list
        require(
            !whitelistPolicy.isWhitelisted(example_not_on_any_list),
            "Assert before testing validateAddLiquidityAuthorization: Should not be whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            whitelistPolicy.validateAddLiquidityAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            false,
            "Not whitelisted AddLiquidity should not be authorized"
        );
    }

    function test_BlackWhitelistPolicy() public {
        // Check BlackWhitelist Policy independant of usage inside Hook
        console.log("\nTesting BlackWhitelistPolicy");
        // Check Policy initialization
        assertEq(policy.isWhitelisted(explicit_whitelisted_example), true, "Should be whitelisted");
        assertEq(policy.isWhitelisted(explicit_blacklisted_example), false, "Should not be whitelisted");
        assertEq(policy.isWhitelisted(example_on_both_lists), true, "Should be whitelisted");
        assertEq(policy.isWhitelisted(example_not_on_any_list), false, "Should not be whitelisted");
        assertEq(policy.isBlacklisted(explicit_blacklisted_example), true, "Should be blacklisted");
        assertEq(policy.isBlacklisted(explicit_whitelisted_example), false, "Should not be blacklisted");
        assertEq(policy.isBlacklisted(example_on_both_lists), true, "Should be blacklisted");
        assertEq(policy.isBlacklisted(example_not_on_any_list), false, "Should not be blacklisted");
        //Check adding and removing single address after initialization
        assertEq(
            policy.isWhitelisted(explicit_allowed_example), false, "Should not be whitelisted after initialization"
        );
        policy.addToWhitelist(explicit_allowed_example);
        assertEq(policy.isWhitelisted(explicit_allowed_example), true, "Should be whitelisted after adding");
        assertEq(policy.isBlacklisted(explicit_banned_example), false, "Should not be blacklisted after initialization");
        policy.addToBlacklist(explicit_banned_example);
        assertEq(policy.isBlacklisted(explicit_banned_example), true, "Should be blacklisted after adding");
        // Check removing single non-whitelisted address - should have no effect
        policy.removeFromWhitelist(example_not_on_any_list);
        assertEq(policy.isWhitelisted(example_not_on_any_list), false, "Should not be whitelisted after removing");
        // Check removing single non-blacklisted address - should have no effect
        policy.removeFromBlacklist(example_not_on_any_list);
        assertEq(policy.isBlacklisted(example_not_on_any_list), false, "Should not be blacklisted after removing");
        // Check adding already whitelisted address - should have no effect
        policy.addToWhitelist(example_on_both_lists);
        assertEq(policy.isWhitelisted(example_on_both_lists), true, "Should be whitelisted after adding again");
        // Check adding already blacklisted address - should have no effect
        policy.addToBlacklist(example_on_both_lists);
        assertEq(policy.isBlacklisted(example_on_both_lists), true, "Should be blacklisted after adding again");
        // Check add and remove empty list in batch
        policy.addToWhitelist(new address[](0));
        assertEq(
            policy.isWhitelisted(example_on_both_lists), true, "Should be whitelisted after adding empty list in batch"
        );
        policy.removeFromWhitelist(new address[](0));
        assertEq(
            policy.isWhitelisted(example_on_both_lists),
            true,
            "Should be whitelisted after removing empty list in batch"
        );
        policy.addToBlacklist(new address[](0));
        assertEq(
            policy.isBlacklisted(example_on_both_lists), true, "Should be blacklisted after adding empty list in batch"
        );
        policy.removeFromBlacklist(new address[](0));
        assertEq(
            policy.isBlacklisted(example_on_both_lists),
            true,
            "Should be blacklisted after removing empty list in batch"
        );
        // Check adding and removing addresses in batch
        policy.addToWhitelist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(policy.isWhitelisted(more_examples_full[i]), true, "Should be whitelisted after adding batch");
        }
        policy.removeFromWhitelist(more_examples_partial);
        for (uint256 i = 0; i < more_examples_partial.length; i++) {
            assertEq(
                policy.isWhitelisted(more_examples_partial[i]), false, "Should not be whitelisted after removing batch"
            );
        }
        policy.removeFromWhitelist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                policy.isWhitelisted(more_examples_full[i]), false, "Should not be whitelisted after removing batch"
            );
        }
        policy.addToBlacklist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(policy.isBlacklisted(more_examples_full[i]), true, "Should be blacklisted after adding batch");
        }
        policy.removeFromBlacklist(more_examples_partial);
        for (uint256 i = 0; i < more_examples_partial.length; i++) {
            assertEq(
                policy.isBlacklisted(more_examples_partial[i]), false, "Should not be blacklisted after removing batch"
            );
        }
        policy.removeFromBlacklist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                policy.isBlacklisted(more_examples_full[i]), false, "Should not be blacklisted after removing batch"
            );
        }
        // Check Authorization functions
        // Case where address is on both lists
        require(
            policy.isWhitelisted(example_on_both_lists) && policy.isBlacklisted(example_on_both_lists),
            "Assert before testing validateSwapAuthorization: Should be whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateSwapAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            true,
            "Whitelisted Swap should not be authorized even when it is also blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateAddLiquidityAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            true,
            "Whitelisted AddLiquidity should be authorized even when it is also blacklisted"
        );
        //Case where address is not on any list
        require(
            !policy.isWhitelisted(example_not_on_any_list) && !policy.isBlacklisted(example_not_on_any_list),
            "Assert before testing validateSwapAuthorization: Should not be whitelisted and not be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateSwapAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            true,
            "Should be authorized if address is on neither list"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateAddLiquidityAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            true,
            "Should be authorized if address is on neither list"
        );
        // Case where address is only on whitelist
        require(
            policy.isWhitelisted(explicit_whitelisted_example) && !policy.isBlacklisted(explicit_whitelisted_example),
            "Assert before testing validateSwapAuthorization: Should be whitelisted and not be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateSwapAuthorization(
                explicit_whitelisted_example,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            true,
            "Whitelisted Swap should be always authorized"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateAddLiquidityAuthorization(
                explicit_whitelisted_example,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            true,
            "Whitelisted AddLiquidity should be always authorized"
        );
        // Case where address is only on blacklist
        require(
            !policy.isWhitelisted(explicit_blacklisted_example) && policy.isBlacklisted(explicit_blacklisted_example),
            "Assert before testing validateSwapAuthorization: Should not be whitelisted and be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateSwapAuthorization(
                explicit_blacklisted_example,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            false,
            "Blacklisted Swap should not be authorized if not explicitely whitelisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            policy.validateAddLiquidityAuthorization(
                explicit_blacklisted_example,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            false,
            "Blacklisted AddLiquidity should not be authorized if not explicitely whitelisted"
        );
    }

    function test_BlacklistPolicy() public {
        // Check BlackWhitelist Policy independant of usage inside Hook
        console.log("Testing BlacklistPolicy");
        // Check Policy initialization
        assertEq(blacklistPolicy.isBlacklisted(explicit_blacklisted_example), true, "Should be blacklisted");
        assertEq(blacklistPolicy.isBlacklisted(explicit_whitelisted_example), false, "Should not be blacklisted");
        assertEq(blacklistPolicy.isBlacklisted(example_on_both_lists), true, "Should be blacklisted");
        assertEq(blacklistPolicy.isBlacklisted(example_not_on_any_list), false, "Should not be blacklisted");
        //Check adding and removing single address after initialization
        assertEq(
            blacklistPolicy.isBlacklisted(explicit_banned_example),
            false,
            "Should not be blacklisted after initialization"
        );
        blacklistPolicy.addToBlacklist(explicit_banned_example);
        assertEq(blacklistPolicy.isBlacklisted(explicit_banned_example), true, "Should be blacklisted after adding");
        // Check removing single non-blacklisted address - should have no effect
        blacklistPolicy.removeFromBlacklist(example_not_on_any_list);
        assertEq(
            blacklistPolicy.isBlacklisted(example_not_on_any_list), false, "Should not be blacklisted after removing"
        );
        // Check adding already blacklisted address - should have no effect
        blacklistPolicy.addToBlacklist(example_on_both_lists);
        assertEq(blacklistPolicy.isBlacklisted(example_on_both_lists), true, "Should be blacklisted after adding again");
        // Check add and remove empty list in batch
        blacklistPolicy.addToBlacklist(new address[](0));
        assertEq(
            blacklistPolicy.isBlacklisted(example_on_both_lists),
            true,
            "Should be blacklisted after adding empty list in batch"
        );
        blacklistPolicy.removeFromBlacklist(new address[](0));
        assertEq(
            blacklistPolicy.isBlacklisted(example_on_both_lists),
            true,
            "Should be blacklisted after removing empty list in batch"
        );
        // Check adding and removing addresses in batch
        blacklistPolicy.addToBlacklist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                blacklistPolicy.isBlacklisted(more_examples_full[i]), true, "Should be blacklisted after adding batch"
            );
        }
        blacklistPolicy.removeFromBlacklist(more_examples_partial);
        for (uint256 i = 0; i < more_examples_partial.length; i++) {
            assertEq(
                blacklistPolicy.isBlacklisted(more_examples_partial[i]),
                false,
                "Should not be blacklisted after removing batch"
            );
        }
        blacklistPolicy.removeFromBlacklist(more_examples_full);
        for (uint256 i = 0; i < more_examples_full.length; i++) {
            assertEq(
                blacklistPolicy.isBlacklisted(more_examples_full[i]),
                false,
                "Should not be blacklisted after removing batch"
            );
        }
        // Check Authorization functions
        require(
            blacklistPolicy.isBlacklisted(example_on_both_lists),
            "Assert before testing validateSwapAuthorization: Should be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            blacklistPolicy.validateSwapAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            false,
            "Blacklisted Swap should not be authorized"
        );
        require(
            !blacklistPolicy.isBlacklisted(example_not_on_any_list),
            "Assert before testing validateSwapAuthorization: Should not be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            blacklistPolicy.validateSwapAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.SwapParams({
                    zeroForOne: true,
                    amountSpecified: 0.0001 ether,
                    sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
                })
            ),
            true,
            "Not blacklisted Swap should be authorized"
        );
        require(
            blacklistPolicy.isBlacklisted(example_on_both_lists),
            "Assert before testing validateAddLiquidityAuthorization: Should be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            blacklistPolicy.validateAddLiquidityAuthorization(
                example_on_both_lists,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            false,
            "Blacklisted AddLiquidity should not be authorized"
        );
        require(
            !blacklistPolicy.isBlacklisted(example_not_on_any_list),
            "Assert before testing validateAddLiquidityAuthorization: Should not be blacklisted"
        );
        vm.prank(randomAddress); // Assure that function can be call from arbitrary address
        assertEq(
            blacklistPolicy.validateAddLiquidityAuthorization(
                example_not_on_any_list,
                key,
                IPoolManager.ModifyLiquidityParams({
                    tickLower: -60,
                    tickUpper: 60,
                    liquidityDelta: 100 ether,
                    salt: bytes32(0)
                })
            ),
            true,
            "Not blacklisted AddLiquidity should be authorized"
        );
    }

    function test_WhitelistPolicyHook() public {
        // Set-up Pool with WhitelistHook

        console.log("Pool initialized with WhitelistHook");
        address addressThis = address(this);
        require(!whitelistPolicy.isWhitelisted(addressThis), "addressThis intially not whitelisted");

        // set up addLiquidity paramters and try adding liquidity
        bytes memory hookData = whitelistPolicy.hookDataFromMsgSender(addressThis);
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -6000,
            tickUpper: 6000,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });
        console.log("Try adding liquidity through an non authorized address:", addressThis);
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(poolKey_WhitelistPolicy, modifyLiquidityParams, hookData);
        console.log("AddLiquidity was blocked as expected");

        // Add addressThis to whitelist
        whitelistPolicy.addToWhitelist(addressThis); // aadressThis is owner of the policy contracts and can change whitelist
        require(whitelistPolicy.isWhitelisted(addressThis), "addressThis should be whitelisted now");
        // Try adding liquidity again
        console.log("Try adding liquidity through an authorized address:", addressThis);
        uint256 balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        modifyLiquidityRouter.modifyLiquidity(poolKey_WhitelistPolicy, modifyLiquidityParams, hookData);
        uint256 balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("AddLiquidity: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("AddLiquidity: Balance of token1 decreased by: %d", balanceToken1Before - balanceToken1After);
        require(balanceToken0Before - balanceToken0After > 0, "Balance of token0 should have decreased");
        require(balanceToken1Before - balanceToken1After > 0, "Balance of token1 should have decreased");
        console.log("AddLiquidity successful");

        // set up swap paramters and try swapping
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        console.log("Try swapping through an authorized address:", addressThis);
        require(whitelistPolicy.isWhitelisted(addressThis), "addressThis should be whitelisted");
        balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        swapRouter.swap(poolKey_WhitelistPolicy, swapParams, testSettings, hookData);
        balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("Swap: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("Swap: Balance of token1 increased by: %d", balanceToken1After - balanceToken1Before);
        require(balanceToken0Before - balanceToken0After > 0, "Balance of token0 should have decreased");
        require(balanceToken1After - balanceToken1Before > 0, "Balance of token1 should have increased");
        console.log("Swap successful");

        // Remove addressThis from whitelist
        whitelistPolicy.removeFromWhitelist(addressThis);
        require(!whitelistPolicy.isWhitelisted(addressThis), "addressThis should not be whitelisted now");
        // Try swapping again
        console.log("Try swapping through an non authorized address:", addressThis);
        vm.expectRevert();
        swapRouter.swap(poolKey_WhitelistPolicy, swapParams, testSettings, hookData);
        console.log("Swap was blocked as expected");
    }

    function test_BlacklistPolicyHook() public {
        // Set-up Pool with BlacklistHook
        console.log("Testing BlacklistPolicyHook");

        address addressThis = address(this);
        require(!blacklistPolicy.isBlacklisted(addressThis), "addressThis intially not blacklisted");

        // set up addLiquidity paramters and try adding liquidity
        bytes memory hookData = whitelistPolicy.hookDataFromMsgSender(addressThis);
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -6000,
            tickUpper: 6000,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });
        console.log("Try adding liquidity through an authorized address:", addressThis);
        uint256 balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        modifyLiquidityRouter.modifyLiquidity(poolKey_BlacklistPolicy, modifyLiquidityParams, hookData);
        uint256 balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("AddLiquidity: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("AddLiquidity: Balance of token1 decreased by: %d", balanceToken1Before - balanceToken1After);
        console.log("AddLiquidity successful");

        // Add addressThis to blacklist
        blacklistPolicy.addToBlacklist(addressThis); // addressThis is owner of the policy contracts and can change blacklist
        require(blacklistPolicy.isBlacklisted(addressThis), "addressThis should be blacklisted now");
        // Try adding liquidity again
        console.log("Try adding liquidity through a blacklisted address:", addressThis);
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(poolKey_BlacklistPolicy, modifyLiquidityParams, hookData);
        console.log("AddLiquidity was blocked as expected");

        // set up swap paramters and try swapping
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        console.log("Try swapping through a non authorized address:", addressThis);
        vm.expectRevert();
        swapRouter.swap(key, swapParams, testSettings, hookData);
        console.log("Swap was blocked as expected");

        // Remove addressThis from blacklist
        blacklistPolicy.removeFromBlacklist(addressThis); // addressThis is owner of the policy contracts and can change blacklist
        require(!blacklistPolicy.isBlacklisted(addressThis), "addressThis should not be blacklisted now");
        // Try swapping again
        console.log("Try swapping through a not blacklisted address:", addressThis);
        balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        swapRouter.swap(poolKey_BlacklistPolicy, swapParams, testSettings, hookData);
        balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("Swap: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("Swap: Balance of token1 increased by: %d", balanceToken1After - balanceToken1Before);
        require(balanceToken0Before - balanceToken0After > 0, "Balance of token0 should have decreased");
        require(balanceToken1After - balanceToken1Before > 0, "Balance of token1 should have increased");
        console.log("Swap was was successfully executed");
    }

    function test_BlackWhitelistPolicyHook() public {
        // Set-up Pool with BlackWhitelistHook
        console.log("Testing BlackWhitelistPolicyHook");

        address addressThis = address(this);
        require(!policy.isBlacklisted(addressThis), "addressThis not intially blacklisted");
        require(!policy.isWhitelisted(addressThis), "addressThis not intially whitelisted");

        // set up addLiquidity paramters and try adding liquidity
        bytes memory hookData = policy.hookDataFromMsgSender(addressThis);
        IPoolManager.ModifyLiquidityParams memory modifyLiquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: -6000,
            tickUpper: 6000,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });
        console.log("Try adding liquidity through a neither blacklisted nor whitelisted address:", addressThis);
        uint256 balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        modifyLiquidityRouter.modifyLiquidity(poolKey_BlackWhitelistPolicy, modifyLiquidityParams, hookData);
        uint256 balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        uint256 balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("AddLiquidity: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("AddLiquidity: Balance of token1 decreased by: %d", balanceToken1Before - balanceToken1After);
        require(balanceToken0Before - balanceToken0After > 0, "Balance of token0 should have decreased");
        require(balanceToken1Before - balanceToken1After > 0, "Balance of token1 should have decreased");
        console.log("AddLiquidity successful as expected");

        // Add addressThis to blacklist
        policy.addToBlacklist(addressThis); // addressThis is owner of the policy contracts and can change blacklist
        require(policy.isBlacklisted(addressThis), "addressThis should be blacklisted now");
        // Try adding liquidity again
        console.log("Try adding liquidity through a blacklisted address:", addressThis);
        vm.expectRevert();
        modifyLiquidityRouter.modifyLiquidity(poolKey_BlackWhitelistPolicy, modifyLiquidityParams, hookData);
        console.log("AddLiquidity was blocked as expected");

        // Add addressThis to whitelist
        policy.addToWhitelist(addressThis); // addressThis is owner of the policy contracts and can change whitelist
        require(policy.isWhitelisted(addressThis), "addressThis should be whitelisted now");
        // Try swapping
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});
        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: 0.0001 ether,
            sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
        });
        console.log("Try swapping through a whitelisted address:", addressThis);
        require(policy.isWhitelisted(addressThis), "addressThis should be whitelisted");
        balanceToken0Before = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1Before = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        swapRouter.swap(poolKey_BlackWhitelistPolicy, swapParams, testSettings, hookData);
        balanceToken0After = MockERC20(Currency.unwrap(currency0)).balanceOf(addressThis);
        balanceToken1After = MockERC20(Currency.unwrap(currency1)).balanceOf(addressThis);
        console.log("Swap: Balance of token0 decreased by: %d", balanceToken0Before - balanceToken0After);
        console.log("Swap: Balance of token1 increased by: %d", balanceToken1After - balanceToken1Before);
        require(balanceToken0Before - balanceToken0After > 0, "Balance of token0 should have decreased");
        require(balanceToken1After - balanceToken1Before > 0, "Balance of token1 should have increased");
        console.log("Swap was successfully executed");

        // Remove addressThis to whitelist
        policy.removeFromWhitelist(addressThis); // addressThis is owner of the policy contracts and can change whitelist
        require(!policy.isWhitelisted(addressThis), "addressThis should not be whitelisted now");
        // Try swapping again
        console.log("Try swapping through a not whitelisted but blacklisted address:", addressThis);
        vm.expectRevert();
        swapRouter.swap(poolKey_BlackWhitelistPolicy, swapParams, testSettings, hookData);
        console.log("Swap was blocked as expected");
    }
}
