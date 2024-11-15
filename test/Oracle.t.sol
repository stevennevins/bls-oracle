// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test, Vm, console2 as console} from "forge-std/src/Test.sol";
import {Registry} from "../contracts/Registry.sol";
import {Oracle} from "../contracts/Oracle.sol";
import {BLSWallet, BLSTestingLib} from "./utils/BLSTestingLib.sol";
import {BLS} from "./utils/BLS.sol";

contract OracleTest is Test {
    struct Operator {
        Vm.Wallet wallet;
        BLSWallet blsWallet;
    }

    Registry public registry;
    Oracle public oracle;
    Vm.Wallet public owner;
    uint256 constant NUM_OPERATORS = 10;
    Operator[NUM_OPERATORS] public operators;

    function setUp() public {
        owner = vm.createWallet("owner");
        registry = new Registry(owner.addr);
        oracle = new Oracle(address(registry));

        // Create wallets for each operator
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            string memory label = vm.toString(i);
            operators[i].wallet = vm.createWallet(label);
            operators[i].blsWallet = BLSTestingLib.createWallet(label);
        }

        // Register all operators
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            vm.startPrank(operators[i].wallet.addr);

            bytes32 messageHash = registry.calculateRegistrationHash(
                operators[i].wallet.addr, operators[i].blsWallet.publicKeyG1
            );

            uint256[2] memory signature = BLSTestingLib.sign(
                operators[i].blsWallet.privateKey, registry.DOMAIN(), messageHash
            );

            Registry.Proof memory proof =
                Registry.Proof({signature: signature, pubkeyG2: operators[i].blsWallet.publicKey});

            registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();
        }
    }

    function test_Setup() public {
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            uint8 operatorId = registry.operatorIds(operators[i].wallet.addr);
            assertTrue(registry.isRegistered(operatorId), "Operator not registered");
        }
    }

    function test_Bitmap() public {
        // Test empty bitmap (no signers)
        uint256 emptyBitmap = 0;
        uint8[] memory nonSigners = oracle.bitmapToNonSignerIds(emptyBitmap);
        assertEq(nonSigners.length, NUM_OPERATORS, "Empty bitmap should return all ids"); // TODO: Feels weird for this to be the operator cap

        // Test bitmap with some signers
        uint256 bitmap = 0;
        bitmap |= (1 << 1); // Set bit 1
        bitmap |= (1 << 3); // Set bit 3
        bitmap |= (1 << 5); // Set bit 5
        nonSigners = oracle.bitmapToNonSignerIds(bitmap);

        // Should return all ids except 1,3,5
        assertEq(nonSigners.length, NUM_OPERATORS-3, "Should return all non-signing ids");
        /// TODO: This will change when i check the nextOperatorId in the bitmap func

        // Test bitmap with all signers
        bitmap = type(uint256).max;
        nonSigners = oracle.bitmapToNonSignerIds(bitmap);
        assertEq(nonSigners.length, 0, "Full bitmap should return empty array");
    }

    function test_checkNonSignerBitmap() public {
        uint256 bitmap = 0;
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            uint8 operatorId = registry.operatorIds(operators[i].wallet.addr);
            bitmap |= (1 << operatorId);
        }

        uint8[] memory nonSigners = oracle.bitmapToNonSignerIds(bitmap);
        assertEq(nonSigners.length, 0, "Should have no non-signers");
        /// TODO: hack
    }

    function test_AggregateSignedMessage() public {
        // Create test message
        bytes memory message = "test message";
        bytes32 messageHash = oracle.calculateMessageHash(message);
        bytes memory domain = bytes(oracle.DOMAIN());

        // Get message point for BLS signature
        uint256[2] memory messagePoint = BLS.hashToPoint(domain, bytes.concat(messageHash));

        // Create aggregate signature from all operators
        uint256[2] memory aggSignature;
        uint256[4] memory aggPubkeyG2;

        // Get bitmap from registry
        uint256 bitmap = registry.operatorBitmap();

        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            uint256[2] memory signature =
                BLSTestingLib.sign(operators[i].blsWallet.privateKey, oracle.DOMAIN(), messageHash);
            uint256[4] memory pubkeyG2 = operators[i].blsWallet.publicKey;

            if (i == 0) {
                aggSignature = signature;
                aggPubkeyG2 = pubkeyG2;
            } else {
                aggSignature = BLS.aggregate(aggSignature, signature);
                aggPubkeyG2 = BLS.aggregate(aggPubkeyG2, pubkeyG2);
            }
        }

        // Create signature data struct
        Oracle.AggregateSignatureData memory sigData = Oracle.AggregateSignatureData({
            aggSignatureG1: aggSignature,
            aggPubkeyG2: aggPubkeyG2,
            signerBitmap: bitmap
        });

        // Record message with aggregate signature
        oracle.record(message, sigData);

        // // Try with invalid signature - should revert
        // sigData.aggSignatureG1[0] = 123456789; // Corrupt signature
        // vm.expectRevert(Oracle.InvalidSignature.selector);
        // oracle.record(message, sigData);
    }

    function test_AggregateSignedMessageWithTamperedSignature() public {
        // Create test message
        bytes memory message = "test message";
        bytes32 messageHash = oracle.calculateMessageHash(message);
        bytes memory domain = bytes(oracle.DOMAIN());

        // Get message point for BLS signature
        uint256[2] memory messagePoint = BLS.hashToPoint(domain, bytes.concat(messageHash));

        // Create aggregate signature from all operators
        uint256[2] memory aggSignature;
        uint256[4] memory aggPubkeyG2;

        // Get bitmap from registry
        uint256 bitmap = registry.operatorBitmap();

        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            uint256[2] memory signature =
                BLSTestingLib.sign(operators[i].blsWallet.privateKey, oracle.DOMAIN(), messageHash);
            uint256[4] memory pubkeyG2 = operators[i].blsWallet.publicKey;

            if (i == 0) {
                aggSignature = signature;
                aggPubkeyG2 = pubkeyG2;
            } else {
                aggSignature = BLS.aggregate(aggSignature, signature);
                aggPubkeyG2 = BLS.aggregate(aggPubkeyG2, pubkeyG2);
            }
        }

        // Tamper with the signature
        aggSignature[0] = 123_456_789;
        aggSignature[1] = 987_654_321;

        // Create signature data struct with tampered signature
        Oracle.AggregateSignatureData memory sigData = Oracle.AggregateSignatureData({
            aggSignatureG1: aggSignature,
            aggPubkeyG2: aggPubkeyG2,
            signerBitmap: bitmap
        });

        // Expect revert when recording message with tampered signature
        vm.expectRevert(Oracle.InvalidSignature.selector);
        oracle.record(message, sigData);
    }

    function test_AggregateSignedMessageWithNonSigners() public {
        // Create test message
        bytes memory message = "test message";
        bytes32 messageHash = oracle.calculateMessageHash(message);
        bytes memory domain = bytes(oracle.DOMAIN());

        // Get message point for BLS signature
        uint256[2] memory messagePoint = BLS.hashToPoint(domain, bytes.concat(messageHash));

        // Create aggregate signature from all operators except last one
        uint256[2] memory aggSignature;
        uint256[4] memory aggPubkeyG2;

        // Get bitmap from registry and remove last operator
        uint256 bitmap = registry.operatorBitmap();
        uint256 lastOperatorBit = 1 << (NUM_OPERATORS - 1);
        logBitmap(bitmap);
        bitmap &= ~lastOperatorBit; // Remove last operator from bitmap
        logBitmap(bitmap);

        // Verify bitmap is updated correctly
        assertEq(bitmap & lastOperatorBit, 0, "Last operator bit should be unset");

        // Get non-signer IDs and verify
        uint8[] memory nonSignerIds = oracle.bitmapToNonSignerIds(bitmap);
        assertEq(nonSignerIds.length, 1, "Should have exactly one non-signer");
        assertEq(nonSignerIds[0], NUM_OPERATORS - 1, "Non-signer should be last operator");

        // Get non-signer APK from registry
        uint256[2] memory nonSignerApk = registry.getOperatorsApk(nonSignerIds);
        uint256[2] memory totalApk = registry.apk();

        // Verify non-signer APK is correct
        assertEq(
            nonSignerApk[0],
            operators[NUM_OPERATORS - 1].blsWallet.publicKeyG1[0],
            "Non-signer APK mismatch"
        );
        assertEq(
            nonSignerApk[1],
            operators[NUM_OPERATORS - 1].blsWallet.publicKeyG1[1],
            "Non-signer APK mismatch"
        );

        for (uint256 i = 0; i < NUM_OPERATORS - 1; i++) {
            // Skip last operator
            uint256[2] memory signature =
                BLSTestingLib.sign(operators[i].blsWallet.privateKey, oracle.DOMAIN(), messageHash);
            uint256[4] memory pubkeyG2 = operators[i].blsWallet.publicKey;

            if (i == 0) {
                aggSignature = signature;
                aggPubkeyG2 = pubkeyG2;
            } else {
                aggSignature = BLS.aggregate(aggSignature, signature);
                aggPubkeyG2 = BLS.aggregate(aggPubkeyG2, pubkeyG2);
            }
        }

        // Create signature data struct
        Oracle.AggregateSignatureData memory sigData = Oracle.AggregateSignatureData({
            aggSignatureG1: aggSignature,
            aggPubkeyG2: aggPubkeyG2,
            signerBitmap: bitmap
        });

        // Verify signature components
        assertTrue(BLS.isValidSignature(aggSignature), "Invalid aggregate signature");

        // Should succeed since we properly excluded non-signer
        oracle.record(message, sigData);
    }

    function logBitmap(
        uint256 bitmap
    ) internal pure {
        string memory bits = "";

        for (uint256 i = 0; i < 256; i++) {
            if ((bitmap >> i) & 1 == 1) {
                bits = string.concat("1", bits);
            } else {
                bits = string.concat("0", bits);
            }
        }
        console.log("Bitmap:");
        console.log("========================================");
        console.log(bits);
        console.log("========================================");
    }
}
