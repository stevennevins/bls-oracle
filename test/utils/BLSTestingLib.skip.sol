// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test, console2 as console} from "../../lib/forge-std/src/Test.sol";
import {BLS} from "./BLS.sol";
import {BLSWrapper} from "./BLSWrapper.sol";
import {BLSTestingLib, BLSWallet} from "./BLSTestingLib.sol";

// @skip-on-test
contract BLSTestingLibTest is Test {
    string constant DOMAIN = "default-domain";
    string constant MESSAGE = "default-message";
    BLSWrapper public bls;

    function setUp() public {
        bls = new BLSWrapper();
    }

    function test_aggregateG1() public {
        vm.skip(true);
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        string memory message1 = "message-1";
        string memory message2 = "message-2";

        uint256[2] memory sig1 = BLSTestingLib.sign(wallet1.privateKey, DOMAIN, message1);
        uint256[2] memory sig2 = BLSTestingLib.sign(wallet2.privateKey, DOMAIN, message2);

        uint256[2] memory aggSig = bls.aggregate(sig1, sig2);

        assertTrue(bls.isOnCurveG1(aggSig), "Aggregated signature should be on G1 curve");
        assertTrue(bls.isValidSignature(aggSig), "Aggregated signature should be valid");
    }

    function test_aggregateG2() public {
        vm.skip(true);
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");

        uint256[4] memory aggPubKey = bls.aggregateG2(wallet1.publicKey, wallet2.publicKey);

        assertTrue(bls.isOnCurveG2(aggPubKey), "Aggregated public key should be on G2 curve");
        assertTrue(bls.isValidPublicKey(aggPubKey), "Aggregated public key should be valid");
    }

    function test_subG1() public {
        vm.skip(true);
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        string memory message1 = "message-1";
        string memory message2 = "message-2";

        uint256[2] memory sig1 = BLSTestingLib.sign(wallet1.privateKey, DOMAIN, message1);
        uint256[2] memory sig2 = BLSTestingLib.sign(wallet2.privateKey, DOMAIN, message2);

        uint256[2] memory aggSig = bls.aggregate(sig1, sig2);
        uint256[2] memory subSig = bls.subG1(aggSig, sig1);

        assertTrue(bls.isOnCurveG1(subSig), "Subtracted signature should be on G1 curve");
        assertTrue(bls.isValidSignature(subSig), "Subtracted signature should be valid");
        assertEq(subSig[0], sig2[0], "Subtracted signature should equal sig2 x-coordinate");
        assertEq(subSig[1], sig2[1], "Subtracted signature should equal sig2 y-coordinate");
    }

    function test_subG2() public {
        vm.skip(true);
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");

        uint256[4] memory aggPubKey = bls.aggregateG2(wallet1.publicKey, wallet2.publicKey);
        uint256[4] memory subPubKey = bls.subG2(aggPubKey, wallet1.publicKey);

        assertTrue(bls.isOnCurveG2(subPubKey), "Subtracted public key should be on G2 curve");
        assertTrue(bls.isValidPublicKey(subPubKey), "Subtracted public key should be valid");
        assertEq(
            subPubKey[0], wallet2.publicKey[0], "Subtracted pubkey should equal wallet2 pubkey x0"
        );
        assertEq(
            subPubKey[1], wallet2.publicKey[1], "Subtracted pubkey should equal wallet2 pubkey x1"
        );
        assertEq(
            subPubKey[2], wallet2.publicKey[2], "Subtracted pubkey should equal wallet2 pubkey y0"
        );
        assertEq(
            subPubKey[3], wallet2.publicKey[3], "Subtracted pubkey should equal wallet2 pubkey y1"
        );
    }

    function test_getPublicKey() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-seed");

        assertNotEq(wallet.publicKey[0], 0);
    }

    function test_hashToPointEquivalence() public {
        vm.skip(true);
        string memory domain = "test-domain";
        string memory message = "test-message";

        uint256[2] memory messagePointLib = BLSTestingLib.hashToPoint(domain, message);
        uint256[2] memory messagePointWrapper = bls.hashToPoint(domain, message);

        assertEq(messagePointLib[0], messagePointWrapper[0], "X-coordinates do not match");
        assertEq(messagePointLib[1], messagePointWrapper[1], "Y-coordinates do not match");
    }

    function test_hashToPointBytes32Equivalence() public {
        vm.skip(true);
        string memory domain = "test-domain";
        bytes32 message = bytes32(uint256(0x1234567890));

        uint256[2] memory messagePointLib = BLSTestingLib.hashToPoint(domain, message);
        uint256[2] memory messagePointWrapper = bls.hashToPoint(domain, message);

        assertEq(messagePointLib[0], messagePointWrapper[0], "X-coordinates do not match");
        assertEq(messagePointLib[1], messagePointWrapper[1], "Y-coordinates do not match");
    }

    function test_getAggPublicKey() public {
        vm.skip(true);
        uint256[] memory privateKeys = new uint256[](3);
        privateKeys[0] = BLSTestingLib.createWallet("wallet-1").privateKey;
        privateKeys[1] = BLSTestingLib.createWallet("wallet-2").privateKey;
        privateKeys[2] = BLSTestingLib.createWallet("wallet-3").privateKey;

        uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);

        assertNotEq(aggregatedPubKey[0], 0);
    }

    function test_signAndVerify() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, MESSAGE);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(DOMAIN, MESSAGE);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Pairing check failed");
    }

    function test_signAndVerifyAggregated() public {
        vm.skip(true);
        uint256[] memory privateKeys = new uint256[](2);
        privateKeys[0] = BLSTestingLib.createWallet("wallet-1").privateKey;
        privateKeys[1] = BLSTestingLib.createWallet("wallet-2").privateKey;

        uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);
        uint256[2] memory aggregatedSig = BLSTestingLib.sign(privateKeys, DOMAIN, MESSAGE);
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, MESSAGE);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(aggregatedSig, aggregatedPubKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Pairing check failed");
    }

    function test_signHashAndVerify() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");
        bytes32 message = bytes32(uint256(0x1234567890));

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, message);
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Pairing check failed");
    }

    function test_aggSignHashAndVerifyAggregated() public {
        vm.skip(true);
        uint256[] memory privateKeys = new uint256[](2);
        privateKeys[0] = BLSTestingLib.createWallet("wallet-1").privateKey;
        privateKeys[1] = BLSTestingLib.createWallet("wallet-2").privateKey;
        bytes32 message = bytes32(uint256(0x1234567890));

        uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);
        uint256[2] memory aggregatedSig = BLSTestingLib.sign(privateKeys, DOMAIN, message);
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(aggregatedSig, aggregatedPubKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Pairing check failed");
    }

    function test_invalidSigVerification() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("valid-wallet");
        BLSWallet memory invalidWallet = BLSTestingLib.createWallet("invalid-wallet");

        uint256[2] memory invalidSig = BLSTestingLib.sign(invalidWallet.privateKey, DOMAIN, MESSAGE);
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, MESSAGE);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(invalidSig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Pairing should fail for invalid sig");
    }

    function test_mismatchedMessageVerification() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, string("message-1"));
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, string("message-2"));

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Pairing should fail for mismatched message");
    }

    function test_incorrectPublicKeyVerification() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("valid-wallet");
        BLSWallet memory incorrectWallet = BLSTestingLib.createWallet("incorrect-wallet");

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, MESSAGE);
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, MESSAGE);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, incorrectWallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Pairing should fail for incorrect public key");
    }

    function test_batchVerification() public {
        vm.skip(true);
        BLSWallet[] memory wallets = new BLSWallet[](3);
        wallets[0] = BLSTestingLib.createWallet("wallet-1");
        wallets[1] = BLSTestingLib.createWallet("wallet-2");
        wallets[2] = BLSTestingLib.createWallet("wallet-3");

        string[] memory messages = new string[](3);
        messages[0] = "message-1";
        messages[1] = "message-2";
        messages[2] = "message-3";

        uint256[2][] memory sigs = new uint256[2][](3);
        uint256[4][] memory pubKeys = new uint256[4][](3);
        uint256[2][] memory messagePoints = new uint256[2][](3);

        for (uint256 i = 0; i < wallets.length; i++) {
            pubKeys[i] = wallets[i].publicKey;
            sigs[i] = BLSTestingLib.sign(wallets[i].privateKey, DOMAIN, messages[i]);
            messagePoints[i] = bls.hashToPoint(DOMAIN, messages[i]);
        }

        (bool pairingSuccess, bool callSuccess) = bls.verifyBatch(sigs, pubKeys, messagePoints);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Batch pairing check failed");
    }

    function test_domainSeparation() public {
        vm.skip(true);
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");
        string memory domain1 = "domain-1";
        string memory domain2 = "domain-2";
        string memory message = "test-message";

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, domain1, message);
        uint256[2] memory messagePoint = bls.hashToPoint(domain2, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Pairing should fail across different domains");
    }

    function test_G1Orientation() public {
        vm.skip(true);
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");

        uint256[4] memory aggPubKeyG2 = bls.aggregateG2(wallet1.publicKey, wallet2.publicKey);
        uint256[2] memory aggPubkeyG1 = bls.aggregate(wallet1.publicKeyG1, wallet2.publicKeyG1);

        (bool pairingSuccess, bool callSuccess) = bls.verifyApk(aggPubKeyG2, aggPubkeyG1);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Aggregated public key verification failed");

        // uint256[2] memory wrongPubkeyG1 = wallet1.publicKeyG1;
        // (pairingSuccess, callSuccess) = bls.verifyApk(aggPubKeyG2, wrongPubkeyG1);

        // assertTrue(callSuccess, "Precompile call failed");
        // assertFalse(pairingSuccess, "Verification should fail with incorrect G1 pubkey");
    }

    function test_SubtractAndVerifySingle() public {
        vm.skip(true);
        // Create two wallets
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        BLSWallet memory wallet3 = BLSTestingLib.createWallet("wallet-3");

        // Aggregate both public keys in G1 (this would be stored on-chain)
        uint256[2] memory aggPubkeyG1 = bls.aggregate(wallet1.publicKeyG1, wallet2.publicKeyG1);
        aggPubkeyG1 = bls.aggregate(aggPubkeyG1, wallet3.publicKeyG1);

        // Create a message and get wallet2 to sign it
        string memory domain = "test-domain";
        bytes32 message = keccak256("test message");
        uint256[2] memory messagePoint = bls.hashToPoint(domain, message);
        uint256[2] memory signature2 = BLSTestingLib.sign(wallet2.privateKey, domain, message);
        uint256[2] memory signature3 = BLSTestingLib.sign(wallet3.privateKey, domain, message);

        uint256[2] memory aggSignatureG1 = bls.aggregate(signature2, signature3);

        // Subtract wallet1's public key from the aggregate
        uint256[2] memory remainingPubkeyG1 = bls.subG1(aggPubkeyG1, wallet1.publicKeyG1);

        // Get wallet2's public key in G2 for verification
        uint256[4] memory pubKeyG2_2 = wallet2.publicKey;
        uint256[4] memory pubKeyG2_3 = wallet3.publicKey;

        uint256[4] memory aggPubkeyG2 = bls.aggregateG2(pubKeyG2_2, pubKeyG2_3);

        // Verify that remainingPubkeyG1 matches wallet2's public key
        (bool pairingSuccess, bool callSuccess) = bls.verifyApk(aggPubkeyG2, remainingPubkeyG1);
        assertTrue(callSuccess, "APK verification call failed");
        assertTrue(pairingSuccess, "APK verification failed");

        // Verify the signature
        (pairingSuccess, callSuccess) = bls.verifySingle(aggSignatureG1, aggPubkeyG2, messagePoint);
        assertTrue(callSuccess, "Signature verification call failed");
        assertTrue(pairingSuccess, "Signature verification failed");
    }

    function test_SubtractAndVerifySingleBatch() public {
        vm.skip(true);
        // Create three wallets
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        BLSWallet memory wallet3 = BLSTestingLib.createWallet("wallet-3");

        // Aggregate public keys in G1 (this would be stored on-chain)
        uint256[2] memory aggPubkeyG1 = bls.aggregate(wallet1.publicKeyG1, wallet2.publicKeyG1);
        aggPubkeyG1 = bls.aggregate(aggPubkeyG1, wallet3.publicKeyG1);

        // Create a message and get wallet2 and wallet3 to sign it
        string memory domain = "test-domain";
        bytes32 message = keccak256("test message");
        uint256[2] memory messagePoint = bls.hashToPoint(domain, message);
        uint256[2] memory signature2 = BLSTestingLib.sign(wallet2.privateKey, domain, message);
        uint256[2] memory signature3 = BLSTestingLib.sign(wallet3.privateKey, domain, message);

        uint256[2] memory aggSignatureG1 = bls.aggregate(signature2, signature3);

        // Subtract wallet1's public key from the aggregate
        uint256[2] memory remainingPubkeyG1 = bls.subG1(aggPubkeyG1, wallet1.publicKeyG1);

        // Get wallet2 and wallet3's public keys in G2 for verification
        uint256[4] memory pubKeyG2_2 = wallet2.publicKey;
        uint256[4] memory pubKeyG2_3 = wallet3.publicKey;
        uint256[4] memory aggPubkeyG2 = bls.aggregateG2(pubKeyG2_2, pubKeyG2_3);

        // Prepare inputs for batch verification
        uint256[12] memory apkInput = bls.prepareApkInput(aggPubkeyG2, remainingPubkeyG1);
        uint256[12] memory sigInput =
            bls.prepareVerifyMessage(aggSignatureG1, aggPubkeyG2, messagePoint);

        // Combine inputs for batch verification
        uint256[] memory batchInput = new uint256[](24);
        for (uint256 i = 0; i < 12; i++) {
            batchInput[i] = apkInput[i];
            batchInput[i + 12] = sigInput[i];
        }

        // Verify both pairings in a single batch
        (bool pairingSuccess, bool callSuccess) = bls.verifyPairingBatch(batchInput, 2);
        assertTrue(callSuccess, "Batch verification call failed");
        assertTrue(pairingSuccess, "Batch verification failed");
    }

    function test_SubtractAndVerifyMultipleMessagesBatch() public {
        vm.skip(true);
        // // Create three wallets
        // BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        // BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        // BLSWallet memory wallet3 = BLSTestingLib.createWallet("wallet-3");

        // // Aggregate public keys in G1 (this would be stored on-chain)
        // uint256[2] memory aggPubkeyG1 = bls.aggregate(wallet1.publicKeyG1, wallet2.publicKeyG1);
        // aggPubkeyG1 = bls.aggregate(aggPubkeyG1, wallet3.publicKeyG1);

        // // Create two messages and get wallet2 and wallet3 to sign them
        // string memory domain = "test-domain";
        // bytes32 message1 = keccak256("test message 1");
        // bytes32 message2 = keccak256("test message 2");

        // uint256[2] memory messagePoint1 = bls.hashToPoint(domain, message1);
        // uint256[2] memory messagePoint2 = bls.hashToPoint(domain, message2);

        // // Get signatures from wallet2 and wallet3 for both messages
        // uint256[2] memory signature2_msg1 = BLSTestingLib.sign(wallet2.privateKey, domain, message1);
        // uint256[2] memory signature3_msg1 = BLSTestingLib.sign(wallet3.privateKey, domain, message1);
        // uint256[2] memory signature2_msg2 = BLSTestingLib.sign(wallet2.privateKey, domain, message2);
        // uint256[2] memory signature3_msg2 = BLSTestingLib.sign(wallet3.privateKey, domain, message2);

        // // Aggregate signatures for each message
        // uint256[2] memory aggSignatureG1_msg1 = bls.aggregate(signature2_msg1, signature3_msg1);
        // uint256[2] memory aggSignatureG1_msg2 = bls.aggregate(signature2_msg2, signature3_msg2);

        // // Aggregate both message signatures together
        // uint256[2] memory totalAggSignatureG1 = bls.aggregate(aggSignatureG1_msg1, aggSignatureG1_msg2);

        // // Subtract wallet1's public key from the aggregate
        // uint256[2] memory remainingPubkeyG1 = bls.subG1(aggPubkeyG1, wallet1.publicKeyG1);

        // // Get wallet2 and wallet3's public keys in G2 for verification
        // uint256[4] memory pubKeyG2_2 = wallet2.publicKey;
        // uint256[4] memory pubKeyG2_3 = wallet3.publicKey;
        // uint256[4] memory aggPubkeyG2 = bls.aggregateG2(pubKeyG2_2, pubKeyG2_3);

        // // Prepare inputs for batch verification
        // uint256[12] memory apkInput = bls.prepareApkInput(aggPubkeyG2, remainingPubkeyG1);
        // uint256[12] memory sigInput1 = bls.prepareVerifyMessage(totalAggSignatureG1, aggPubkeyG2, messagePoint1);
        // uint256[12] memory sigInput2 = bls.prepareVerifyMessage(totalAggSignatureG1, aggPubkeyG2, messagePoint2);

        // // Combine inputs for batch verification
        // uint256[] memory batchInput = new uint256[](36);
        // for (uint256 i = 0; i < 12; i++) {
        //     batchInput[i] = apkInput[i];
        //     batchInput[i + 12] = sigInput1[i];
        //     batchInput[i + 24] = sigInput2[i];
        // }

        // // Verify all pairings in a single batch
        // (bool pairingSuccess, bool callSuccess) = bls.verifyPairingBatch(batchInput, 3);
        // assertTrue(callSuccess, "Batch verification call failed");
        // assertTrue(pairingSuccess, "Batch verification failed");
    }

    function logPublicKey(
        uint256[4] memory pubKey
    ) internal pure {
        console.log("Public Key Components:");
        console.log("x0:", pubKey[0]);
        console.log("x1:", pubKey[1]);
        console.log("y0:", pubKey[2]);
        console.log("y1:", pubKey[3]);
    }

    function logSig(
        uint256[2] memory sig
    ) internal pure {
        console.log("Sig Components:");
        console.log("x:", sig[0]);
        console.log("y:", sig[1]);
    }

    function logPoint(string memory label, uint256[2] memory point) internal pure {
        console.log(string.concat(label, " Components:"));
        console.log("x:", point[0]);
        console.log("y:", point[1]);
    }

    function testFuzz_publicKeyGenerationAndCurveCheck(
        uint256 seed
    ) public {
        vm.skip(true);

        BLSWallet memory wallet = BLSTestingLib.createWallet(vm.toString(seed));

        bool isValidPubKey = bls.isValidPublicKey(wallet.publicKey);
        bool isOnCurve = bls.isOnCurveG2(wallet.publicKey);

        assertTrue(isValidPubKey, "Public key should be valid");
        assertTrue(isOnCurve, "Public key should be on curve G2");
    }

    function testFuzz_aggregatedPublicKeyOnCurve(
        uint256[] memory seeds
    ) public {
        vm.skip(true);
        vm.assume(seeds.length >= 2 && seeds.length <= 10);
        uint256[] memory privateKeys = new uint256[](seeds.length);

        for (uint256 i = 0; i < seeds.length; i++) {
            privateKeys[i] = BLSTestingLib.createWallet(vm.toString(seeds[i])).privateKey;
        }

        uint256[4] memory aggPubKey = BLSTestingLib.getPublicKey(privateKeys);

        bool isValidPubKey = bls.isValidPublicKey(aggPubKey);
        bool isOnCurve = bls.isOnCurveG2(aggPubKey);

        assertTrue(isValidPubKey, "Aggregated public key should be valid");
        assertTrue(isOnCurve, "Aggregated public key should be on curve G2");
    }

    function testFuzz_signAndVerifySingle(
        uint256 seed
    ) public {
        vm.skip(true);
        string memory domain = "domain-message";
        string memory message = "message";

        BLSWallet memory wallet = BLSTestingLib.createWallet(vm.toString(seed));
        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, domain, message);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Sig verification failed");
    }

    function testFuzz_signAndVerifySingle_invalidSig(
        uint256 validSeed,
        uint256 invalidSeed
    ) public {
        vm.skip(true);
        string memory domain = "domain-message";
        string memory message = "message";
        vm.assume(validSeed != invalidSeed);

        BLSWallet memory validWallet = BLSTestingLib.createWallet(vm.toString(validSeed));
        BLSWallet memory invalidWallet = BLSTestingLib.createWallet(vm.toString(invalidSeed));

        uint256[2] memory invalidSig = BLSTestingLib.sign(invalidWallet.privateKey, domain, message);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(invalidSig, validWallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Invalid sig should not verify");
    }

    function test_verifyMultipleWithAggregates() public {
        vm.skip(true);
        // Create 4 wallets - first 2 will be aggregated, last 2 individual
        BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
        BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2");
        BLSWallet memory wallet3 = BLSTestingLib.createWallet("wallet-3");
        BLSWallet memory wallet4 = BLSTestingLib.createWallet("wallet-4");

        string memory domain = "test-domain";
        string[] memory messages = new string[](3);
        messages[0] = "message-for-aggregate";
        messages[1] = "message-for-wallet3";
        messages[2] = "message-for-wallet4";

        uint256[] memory aggPrivateKeys = new uint256[](2);
        aggPrivateKeys[0] = wallet1.privateKey;
        aggPrivateKeys[1] = wallet2.privateKey;

        uint256[2][] memory signatures = new uint256[2][](3);
        uint256[4][] memory pubKeys = new uint256[4][](3);
        uint256[2][] memory messagePoints = new uint256[2][](3);

        signatures[0] = BLSTestingLib.sign(aggPrivateKeys, domain, messages[0]);
        pubKeys[0] = BLSTestingLib.getPublicKey(aggPrivateKeys);
        messagePoints[0] = BLSTestingLib.hashToPoint(domain, messages[0]);

        signatures[1] = BLSTestingLib.sign(wallet3.privateKey, domain, messages[1]);
        pubKeys[1] = wallet3.publicKey;
        messagePoints[1] = BLSTestingLib.hashToPoint(domain, messages[1]);

        signatures[2] = BLSTestingLib.sign(wallet4.privateKey, domain, messages[2]);
        pubKeys[2] = wallet4.publicKey;
        messagePoints[2] = BLSTestingLib.hashToPoint(domain, messages[2]);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifyBatch(signatures, pubKeys, messagePoints);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Batch verification failed");
    }
}
