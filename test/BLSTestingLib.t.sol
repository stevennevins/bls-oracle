// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Test, console2 as console} from "../lib/forge-std/src/Test.sol";
import {BLSWrapper} from "./utils/BLSWrapper.sol";
import {BLSTestingLib, BLSWallet} from "../contracts/BLSTestingLib.sol";

contract BLSTestingLibTest is Test {
    string constant DOMAIN = "default-domain";
    string constant MESSAGE = "default-message";
    BLSWrapper public bls;

    function setUp() public {
        bls = new BLSWrapper();
    }

    function test_getPublicKey() public {
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-seed");

        assertNotEq(wallet.publicKey[0], 0);
    }

    function test_hashToPointEquivalence() public {
        string memory domain = "test-domain";
        string memory message = "test-message";

        uint256[2] memory messagePointLib = BLSTestingLib.hashToPoint(domain, message);
        uint256[2] memory messagePointWrapper = bls.hashToPoint(domain, message);

        assertEq(messagePointLib[0], messagePointWrapper[0], "X-coordinates do not match");
        assertEq(messagePointLib[1], messagePointWrapper[1], "Y-coordinates do not match");
    }

    function test_hashToPointBytes32Equivalence() public {
        string memory domain = "test-domain";
        bytes32 message = bytes32(uint256(0x1234567890));

        uint256[2] memory messagePointLib = BLSTestingLib.hashToPoint(domain, message);
        uint256[2] memory messagePointWrapper = bls.hashToPoint(domain, message);

        assertEq(messagePointLib[0], messagePointWrapper[0], "X-coordinates do not match");
        assertEq(messagePointLib[1], messagePointWrapper[1], "Y-coordinates do not match");
    }

    function test_getAggPublicKey() public {
        uint256[] memory privateKeys = new uint256[](3);
        privateKeys[0] = BLSTestingLib.createWallet("wallet-1").privateKey;
        privateKeys[1] = BLSTestingLib.createWallet("wallet-2").privateKey;
        privateKeys[2] = BLSTestingLib.createWallet("wallet-3").privateKey;

        uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);

        assertNotEq(aggregatedPubKey[0], 0);
    }

    function test_signAndVerify() public {
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, MESSAGE);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(DOMAIN, MESSAGE);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Pairing check failed");
    }

    function test_signAndVerifyAggregated() public {
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
        BLSWallet memory wallet = BLSTestingLib.createWallet("test-wallet");

        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, DOMAIN, string("message-1"));
        uint256[2] memory messagePoint = bls.hashToPoint(DOMAIN, string("message-2"));

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Pairing should fail for mismatched message");
    }

    function test_incorrectPublicKeyVerification() public {
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
        string calldata seed
    ) public {
        vm.assume(bytes(seed).length > 0);

        BLSWallet memory wallet = BLSTestingLib.createWallet(seed);

        bool isValidPubKey = bls.isValidPublicKey(wallet.publicKey);
        bool isOnCurve = bls.isOnCurveG2(wallet.publicKey);

        assertTrue(isValidPubKey, "Public key should be valid");
        assertTrue(isOnCurve, "Public key should be on curve G2");
    }

    function testFuzz_aggregatedPublicKeyOnCurve(
        string[] calldata seeds
    ) public {
        vm.assume(seeds.length >= 2 && seeds.length <= 10);
        uint256[] memory privateKeys = new uint256[](seeds.length);

        for (uint256 i = 0; i < seeds.length; i++) {
            vm.assume(bytes(seeds[i]).length > 0);
            privateKeys[i] = BLSTestingLib.createWallet(seeds[i]).privateKey;
        }

        uint256[4] memory aggPubKey = BLSTestingLib.getPublicKey(privateKeys);

        bool isValidPubKey = bls.isValidPublicKey(aggPubKey);
        bool isOnCurve = bls.isOnCurveG2(aggPubKey);

        assertTrue(isValidPubKey, "Aggregated public key should be valid");
        assertTrue(isOnCurve, "Aggregated public key should be on curve G2");
    }

    function testFuzz_signAndVerifySingle(
        string calldata seed
    ) public {
        vm.assume(bytes(seed).length > 0);
        string memory domain = "domain-message";
        string memory message = "message";

        BLSWallet memory wallet = BLSTestingLib.createWallet(seed);
        uint256[2] memory sig = BLSTestingLib.sign(wallet.privateKey, domain, message);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(sig, wallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertTrue(pairingSuccess, "Sig verification failed");
    }

    function testFuzz_signAndVerifySingle_invalidSig(
        string calldata validSeed,
        string calldata invalidSeed
    ) public {
        string memory domain = "domain-message";
        string memory message = "message";
        vm.assume(bytes(validSeed).length > 0);
        vm.assume(bytes(invalidSeed).length > 0);
        vm.assume(keccak256(bytes(validSeed)) != keccak256(bytes(invalidSeed)));

        BLSWallet memory validWallet = BLSTestingLib.createWallet(validSeed);
        BLSWallet memory invalidWallet = BLSTestingLib.createWallet(invalidSeed);

        uint256[2] memory invalidSig = BLSTestingLib.sign(invalidWallet.privateKey, domain, message);
        uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);

        (bool pairingSuccess, bool callSuccess) =
            bls.verifySingle(invalidSig, validWallet.publicKey, messagePoint);

        assertTrue(callSuccess, "Precompile call failed");
        assertFalse(pairingSuccess, "Invalid sig should not verify");
    }

    function test_verifyMultipleWithAggregates() public {
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
