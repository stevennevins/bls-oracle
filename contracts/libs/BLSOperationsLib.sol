// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {BLS} from "../../test/utils/BLS.sol";

library BLSOperations {
    struct Proof {
        uint256[2] signature;
        uint256[4] pubkeyG2;
    }

    function validateKey(
        address operator,
        uint256[2] memory pubkeyG1,
        Proof memory proof,
        bytes32 messageHash,
        string memory domain
    ) internal view returns (bool) {
        uint256[12] memory apkInput = BLS.prepareApkInput(proof.pubkeyG2, pubkeyG1);
        uint256[2] memory messagePoint = BLS.hashToPoint(bytes(domain), bytes.concat(messageHash));
        uint256[12] memory messageInput = BLS.prepareVerifyMessage(
            proof.signature,
            proof.pubkeyG2,
            messagePoint
        );

        uint256[] memory batchInput = new uint256[](24);
        for (uint256 i = 0; i < 12; i++) {
            batchInput[i] = apkInput[i];
            batchInput[i + 12] = messageInput[i];
        }

        (bool pairingSuccess, bool callSuccess) = BLS.verifyPairingBatch(batchInput, 2);
        return pairingSuccess && callSuccess;
    }

    function aggregateKeys(uint256[2] memory base, uint256[2] memory addition, bool isAdd) internal pure returns (uint256[2] memory) {
        return isAdd ? BLS.aggregate(base, addition) : BLS.sub(base, addition);
    }

    function verifySingleSignature(
        bytes32 messageHash,
        uint256[2] memory signature,
        uint256[4] memory g2Pubkey,
        uint256[2] memory signingKeys,
        string memory domain
    ) internal view returns (bool) {
        uint256[4] memory pubkeyG2 = BLS.g1ToPk(signingKeys);
        uint256[12] memory input = BLS.prepareVerifyMessage(signature, pubkeyG2, messagePoint);

        (bool pairingSuccess, bool callSuccess) = BLS.verifyPairingBatch(input, 1);
        return pairingSuccess && callSuccess;
    }

    function verifyMultipleSignatures(
        bytes32[] memory messageHashes,
        uint256[2][] memory signatures,
        uint256[4][] memory g2Pubkeys,
        uint256[2][] memory apks,
        string memory domain
    ) internal view returns (bool) {
        require(messageHashes.length == signatures.length && signatures.length == apks.length, "Length mismatch");

        uint256[] memory batchInput = new uint256[](messageHashes.length * 12);

        for (uint256 i = 0; i < messageHashes.length; i++) {
            uint256[2] memory messagePoint = BLS.hashToPoint(bytes(domain), bytes.concat(messageHashes[i]));
            uint256[12] memory input = BLS.prepareVerifyMessage(signatures[i], g2Pubkeys[i], messagePoint);

            for (uint256 j = 0; j < 12; j++) {
                batchInput[i * 12 + j] = input[j];
            }
        }

        (bool pairingSuccess, bool callSuccess) = BLS.verifyPairingBatch(batchInput, uint8(messageHashes.length));
        return pairingSuccess && callSuccess;
    }
}