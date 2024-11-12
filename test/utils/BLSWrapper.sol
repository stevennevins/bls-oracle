// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "./BLS.sol";

/// Expose library functions as a contract we can hit
contract BLSWrapper {
    function expandMsgTo96(
        bytes memory domain,
        bytes memory message
    ) external pure returns (bytes memory) {
        return BLS.expandMsgTo96(domain, message);
    }

    function hashToField(
        bytes memory domain,
        bytes memory message
    ) external pure returns (uint256[2] memory) {
        return BLS.hashToField(domain, message);
    }

    function mapToPoint(
        uint256 value
    ) external view returns (uint256[2] memory) {
        return BLS.mapToPoint(value);
    }

    function hashToPoint(
        string memory domain,
        string memory message
    ) external view returns (uint256[2] memory) {
        return BLS.hashToPoint(bytes(domain), bytes(message));
    }

    function hashToPoint(
        string memory domain,
        bytes32 message
    ) external view returns (uint256[2] memory) {
        return BLS.hashToPoint(bytes(domain), bytes.concat(message));
    }

    function verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) external view returns (bool, bool) {
        return BLS.verifySingle(signature, pubkey, message);
    }

    function verifyBatch(
        uint256[2][] memory signatures,
        uint256[4][] memory pubKeys,
        uint256[2][] memory messages
    ) external view returns (bool, bool) {
        return BLS.verifyMultiple(signatures, pubKeys, messages);
    }

    function isOnCurveG1(
        uint256[2] memory point
    ) external pure returns (bool) {
        return BLS.isOnCurveG1(point);
    }

    function isOnCurveG2(
        uint256[4] memory point
    ) external pure returns (bool) {
        return BLS.isOnCurveG2(point);
    }

    function isValidSignature(
        uint256[2] memory signature
    ) external pure returns (bool) {
        return BLS.isValidSignature(signature);
    }

    function isValidPublicKey(
        uint256[4] memory publicKey
    ) external pure returns (bool) {
        return BLS.isValidPublicKey(publicKey);
    }

    function aggregate(
        uint256[2] memory pk1,
        uint256[2] memory pk2
    ) external view returns (uint256[2] memory) {
        return BLS.aggregate(pk1, pk2);
    }
}
