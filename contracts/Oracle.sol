// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Registry} from "./Registry.sol";

contract Oracle {
    Registry public registry;

    error InvalidSignature();

    constructor(
        address _registry
    ) {
        registry = Registry(_registry);
    }

    /// TOTP based?
    function record(
        bytes memory response,
        uint256[4] memory signature,
        uint8[] memory operatorIds
    ) external view {
        uint256[2] memory apk = registry.getOperatorsApk(operatorIds);

        // Verify BLS signature
        bytes32 messageHash = constructMessage(response);
        bool isValid = verifySingleSignature(messageHash, signature, apk);
        if (!isValid) {
            revert InvalidSignature();
        }

        /// TODO: Record data
    }

    /// TOTP based?
    function recordBatch(
        bytes[] memory response,
        uint256[2][] memory signature,
        uint8[][] memory operatorIds
    ) external view {
        /// TODO: Record data
    }

    function constructMessage(
        bytes memory responseData
    ) public pure returns (bytes32) {
        /// TODO: more interpretable / TOTP / typed datahash
        return keccak256(responseData);
    }

    function verifySingleSignature(
        bytes32 messageHash,
        uint256[4] memory signature,
        uint256[2] memory signingKeys
    ) internal view returns (bool) {
        /// TODO: implementation to call precompile
        return true;
    }

    function verifyMultipleSignature(
        bytes32[] memory messageHash,
        uint256[4][] memory signatures,
        uint256[2][] memory apk
    ) internal view returns (bool) {
        /// TODO: implementation to call precompile
        return true;
    }
}
