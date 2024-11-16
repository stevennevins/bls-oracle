// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Registry} from "./Registry.sol";
import {BLS} from "../test/utils/BLS.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract Oracle is EIP712 {
    Registry public registry;

    struct AggregateSignatureData {
        uint256[2] aggSignatureG1;
        uint256[4] aggPubkeyG2;
        uint256 signerBitmap;
    }

    string public constant DOMAIN = "oracle-domain";

    bytes32 public constant RESPONSE_TYPEHASH = keccak256("Response(bytes response,uint256 totp)");

    error InvalidSignature();

    event ResponseRecorded(bytes response);

    constructor(
        address _registry
    ) EIP712("Oracle", "1.0") {
        registry = Registry(_registry);
    }

    function record(bytes memory response, AggregateSignatureData memory signature) external {
        uint8[] memory nonSignerIds = _bitmapToNonSignerIds(signature.signerBitmap);
        // uint256[2] memory nonSignerApk = registry.getOperatorsApk(nonSignerIds);
        uint256[2] memory aggApk = registry.apk();
        if (nonSignerIds.length > 0) {
            uint256[2] memory nonSignerApk = registry.getOperatorsApk(nonSignerIds);
            aggApk = BLS.sub(aggApk, nonSignerApk);
        }

        bytes32 messageHash = calculateMessageHash(response);
        uint256[2] memory messagePoint = BLS.hashToPoint(bytes(DOMAIN), bytes.concat(messageHash));

        uint256[12] memory apkInput = BLS.prepareApkInput(signature.aggPubkeyG2, aggApk);
        uint256[12] memory sigInput =
            BLS.prepareVerifyMessage(signature.aggSignatureG1, signature.aggPubkeyG2, messagePoint);

        uint256[] memory batchInput = new uint256[](24);
        for (uint256 i = 0; i < 12; i++) {
            batchInput[i] = apkInput[i];
            batchInput[i + 12] = sigInput[i];
        }

        (bool pairingSuccess, bool callSuccess) = BLS.verifyPairingBatch(batchInput, 2);

        if (!callSuccess || !pairingSuccess) {
            revert InvalidSignature();
        }

        emit ResponseRecorded(response);
    }

    function calculateMessageHash(
        bytes memory responseData
    ) public view returns (bytes32) {
        uint256 totp = block.timestamp / 3600;
        return _hashTypedDataV4(keccak256(abi.encode(RESPONSE_TYPEHASH, responseData, totp)));
    }

    function _bitmapToNonSignerIds(
        uint256 bitmap
    ) internal returns (uint8[] memory) {
        uint256 registryBitmap = registry.operatorBitmap();
        uint8[] memory indices = new uint8[](255);
        uint8 zeroCount = 0;
        for (uint8 i = 0; i < 255; i++) {
            // Check if bit is set in registry bitmap but not in passed bitmap
            if (((registryBitmap & (1 << i)) != 0) && ((bitmap & (1 << i)) == 0)) {
                indices[zeroCount] = i;
                zeroCount++;
            }
        }

        assembly {
            mstore(indices, zeroCount) // Update array length
        }

        return indices;
    }

    function bitmapToNonSignerIds(
        uint256 bitmap
    ) external returns (uint8[] memory) {
        return _bitmapToNonSignerIds(bitmap);
    }
}
