// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Vm} from "forge-std/src/Vm.sol";
import {console2 as console} from "../../lib/forge-std/src/Test.sol";

struct BLSWallet {
    uint256 privateKey;
    uint256[4] publicKey;
    uint256[2] publicKeyG1;
}

library BLSTestingLib {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function createWallet(
        string memory seed
    ) internal returns (BLSWallet memory) {
        uint256 privateKey = uint256(keccak256(abi.encodePacked(seed)));
        uint256[4] memory publicKey = getPublicKey(privateKey);
        uint256[2] memory publicKeyG1 = getPublicKeyG1(privateKey);
        return BLSWallet({privateKey: privateKey, publicKey: publicKey, publicKeyG1: publicKeyG1});
    }

    function getPublicKeyG1(
        uint256 privateKey
    ) internal returns (uint256[2] memory) {
        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "get-pubkey-g1";
        inputs[3] = vm.toString(bytes32(privateKey));

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory pubKey;
        pubKey[0] = decodedResponse[2];
        pubKey[1] = decodedResponse[3];
        return pubKey;
    }

    function getPublicKey(
        uint256 privateKey
    ) internal returns (uint256[4] memory) {
        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "get-pubkey";
        inputs[3] = vm.toString(bytes32(privateKey));

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[6] memory decodedResponse = abi.decode(jsonBytes, (uint256[6]));
        uint256[4] memory pubKey;
        pubKey[0] = decodedResponse[2];
        pubKey[1] = decodedResponse[3];
        pubKey[2] = decodedResponse[4];
        pubKey[3] = decodedResponse[5];
        return pubKey;
    }

    function getPublicKey(
        uint256[] memory privateKeys
    ) internal returns (uint256[4] memory) {
        string[] memory inputs = new string[](4);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "get-agg-pubkey";

        string memory privateKeyList = "";
        for (uint256 i; i < privateKeys.length; i++) {
            if (i > 0) {
                privateKeyList = string.concat(privateKeyList, ",");
            }
            privateKeyList = string.concat(privateKeyList, vm.toString(bytes32(privateKeys[i])));
        }
        inputs[3] = privateKeyList;

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[6] memory decodedResponse = abi.decode(jsonBytes, (uint256[6]));
        uint256[4] memory pubKey;
        pubKey[0] = decodedResponse[2];
        pubKey[1] = decodedResponse[3];
        pubKey[2] = decodedResponse[4];
        pubKey[3] = decodedResponse[5];
        return pubKey;
    }

    function sign(
        uint256[] memory privateKeys,
        string memory domain,
        bytes32 message
    ) internal returns (uint256[2] memory) {
        // Build comma-separated private key list
        string memory privateKeyList = "";
        for (uint256 i; i < privateKeys.length; i++) {
            if (i > 0) {
                privateKeyList = string.concat(privateKeyList, ",");
            }
            privateKeyList = string.concat(privateKeyList, vm.toString(bytes32(privateKeys[i])));
        }

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "sign-agg";
        inputs[3] = privateKeyList;
        inputs[4] = domain;
        inputs[5] = vm.toString(message);

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");
        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory signature;
        signature[0] = decodedResponse[2];
        signature[1] = decodedResponse[3];
        return signature;
    }

    function sign(
        uint256[] memory privateKeys,
        string memory domain,
        string memory message
    ) internal returns (uint256[2] memory) {
        // Build comma-separated private key list
        string memory privateKeyList = "";
        for (uint256 i; i < privateKeys.length; i++) {
            if (i > 0) {
                privateKeyList = string.concat(privateKeyList, ",");
            }
            privateKeyList = string.concat(privateKeyList, vm.toString(bytes32(privateKeys[i])));
        }

        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "sign-agg";
        inputs[3] = privateKeyList;
        inputs[4] = domain;
        inputs[5] = message;

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory signature;
        signature[0] = decodedResponse[2];
        signature[1] = decodedResponse[3];
        return signature;
    }

    function sign(
        uint256 privateKey,
        string memory domain,
        bytes32 message
    ) internal returns (uint256[2] memory) {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "sign";
        inputs[3] = vm.toString(bytes32(privateKey));
        inputs[4] = domain;
        inputs[5] = vm.toString(message);

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");
        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory signature;
        signature[0] = decodedResponse[2];
        signature[1] = decodedResponse[3];
        return signature;
    }

    function sign(
        uint256 privateKey,
        string memory domain,
        string memory message
    ) internal returns (uint256[2] memory) {
        string[] memory inputs = new string[](6);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "sign";
        inputs[3] = vm.toString(bytes32(privateKey));
        inputs[4] = domain;
        inputs[5] = message;

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");
        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory signature;
        signature[0] = decodedResponse[2];
        signature[1] = decodedResponse[3];
        return signature;
    }

    function hashToPoint(
        string memory domain,
        string memory message
    ) internal returns (uint256[2] memory) {
        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "hash";
        inputs[3] = domain;
        inputs[4] = message;

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory point;
        point[0] = decodedResponse[2];
        point[1] = decodedResponse[3];
        return point;
    }

    function hashToPoint(
        string memory domain,
        bytes32 message
    ) internal returns (uint256[2] memory) {
        string[] memory inputs = new string[](5);
        inputs[0] = "node";
        inputs[1] = "./dist/cli/cli.js";
        inputs[2] = "hash";
        inputs[3] = domain;
        inputs[4] = vm.toString(message);

        bytes memory response = vm.ffi(inputs);
        string memory jsonStr = string.concat("[", string(response), "]");

        bytes memory jsonBytes = vm.parseJson(jsonStr);
        uint256[4] memory decodedResponse = abi.decode(jsonBytes, (uint256[4]));
        uint256[2] memory point;
        point[0] = decodedResponse[2];
        point[1] = decodedResponse[3];
        return point;
    }
}
