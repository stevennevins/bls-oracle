// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Registry} from "../../contracts/Registry.sol";

contract RegistryHarness is Registry {
    constructor(
        address initialOwner
    ) Registry(initialOwner) {}

    function exposed_getNextAvailableOperatorId() external view returns (uint8) {
        return _getNextAvailableOperatorId();
    }

    function exposed_register(
        address operator
    ) external returns (uint8) {
        return _register(operator);
    }

    function exposed_updateSigningKey(
        uint8 operatorId,
        uint256[2] memory signingKey,
        uint256[4] memory pubkeyG2
    ) external {
        _updateSigningKey(operatorId, signingKey, pubkeyG2);
    }

    function exposed_deregister(
        uint8 operatorId
    ) external {
        _deregister(operatorId);
    }

    function exposed_validateKey(
        address operator,
        uint256[2] memory pubkeyG1,
        Proof memory proof
    ) external view returns (bool) {
        return _validateKey(operator, pubkeyG1, proof);
    }

    function exposed_updateApk(uint256[2] memory publicKeyG1, bool isAdd) external {
        _updateApk(publicKeyG1, isAdd);
    }

    function exposed_updateOperatorBitmap(uint8 operatorId, bool isAdd) external {
        _updateOperatorBitmap(operatorId, isAdd);
    }

    function exposed_processQueuesIfNecessary() external {
        _processQueuesIfNecessary();
    }

    function exposed_processEntryQueue(
        uint256 epoch
    ) external {
        _processEntryQueue(epoch);
    }

    function exposed_processExitQueue(
        uint256 epoch
    ) external {
        _processExitQueue(epoch);
    }
}
