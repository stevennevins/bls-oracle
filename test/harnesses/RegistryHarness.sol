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
}
