// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Registry} from "../../contracts/Registry.sol";

contract RegistryHarness is Registry {
    constructor(
        address initialOwner
    ) Registry(initialOwner) {}

    function exposed_validateKey(
        address operator,
        uint256[2] memory pubkeyG1,
        Proof memory proof
    ) external view returns (bool) {
        return _validateKey(operator, pubkeyG1, proof);
    }

    function exposed_processQueuesIfNecessary() external {
        _processQueuesIfNecessary();
    }
}
