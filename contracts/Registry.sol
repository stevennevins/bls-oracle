// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BLS} from "../test/utils/BLS.sol";

contract Registry is Ownable {
    struct Operator {
        address operator;
        uint256[4] signingKey;
    }

    // Mapping from operator ID (1-256) to operator data
    mapping(uint8 => Operator) public operators;

    // Mapping of registered operator IDs
    mapping(uint8 => bool) public registeredOperators;

    // Counter for next available operator ID
    uint8 private nextOperatorId = 1;

    // Mapping from operator address to operator ID
    mapping(address => uint8) public operatorIds;

    event OperatorRegistered(uint8 indexed operatorId, address indexed operator);
    event SigningKeyUpdated(uint8 indexed operatorId, uint256[4] signingKey);
    event OperatorDeregistered(uint8 indexed operatorId);

    error AlreadyRegistered(uint8 operatorId);
    error NotRegistered(uint8 operatorId);
    error InvalidOperator(address operator);
    error NotAuthorized();
    error OperatorLimitReached();

    constructor(
        address initialOwner
    ) Ownable(initialOwner) {}

    function register(
        uint256[4] memory signingKey
    ) external returns (uint8) {
        return _register(msg.sender, signingKey);
    }

    function updateSigningKey(
        uint256[4] memory newSigningKey
    ) external {
        uint8 operatorId = operatorIds[msg.sender];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }

        _updateSigningKey(operatorId, newSigningKey);
    }

    function deregister() external {
        uint8 operatorId = operatorIds[msg.sender];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }

        _deregister(operatorId);
    }

    function kick(
        uint8 operatorId
    ) external onlyOwner {
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }

        _deregister(operatorId);
    }

    function getOperator(
        uint8 operatorId
    ) external view returns (address, uint256[4] memory) {
        Operator memory op = operators[operatorId];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        return (op.operator, op.signingKey);
    }

    function getOperatorsApk(
        uint8[] memory operatorIds
    ) external view returns (uint256[2] memory apk) {
        if (operatorIds.length == 0) {
            return apk;
        }

        // Get first signing key
        uint8 operatorId = operatorIds[0];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        apk; // TODO :Fix

        // Add remaining signing keys
        for (uint256 i = 1; i < operatorIds.length; i++) {
            operatorId = operatorIds[i];
            if (!isRegistered(operatorId)) {
                revert NotRegistered(operatorId);
            }
            apk = BLS.aggregate(apk, apk); /// TODO: Fix
        }

        return apk;
    }

    function isRegistered(
        uint8 operatorId
    ) public view returns (bool) {
        return registeredOperators[operatorId];
    }

    function _getNextAvailableOperatorId() internal view returns (uint8) {
        if (nextOperatorId > 256) {
            revert OperatorLimitReached();
        }

        // Start from 1 since operatorId 0 is invalid
        for (uint8 i = 1; i < nextOperatorId; i++) {
            // Check if this slot is operatorId is unallocated
            if (!isRegistered(i)) {
                return i;
            }
        }

        // If no gaps found, return next sequential ID
        return nextOperatorId;
    }

    function _register(address operator, uint256[4] memory signingKey) internal returns (uint8) {
        if (nextOperatorId > 256) {
            revert OperatorLimitReached();
        }

        uint8 operatorId = _getNextAvailableOperatorId();

        // If we found a gap, use that ID. Otherwise increment nextOperatorId
        if (operatorId == nextOperatorId) {
            nextOperatorId++;
        }

        operators[operatorId].operator = operator;
        operatorIds[operator] = operatorId;
        registeredOperators[operatorId] = true;

        _updateSigningKey(operatorId, signingKey);

        emit OperatorRegistered(operatorId, operator);

        return operatorId;
    }

    function _updateSigningKey(uint8 operatorId, uint256[4] memory signingKey) internal {
        operators[operatorId].signingKey = signingKey;
        emit SigningKeyUpdated(operatorId, signingKey);
    }

    function _deregister(
        uint8 operatorId
    ) internal {
        address operator = operators[operatorId].operator;
        delete operatorIds[operator];
        delete operators[operatorId];
        delete registeredOperators[operatorId];

        emit OperatorDeregistered(operatorId);
    }
}
