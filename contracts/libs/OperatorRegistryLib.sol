// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

library OperatorRegistry {
    struct Operator {
        address operator;
        uint256[2] signingKey;
    }

    struct RegistryState {
        mapping(uint8 => Operator) operators;
        mapping(uint8 => bool) registeredOperators;
        mapping(address => uint8) operatorIds;
        uint8 nextOperatorId;
    }

    error OperatorLimitReached();
    error NotRegistered(uint8 operatorId);

    function getNextAvailableOperatorId(RegistryState storage self) internal view returns (uint8) {
        if (self.nextOperatorId >= 256) {
            revert OperatorLimitReached();
        }

        for (uint8 i = 0; i < self.nextOperatorId; i++) {
            if (!self.registeredOperators[i]) {
                return i;
            }
        }

        return self.nextOperatorId;
    }

    function register(
        RegistryState storage self,
        address operator
    ) internal returns (uint8) {
        uint8 operatorId = getNextAvailableOperatorId(self);
        if (operatorId == self.nextOperatorId) {
            self.nextOperatorId++;
        }

        self.operators[operatorId].operator = operator;
        self.operatorIds[operator] = operatorId;
        self.registeredOperators[operatorId] = true;

        return operatorId;
    }

    function deregister(
        RegistryState storage self,
        uint8 operatorId
    ) internal {
        address operator = self.operators[operatorId].operator;
        delete self.operatorIds[operator];
        delete self.operators[operatorId];
        delete self.registeredOperators[operatorId];
    }
}