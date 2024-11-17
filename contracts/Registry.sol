// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EpochLib} from "./EpochLib.sol";
import {BLS} from "../test/utils/BLS.sol";
import {console2 as console} from "../lib/forge-std/src/Test.sol";

contract Registry is Ownable, EIP712 {
    enum Action {
        ENTRY,
        EXIT,
        UPDATE_KEY
    }

    struct Operator {
        address operator;
        uint256[2] signingKey;
        uint256 activationEpoch;
        uint256 deactivationEpoch;
    }

    struct Proof {
        uint256[2] signature;
        uint256[4] pubkeyG2;
    }

    string public constant DOMAIN = "test-domain";
    bytes32 public constant REGISTRATION_TYPEHASH =
        keccak256("Registration(address operator,uint256[2] signingKey,uint256 totp)");

    uint256 public constant SLOTS_PER_EPOCH = 24; // 1 day epochs
    uint256 public constant SLOT_DURATION = 1 hours; // 1 hour slots
    uint256 public constant MAX_CHURN_ENTRIES = 4; // Maximum entries per epoch
    uint256 public constant MAX_CHURN_EXITS = 4; // Maximum exits per epoch
    uint256 public constant MAX_ACTIVE_OPERATORS = 200;

    mapping(uint8 => Operator) public operators;
    mapping(uint8 => bool) public registeredOperators;
    mapping(address => uint8) public operatorIds;
    uint8 public nextOperatorId;

    uint256[2] internal apkG1;
    uint256 internal activeOperatorBitmap;
    uint256 public lastUpdateEpoch;
    uint256 public genesisTime;

    uint256 public pendingEntries;
    uint256 public pendingExits;

    mapping(uint256 => uint8[4]) public entryQueue;
    mapping(uint256 => uint8[4]) public exitQueue;
    mapping(uint256 => uint256[2]) public apkChangeQueue;

    /// @notice Mapping of scheduled signing key updates per epoch and operator
    mapping(uint256 => mapping(uint8 => uint256[2])) public signingKeyChangeQueue;

    event OperatorRegistered(uint8 indexed operatorId, address indexed operator);
    event OperatorSigningKeyUpdated(
        uint8 indexed operatorId, uint256[2] signingKey, uint256[4] pubkeyG2
    );
    event OperatorDeregistered(uint8 indexed operatorId);
    event ApkUpdated(uint256[2] newApk);
    event OperatorBitmapUpdated(uint256 newBitmap);

    error AlreadyRegistered(uint8 operatorId);
    error NotRegistered(uint8 operatorId);
    error InvalidOperator(address operator);
    error NotAuthorized();
    error OperatorLimitReached();
    error InvalidSignature();
    error QueueNeedsProcessing();

    constructor(
        address initialOwner
    ) Ownable(initialOwner) EIP712("Registry", "1.0") {
        genesisTime = block.timestamp;
    }

    function register(
        uint256[2] memory signingKey,
        Proof memory proof
    ) external returns (uint8, uint256) {
        _processQueuesIfNecessary();
        if (!_validateKey(msg.sender, signingKey, proof)) {
            revert InvalidSignature();
        }
        uint8 operatorId = _registerOperator(msg.sender);
        uint256 effectiveEpoch = _queueOperatorUpdate(operatorId, signingKey, Action.ENTRY);
        return (operatorId, effectiveEpoch);
    }

    function updateSigningKey(uint256[2] memory signingKey, Proof memory proof) external {
        _processQueuesIfNecessary();
        uint8 operatorId = operatorIds[msg.sender];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        if (!_validateKey(msg.sender, signingKey, proof)) {
            revert InvalidSignature();
        }
        _queueOperatorUpdate(operatorId, signingKey, Action.UPDATE_KEY);
    }

    function deregister() external {
        _processQueuesIfNecessary();
        uint8 operatorId = operatorIds[msg.sender];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        uint256[2] memory signingKey = operators[operatorId].signingKey;
        _deregisterOperator(operatorId);
        _queueOperatorUpdate(operatorId, signingKey, Action.EXIT);
    }

    function kick(
        uint8 operatorId
    ) external onlyOwner {
        _processQueuesIfNecessary();
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        uint256[2] memory oldKey = operators[operatorId].signingKey;
        _deregisterOperator(operatorId);
        _updateSigningKeyData(
            operatorId, [uint256(0), uint256(0)], [uint256(0), uint256(0), uint256(0), uint256(0)]
        );
        _updateApk(oldKey, false);
        _updateOperatorBitmap(operatorId, false);
    }

    function getOperator(
        uint8 operatorId
    ) external view returns (address, uint256[2] memory) {
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        Operator memory op = operators[operatorId];
        return (op.operator, op.signingKey);
    }

    function operatorBitmap() external view returns (uint256) {
        if (_needsQueueProcessing()) {
            revert QueueNeedsProcessing();
        }
        return activeOperatorBitmap;
    }

    function getOperatorsApk(
        uint8[] memory ids
    ) external view returns (uint256[2] memory apk) {
        if (_needsQueueProcessing()) {
            revert QueueNeedsProcessing();
        }
        uint256 length = ids.length;
        require(length > 0, "No operator IDs provided");
        apk = [uint256(0), uint256(0)];
        for (uint256 i = 0; i < length; i++) {
            uint8 operatorId = ids[i];
            if (!isRegistered(operatorId)) {
                revert NotRegistered(operatorId);
            }
            apk = BLS.aggregate(apk, operators[operatorId].signingKey);
        }
    }

    function apk() external view returns (uint256[2] memory) {
        return apkG1;
    }

    function getNextEntryEpoch() external view returns (uint256) {
        return _getNextEntryEpoch();
    }

    function getNextExitEpoch() external view returns (uint256) {
        return _getNextExitEpoch();
    }

    function isRegistered(
        uint8 operatorId
    ) public view returns (bool) {
        return registeredOperators[operatorId];
    }

    function calculateRegistrationHash(
        address operator,
        uint256[2] memory signingKey
    ) public view returns (bytes32) {
        uint256 totp = block.timestamp / 3600;
        return _hashTypedDataV4(
            keccak256(abi.encode(REGISTRATION_TYPEHASH, operator, signingKey, totp))
        );
    }

    function processQueues() external {
        _processQueuesIfNecessary();
    }

    function getActivationEpoch(
        uint8 operatorId
    ) external view returns (uint256) {
        return operators[operatorId].activationEpoch;
    }

    function getDeactivationEpoch(
        uint8 operatorId
    ) external view returns (uint256) {
        return operators[operatorId].deactivationEpoch;
    }

    function isActive(
        uint8 operatorId
    ) external view returns (bool) {
        if (!isRegistered(operatorId)) {
            return false;
        }
        Operator memory operator = operators[operatorId];
        uint256 currentEpoch = EpochLib.currentEpoch(genesisTime, SLOT_DURATION, SLOTS_PER_EPOCH);
        if (operator.activationEpoch > currentEpoch) {
            return false;
        }
        if (operator.deactivationEpoch != 0 && operator.deactivationEpoch <= currentEpoch) {
            return false;
        }
        return true;
    }

    function _registerOperator(
        address operator
    ) internal returns (uint8) {
        uint8 operatorId = _getNextAvailableOperatorId();
        operators[operatorId] = Operator({
            operator: operator,
            signingKey: [uint256(0), uint256(0)],
            activationEpoch: 0,
            deactivationEpoch: 0
        });
        operatorIds[operator] = operatorId;
        registeredOperators[operatorId] = true;
        if (operatorId == nextOperatorId) {
            nextOperatorId++;
        }
        emit OperatorRegistered(operatorId, operator);
        return operatorId;
    }

    function _deregisterOperator(
        uint8 operatorId
    ) internal {
        address operator = operators[operatorId].operator;
        delete registeredOperators[operatorId];
        delete operatorIds[operator];
        emit OperatorDeregistered(operatorId);
    }

    function _updateSigningKeyData(
        uint8 operatorId,
        uint256[2] memory signingKey,
        uint256[4] memory pubkeyG2
    ) internal {
        operators[operatorId].signingKey = signingKey;
        emit OperatorSigningKeyUpdated(operatorId, signingKey, pubkeyG2);
    }

    function _validateKey(
        address operator,
        uint256[2] memory pubkeyG1,
        Proof memory proof
    ) internal view returns (bool) {
        uint256[12] memory apkInput = BLS.prepareApkInput(proof.pubkeyG2, pubkeyG1);
        bytes32 messageHash = calculateRegistrationHash(operator, pubkeyG1);
        uint256[2] memory messagePoint =
            BLS.hashToPoint(bytes(DOMAIN), abi.encodePacked(messageHash));
        uint256[12] memory messageInput =
            BLS.prepareVerifyMessage(proof.signature, proof.pubkeyG2, messagePoint);

        uint256[] memory batchInput = new uint256[](24);
        for (uint256 i = 0; i < 12; i++) {
            batchInput[i] = apkInput[i];
            batchInput[i + 12] = messageInput[i];
        }

        (bool pairingSuccess, bool callSuccess) = BLS.verifyPairingBatch(batchInput, 2);
        return pairingSuccess && callSuccess;
    }

    function _queueOperatorUpdate(
        uint8 operatorId,
        uint256[2] memory signingKey,
        Action action
    ) internal returns (uint256) {
        uint256 effectiveEpoch;
        if (action == Action.ENTRY) {
            effectiveEpoch = _addToEntryQueue(operatorId, signingKey);
        } else if (action == Action.EXIT) {
            effectiveEpoch = _addToExitQueue(operatorId, signingKey);
        } else if (action == Action.UPDATE_KEY) {
            effectiveEpoch = _updateOperatorKey(operatorId, signingKey);
        } else {
            revert();
        }
        return effectiveEpoch;
    }

    function _addToEntryQueue(
        uint8 operatorId,
        uint256[2] memory signingKey
    ) internal returns (uint256) {
        uint256 activationEpoch = _getNextEntryEpoch();
        _addToQueue(entryQueue, operatorId, pendingEntries, MAX_CHURN_ENTRIES, true);
        operators[operatorId].activationEpoch = activationEpoch;
        operators[operatorId].signingKey = signingKey;
        apkChangeQueue[activationEpoch] = BLS.aggregate(apkChangeQueue[activationEpoch], signingKey);
        return activationEpoch;
    }

    function _addToExitQueue(
        uint8 operatorId,
        uint256[2] memory signingKey
    ) internal returns (uint256) {
        uint256 deactivationEpoch = _getNextExitEpoch();
        _addToQueue(exitQueue, operatorId, pendingExits, MAX_CHURN_EXITS, false);
        operators[operatorId].deactivationEpoch = deactivationEpoch;
        apkChangeQueue[deactivationEpoch] = BLS.sub(apkChangeQueue[deactivationEpoch], signingKey);
        return deactivationEpoch;
    }

    function _updateOperatorKey(
        uint8 operatorId,
        uint256[2] memory newSigningKey
    ) internal returns (uint256) {
        uint256[2] memory oldKey = operators[operatorId].signingKey;
        uint256 currentEpoch = EpochLib.currentEpoch(genesisTime, SLOT_DURATION, SLOTS_PER_EPOCH);
        uint256 effectiveEpoch = currentEpoch + 1; // Schedule for next epoch

        // Schedule the signing key update
        signingKeyChangeQueue[effectiveEpoch][operatorId] = newSigningKey;

        // Schedule the apkG1 update
        uint256[2] memory apkDelta = BLS.sub(newSigningKey, oldKey);
        apkChangeQueue[effectiveEpoch] = BLS.aggregate(apkChangeQueue[effectiveEpoch], apkDelta);

        return effectiveEpoch;
    }

    function _addToQueue(
        mapping(uint256 => uint8[4]) storage queue,
        uint8 operatorId,
        uint256 queueSize,
        uint256 maxChurn,
        bool isEntry
    ) internal {
        uint256 epoch = isEntry ? _getNextEntryEpoch() : _getNextExitEpoch();
        uint8[4] storage epochQueue = queue[epoch];
        uint256 slot = queueSize % maxChurn;

        epochQueue[slot] = operatorId;
        queue[epoch] = epochQueue;

        if (isEntry) {
            pendingEntries++;
        } else {
            pendingExits++;
        }
    }

    function _processQueuesIfNecessary() internal {
        if (_needsQueueProcessing()) {
            uint256 currentEpoch = EpochLib.currentEpoch(
                genesisTime,
                SLOT_DURATION,
                SLOTS_PER_EPOCH
            );

            for (uint256 epoch = lastUpdateEpoch + 1; epoch <= currentEpoch; epoch++) {
                _processQueue(entryQueue, pendingEntries, MAX_CHURN_ENTRIES, epoch, true);
                _processQueue(exitQueue, pendingExits, MAX_CHURN_EXITS, epoch, false);

                // Apply signing key updates scheduled for this epoch
                _processSigningKeyUpdates(epoch);

                // Apply apkG1 changes for this epoch
                _applyApkChanges(epoch);
            }

            lastUpdateEpoch = currentEpoch;
        }
    }

    function _needsQueueProcessing() internal view returns (bool) {
        uint256 currentEpoch = EpochLib.currentEpoch(genesisTime, SLOT_DURATION, SLOTS_PER_EPOCH);
        return currentEpoch > lastUpdateEpoch;
    }

    function _processQueue(
        mapping(uint256 => uint8[4]) storage queue,
        uint256 queueLength,
        uint256 maxChurn,
        uint256 epoch,
        bool isEntry
    ) internal {
        uint8[4] storage operators = queue[epoch];
        uint256 operatorsToProcess = queueLength < maxChurn ? queueLength : maxChurn;

        for (uint256 i = 0; i < operatorsToProcess; i++) {
            uint8 operatorId = operators[i];
            if (isEntry) {
                pendingEntries--;
                _updateOperatorBitmap(operatorId, true);
            } else {
                pendingExits--;
                _updateOperatorBitmap(operatorId, false);
                delete operators[operatorId];
            }
        }

        delete queue[epoch];
    }

    function _applyApkChanges(
        uint256 epoch
    ) internal {
        uint256[2] memory epochApkChange = apkChangeQueue[epoch];
        if (epochApkChange[0] != 0 || epochApkChange[1] != 0) {
            apkG1 = BLS.aggregate(apkG1, epochApkChange);
            emit ApkUpdated(apkG1);
            delete apkChangeQueue[epoch];
        }
    }

    function _updateApk(uint256[2] memory publicKeyG1, bool isAdd) internal {
        if (isAdd) {
            apkG1 = BLS.aggregate(apkG1, publicKeyG1);
        } else {
            apkG1 = BLS.sub(apkG1, publicKeyG1);
        }
        emit ApkUpdated(apkG1);
    }

    function _updateOperatorBitmap(uint8 operatorId, bool isAdd) internal {
        if (isAdd) {
            activeOperatorBitmap |= (1 << operatorId);
        } else {
            activeOperatorBitmap &= ~(1 << operatorId);
        }
        emit OperatorBitmapUpdated(activeOperatorBitmap);
    }

    function _getNextAvailableOperatorId() internal view returns (uint8) {
        for (uint8 i = 0; i < nextOperatorId; i++) {
            if (!isRegistered(i)) {
                return i;
            }
        }
        if (nextOperatorId >= 256) {
            revert OperatorLimitReached();
        }
        return nextOperatorId;
    }

    function _getNextEntryEpoch() internal view returns (uint256) {
        uint256 currentEpoch = EpochLib.currentEpoch(genesisTime, SLOT_DURATION, SLOTS_PER_EPOCH);
        uint256 epochsNeeded = pendingEntries / MAX_CHURN_ENTRIES + 1;
        return currentEpoch + epochsNeeded;
    }

    function _getNextExitEpoch() internal view returns (uint256) {
        uint256 currentEpoch = EpochLib.currentEpoch(genesisTime, SLOT_DURATION, SLOTS_PER_EPOCH);
        uint256 epochsNeeded = pendingExits / MAX_CHURN_EXITS + 1;
        return currentEpoch + epochsNeeded;
    }

    function _processSigningKeyUpdates(uint256 epoch) internal {
        mapping(uint8 => uint256[2]) storage updates = signingKeyChangeQueue[epoch];

        for (uint8 operatorId = 0; operatorId < nextOperatorId; operatorId++) {
            uint256[2] memory newSigningKey = updates[operatorId];
            if (newSigningKey[0] != 0 || newSigningKey[1] != 0) {
                // Update the operator's signing key
                operators[operatorId].signingKey = newSigningKey;

                // Emit event for signing key update
                emit OperatorSigningKeyUpdated(
                    operatorId,
                    newSigningKey,
                    [uint256(0), uint256(0), uint256(0), uint256(0)]
                );

                // Remove the update from the queue
                delete updates[operatorId];
                // delete signingKeyChangeQueue[epoch][operatorId];
            }
        }

        // Remove the epoch from the queue if all updates have been processed
    }
}
