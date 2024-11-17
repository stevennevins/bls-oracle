// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EpochLib} from "./EpochLib.sol";
import {BLS} from "../test/utils/BLS.sol";
import {console2 as console} from "../lib/forge-std/src/Test.sol";

contract Registry is Ownable, EIP712 {
    enum Action {
        ENTRY, EXIT, UPDATE_KEY
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

    mapping(uint8 => Operator) public operators;
    // uint256[256][2] internal pubKeys;
    mapping(uint8 => bool) public registeredOperators;
    mapping(address => uint8) public operatorIds;
    uint8 public nextOperatorId;

    uint256[2] internal apkG1;
    uint256 internal activeOperatorBitmap;
    uint256 public lastUpdateEpoch;

    mapping(uint256 epoch => uint8[4]) public entryQueue;
    mapping(uint256 epoch => uint8[4]) public exitQueue;
    mapping(uint256 epoch => uint256[2]) public apkChangeQueue;
    /// Handle delayed operator key changes
    mapping(uint8 operatorId => uint256[2]) public nextKey; /// Write to this and then in process Queue write it to the operator

    // Epoch variables
    uint256 public SLOTS_PER_EPOCH = 24; // 1 day epochs
    uint256 public SLOT_DURATION = 1 hours; // 1 hour slots
    uint256 public genesisTime;

    // Entry/Exit queue variables
    uint256 public pendingEntries;
    uint256 public pendingExits;
    uint256 public MAX_CHURN_ENTRIES = 4; // Maximum entries per epoch
    uint256 public MAX_CHURN_EXITS = 4; // Maximum exits per epoch
    uint256 public MAX_QUEUE_ENTRIES = 28;
    uint256 public MAX_QUEUE_EXITS = 28;
    uint256 public MAX_ACTIVE_OPERATORS = 200;

    bytes32 public constant REGISTRATION_TYPEHASH =
        keccak256("Registration(address operator,uint256[2] signingKey,uint256 totp)");

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

    /// TODO: Epoch based queue entry / exit.  This will enable caching bitmap -> Apk caching with solid guarentees
    /// TODO: Include valid until so the registration will fail if they entry queue is too long relative to their intent to wait + TOTP
    constructor(
        address initialOwner
    ) Ownable(initialOwner) EIP712("Registry", "1.0") {
        genesisTime = block.timestamp;
    }

    function register(uint256[2] memory signingKey, Proof memory proof) external returns (uint8, uint256) {
        _processQueuesIfNecessary();
        if (!_validateKey(msg.sender, signingKey, proof)) {
            revert InvalidSignature();
        }
        uint8 operatorId = _register(msg.sender);
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

        _queueOperatorUpdate(operatorId, signingKey, Action.UPDATE_KEY); // TODO: Prevent signing key updates after queue. Simple way might be to prevent if in Activation/Deactivation Queues
    }

    function deregister() external {
        _processQueuesIfNecessary();
        uint8 operatorId = operatorIds[msg.sender];
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }

        uint256[2] memory oldKey = operators[operatorId].signingKey;
        _deregister(operatorId);
        uint256[2] memory signingKey = operators[operatorId].signingKey;
        _queueOperatorUpdate(operatorId, signingKey, Action.EXIT); // TODO: Prevent signing key updates after queue
    }

    function kick(
        uint8 operatorId
    ) external onlyOwner {
        _processQueuesIfNecessary();
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }

        uint256[2] memory oldKey = operators[operatorId].signingKey;
        _deregister(operatorId);
        _updateSigningKey(
            operatorId, [uint256(0), uint256(0)], [uint256(0), uint256(0), uint256(0), uint256(0)]
        );
        _updateApk({publicKeyG1: oldKey, isAdd: false});
        _updateOperatorBitmap({operatorId: operatorId, isAdd: false});
    }

    function getOperator(
        uint8 operatorId
    ) external returns (address, uint256[2] memory) {
        /// TODO: This should not be view and should process the queues if necessary
        if (!isRegistered(operatorId)) {
            revert NotRegistered(operatorId);
        }
        Operator memory op = operators[operatorId];
        return (op.operator, op.signingKey);
    }

    function operatorBitmap() external returns (uint256) {
        /// TODO: This should not be view and should process the queues if necessary
        return activeOperatorBitmap;
    }

    function getOperatorsApk(
        uint8[] memory ids
    ) external returns (uint256[2] memory apk) {
        /// TODO: This should not be view and should process the queues if necessary
        uint256 length = ids.length;
        if (length == 0) {
            return apk;
        }

        if (!isRegistered(ids[0])) {
            revert NotRegistered(ids[0]);
        }
        apk = operators[ids[0]].signingKey;

        if (length == 1) {
            return apk;
        }

        for (uint256 i = 0; i < length; i++) {
            uint8 operatorId = ids[i];
            if (operatorId >= nextOperatorId) {
                /// TODO: Should handle this in bitmap function
                continue;
            }
            if (!isRegistered(operatorId)) {
                revert NotRegistered(operatorId);
            }
            apk = BLS.aggregate(apk, operators[operatorId].signingKey);
        }
    }

    function apk() external returns (uint256[2] memory) {
        /// TODO: This should not be view and should process the queues if necessary
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
        /// TODO: Assess the guarentees of this function
        /// active vs registered distinction
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

    /// @notice Process any pending entry and exit queues for the current epoch
    /// @dev This function can be called by anyone to process the queues
    function processQueues() external {
        _processQueuesIfNecessary();
    }

    function _getNextAvailableOperatorId() internal view returns (uint8) {
        if (nextOperatorId >= 256) {
            revert OperatorLimitReached();
        }

        for (uint8 i = 0; i < nextOperatorId; i++) {
            if (!isRegistered(i)) {
                return i;
            }
        }

        return nextOperatorId;
    }

    function _register(
        address operator
    ) internal returns (uint8) {
        if (nextOperatorId > 256) {
            revert OperatorLimitReached();
        }

        uint8 operatorId = _getNextAvailableOperatorId();
        if (operatorId == nextOperatorId) {
            nextOperatorId++;
        }

        operators[operatorId].operator = operator;
        operatorIds[operator] = operatorId;
        registeredOperators[operatorId] = true;

        emit OperatorRegistered(operatorId, operator);
        return operatorId;
    }

    function _updateSigningKey(
        uint8 operatorId,
        uint256[2] memory signingKey,
        uint256[4] memory pubkeyG2
    ) internal {
        operators[operatorId].signingKey = signingKey;
        emit OperatorSigningKeyUpdated(operatorId, signingKey, pubkeyG2);
    }

    function _deregister(
        uint8 operatorId
    ) internal {
        address operator = operators[operatorId].operator;
        // delete operatorIds[operator];
        // delete operators[operatorId];
        delete registeredOperators[operatorId];

        emit OperatorDeregistered(operatorId);
    }

    function _validateKey(
        address operator,
        uint256[2] memory pubkeyG1,
        Proof memory proof
    ) internal view returns (bool) {
        uint256[12] memory apkInput = BLS.prepareApkInput(proof.pubkeyG2, pubkeyG1);
        bytes32 messageHash = calculateRegistrationHash(operator, pubkeyG1);
        uint256[2] memory messagePoint = BLS.hashToPoint(bytes(DOMAIN), bytes.concat(messageHash));
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
        Action reason
    ) internal returns (uint256) {
        uint256 effectiveEpoch;
        if (reason == Action.ENTRY) {
            effectiveEpoch = _addToEntryQueue(operatorId);
            operators[operatorId].activationEpoch = effectiveEpoch;
            operators[operatorId].signingKey = signingKey;
            uint256[2] memory apk = apkChangeQueue[effectiveEpoch];
            apkChangeQueue[effectiveEpoch] = BLS.aggregate(apk, signingKey);
        } else if (reason == Action.EXIT) {
            effectiveEpoch = _addToExitQueue(operatorId);
            operators[operatorId].deactivationEpoch = effectiveEpoch;
            uint256[2] memory apk = apkChangeQueue[effectiveEpoch];
            apkChangeQueue[effectiveEpoch] = BLS.sub(apk, signingKey);
        } else if (reason == Action.UPDATE_KEY){
            uint256 currentSlot = EpochLib.currentSlot(genesisTime, SLOT_DURATION);
            effectiveEpoch = EpochLib.slotToEpoch(currentSlot, SLOTS_PER_EPOCH) + 1; // Takes effect next epoch
            uint256[2] memory apk = apkChangeQueue[effectiveEpoch];
            uint256[2] memory oldKey = operators[operatorId].signingKey;
            uint256[2] memory delta = BLS.sub(signingKey, oldKey);
            apkChangeQueue[effectiveEpoch] = BLS.aggregate(apk, delta);
        } else {
            revert("Invalid path");
        }
        return effectiveEpoch;
    }

    function _processQueuesIfNecessary() internal {
        uint256 currentSlot = EpochLib.currentSlot(genesisTime, SLOT_DURATION);
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, SLOTS_PER_EPOCH);

        // Return early if already processed this epoch
        if (lastUpdateEpoch >= currentEpoch) {
            return;
        }

        _processEntryQueue(currentEpoch);
        _processExitQueue(currentEpoch);

        lastUpdateEpoch = currentEpoch;
    }

    function _addToQueue(
        uint256 epoch,
        mapping(uint256 => uint8[4]) storage queue,
        uint8 operatorId,
        uint256 queueSize,
        uint256 maxEpochChurn, // paramaterizing this since they may differ
        bool isEntry
    ) internal {
        // Get current queue for this epoch
        uint8[4] storage epochQueue = queue[epoch];

        // Calculate slot index (0-3) based on queue size
        uint256 slot = queueSize % maxEpochChurn;

        console.log("Adding to queue - epoch: %s, slot: %s", epoch, slot);
        // Add operator to queue
        epochQueue[slot] = operatorId;
        queue[epoch] = epochQueue;

        // Update pending count
        if (isEntry) {
            pendingEntries++;
        } else {
            pendingExits++;
        }
    }

    function _addToEntryQueue(uint8 operatorId) internal returns (uint256){
        uint256 activationEpoch = _getNextEntryEpoch();
        console.log("OperatorId: %s", operatorId);
        console.log("Pending entries: %s", pendingEntries);
        console.log("Activation epoch: %s", activationEpoch);
        _addToQueue(activationEpoch, entryQueue, operatorId, pendingEntries, MAX_CHURN_ENTRIES, true);
        return activationEpoch;
    }

    function _addToExitQueue(
        uint8 operatorId
    ) internal returns (uint256) {
        uint256 deactivationEpoch = _getNextExitEpoch();
        _addToQueue(deactivationEpoch, entryQueue, operatorId, pendingEntries, MAX_CHURN_EXITS, false);
        return deactivationEpoch;

    }

    function _processEntryQueue(
        uint256 epoch
    ) internal {
        _processQueue(epoch, entryQueue, pendingEntries, MAX_CHURN_ENTRIES, true);
    }

    function _processExitQueue(
        uint256 epoch
    ) internal {
        _processQueue(epoch, exitQueue, pendingExits, MAX_CHURN_EXITS, false);
    }

    function _processQueue(
        uint256 epoch,
        mapping(uint256 => uint8[4]) storage queue,
        uint256 queueLength,
        uint256 maxChurn, // paramaterizing this since they may differ
        bool isEntry
    ) internal {
        uint8[4] memory operators = queue[epoch];
        uint256 operatorsToProcess = queueLength < maxChurn ? queueLength : maxChurn;

        // Process operators up to maxChurn limit
        for (uint256 i = 0; i < operatorsToProcess; i++) {
            uint8 operatorId = operators[i];
            if (isEntry) {
                pendingEntries--;
            } else {
                pendingExits--;
                delete operators[operatorId];
            }
            _updateOperatorBitmap(operatorId, isEntry);
        }

        // Apply queued APK changes for this epoch
        uint256[2] memory epochApkChange = apkChangeQueue[epoch];
        if (epochApkChange[0] != 0 || epochApkChange[1] != 0) {
            _updateApk(epochApkChange, true);
        }

        delete queue[epoch];
        delete apkChangeQueue[epoch];
    }

    /// These should change to be called by the queue process functions vs register, deregister, and kick
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

    function _getNextEntryEpoch() internal view returns (uint256) {
        uint256 currentSlot = EpochLib.currentSlot(genesisTime, SLOT_DURATION);
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, SLOTS_PER_EPOCH);
        uint256 epochsNeeded = pendingEntries / MAX_CHURN_ENTRIES + 1;
        return currentEpoch + epochsNeeded;
    }

    function _getNextExitEpoch() internal view returns (uint256) {
        uint256 currentSlot = EpochLib.currentSlot(genesisTime, SLOT_DURATION);
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, SLOTS_PER_EPOCH);
        uint256 epochsNeeded = pendingExits / MAX_CHURN_EXITS + 1;
        return currentEpoch + epochsNeeded;
    }

    /// @notice Returns the epoch at which an operator was activated
    /// @param operatorId The ID of the operator
    /// @return The epoch at which the operator was activated, or 0 if never activated
    function getActivationEpoch(uint8 operatorId) external view returns (uint256) {
        return operators[operatorId].activationEpoch;
    }

    /// @notice Returns the epoch at which an operator was deactivated
    /// @param operatorId The ID of the operator
    /// @return The epoch at which the operator was deactivated, or 0 if never deactivated
    function getDeactivationEpoch(uint8 operatorId) external view returns (uint256) {
        return operators[operatorId].deactivationEpoch;
    }

    /// @notice Returns whether an operator is active based on their registration status and epochs
    /// @param operatorId The ID of the operator
    /// @return True if the operator is active, false otherwise
    function isActive(uint8 operatorId) external view returns (bool) {
        Operator memory operator = operators[operatorId];

        // Not registered
        if (!isRegistered(operatorId)) {
            return false;
        }

        uint256 currentSlot = EpochLib.currentSlot(genesisTime, SLOT_DURATION);
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, SLOTS_PER_EPOCH);

        // Check if after activation epoch
        if (operator.activationEpoch > currentEpoch) {
            return false;
        }

        // Check if before deactivation epoch (if set)
        if (operator.deactivationEpoch != 0 && operator.deactivationEpoch <= currentEpoch) {
            return false;
        }

        return true;
    }

}