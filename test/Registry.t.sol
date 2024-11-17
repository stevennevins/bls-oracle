// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test, Vm} from "forge-std/src/Test.sol";
import {Registry} from "../contracts/Registry.sol";
import {BLSWallet, BLSTestingLib} from "./utils/BLSTestingLib.sol";
import {BLS} from "./utils/BLS.sol";
import {EpochLib} from "../contracts/EpochLib.sol";
import {console2 as console} from "forge-std/src/console2.sol";

contract RegistrySetup is Test {
    struct Operator {
        Vm.Wallet wallet;
        BLSWallet blsWallet;
    }

    Registry public registry;
    Vm.Wallet public owner;
    uint256 constant NUM_OPERATORS = 10;
    Operator[NUM_OPERATORS] public operators;

    function setUp() public virtual {
        owner = vm.createWallet("owner");
        registry = new Registry(owner.addr);

        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            string memory label = vm.toString(i);
            operators[i].wallet = vm.createWallet(label);
            operators[i].blsWallet = BLSTestingLib.createWallet(label);
        }
    }

    function logOperatorState(uint8 operatorId, string memory action) internal view {
        console.log("=== Operator State Change ===");
        console.log("Action:", action);
        console.log("Operator ID:", operatorId);

        if (registry.isRegistered(operatorId)) {
            (address registeredAddr, uint256[2] memory signingKey) =
                registry.getOperator(operatorId);
            console.log("Operator Address:", registeredAddr);
            console.log("Signing Key[0]:", signingKey[0]);
            console.log("Signing Key[1]:", signingKey[1]);
            console.log("Activation Epoch:", registry.getActivationEpoch(operatorId));
            console.log("Deactivation Epoch:", registry.getDeactivationEpoch(operatorId));
            console.log("Is Active:", registry.isActive(operatorId));
        } else {
            console.log("Operator not registered");
        }
        console.log("Current Bitmap:", registry.operatorBitmap());
        console.log("=========================");
    }

    function warpToNextEpoch() internal {
        warpEpochs(1);
    }

    function getCurrentEpoch() internal view returns (uint256) {
        uint256 currentSlot = EpochLib.currentSlot(registry.genesisTime(), registry.SLOT_DURATION());
        return EpochLib.slotToEpoch(currentSlot, registry.SLOTS_PER_EPOCH());
    }

    function warpEpochs(
        uint256 numEpochs
    ) internal {
        console.log("=== Warping Forward %s Epochs ===", numEpochs);
        console.log("Current Time:", block.timestamp);

        uint256 currentEpoch = getCurrentEpoch();

        console.log("Current Epoch:", currentEpoch);

        uint256 targetEpochStartSlot =
            EpochLib.epochStartSlot(currentEpoch + numEpochs, registry.SLOTS_PER_EPOCH());
        uint256 targetEpochStartTime = EpochLib.slotToTime(
            targetEpochStartSlot, registry.genesisTime(), registry.SLOT_DURATION()
        );

        console.log("Target Epoch:", currentEpoch + numEpochs);
        console.log("Warping to Time:", targetEpochStartTime);

        vm.warp(targetEpochStartTime);
    }

    function computePastEpochStartTime(
        uint256 numEpochsBack
    ) internal view returns (uint256) {
        console.log("=== Computing Start Time %s Epochs Back ===", numEpochsBack);
        console.log("Current Time:", block.timestamp);

        uint256 currentEpoch = getCurrentEpoch();

        require(currentEpoch >= numEpochsBack, "Cannot warp back before genesis");

        console.log("Current Epoch:", currentEpoch);
        console.log("Target Epoch:", currentEpoch - numEpochsBack);

        uint256 targetEpochStartSlot =
            EpochLib.epochStartSlot(currentEpoch - numEpochsBack, registry.SLOTS_PER_EPOCH());

        uint256 targetEpochStartTime = EpochLib.slotToTime(
            targetEpochStartSlot, registry.genesisTime(), registry.SLOT_DURATION()
        );

        console.log("Target Start Time:", targetEpochStartTime);

        return targetEpochStartTime;
    }

    function registerOperator(
        uint256 index
    ) internal returns (uint8 operatorId, uint256 effectiveEpoch) {
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[index].wallet.addr, operators[index].blsWallet.publicKeyG1
        );

        uint256[2] memory signature = BLSTestingLib.sign(
            operators[index].blsWallet.privateKey, registry.DOMAIN(), messageHash
        );

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[index].blsWallet.publicKey});

        vm.startPrank(operators[index].wallet.addr);
        (operatorId, effectiveEpoch) =
            registry.register(operators[index].blsWallet.publicKeyG1, proof);
        vm.stopPrank();
    }

    function deregisterOperator(
        uint256 index
    ) internal {
        uint8 operatorId = registry.operatorIds(operators[index].wallet.addr);

        vm.startPrank(operators[index].wallet.addr);
        registry.deregister();
        vm.stopPrank();
    }

    function updateOperatorSigningKey(uint256 index, string memory newKeyLabel) internal {
        operators[index].blsWallet = BLSTestingLib.createWallet(newKeyLabel);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[index].wallet.addr, operators[index].blsWallet.publicKeyG1
        );

        uint256[2] memory signature = BLSTestingLib.sign(
            operators[index].blsWallet.privateKey, registry.DOMAIN(), messageHash
        );

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[index].blsWallet.publicKey});

        vm.startPrank(operators[index].wallet.addr);
        registry.updateSigningKey(operators[index].blsWallet.publicKeyG1, proof);
        vm.stopPrank();
    }

    function getOperatorIds(
        uint256 count
    ) internal pure returns (uint8[] memory operatorIds) {
        operatorIds = new uint8[](count);
        for (uint256 i = 0; i < count; i++) {
            operatorIds[i] = uint8(i);
        }
    }
}

contract RegisterTest is RegistrySetup {
    function testRegister() public {
        (uint8 operatorId,) = registerOperator(0);

        assertEq(registry.operatorIds(operators[0].wallet.addr), operatorId);
        assertTrue(registry.isRegistered(operatorId));

        assertFalse(registry.isActive(operatorId));

        warpToNextEpoch();

        assertTrue(registry.isActive(operatorId));
    }

    function testMaxChurnRegistration() public {
        uint8[] memory operatorIds = new uint8[](5);
        uint256[] memory effectiveEpochs = new uint256[](5);

        for (uint256 i = 0; i < 5; i++) {
            (operatorIds[i], effectiveEpochs[i]) = registerOperator(i);
        }

        assertEq(effectiveEpochs[0], effectiveEpochs[1]);
        assertEq(effectiveEpochs[1], effectiveEpochs[2]);
        assertEq(effectiveEpochs[2], effectiveEpochs[3]);

        assertEq(effectiveEpochs[4], effectiveEpochs[0] + 1);
    }

    function testReuseOperatorId() public {
        (uint8 operatorId1,) = registerOperator(0);
        assertEq(operatorId1, 0);
        (uint8 operatorId2,) = registerOperator(1);
        assertEq(operatorId2, 1);

        // Process registration
        warpToNextEpoch();
        registry.processQueues();

        // Deregister second operator
        deregisterOperator(1);
        warpToNextEpoch();
        registry.processQueues();

        assertFalse(registry.isRegistered(1));

        // Register new operator and verify it reuses ID 1
        (uint8 newOperatorId,) = registerOperator(2);
        assertEq(newOperatorId, 1);

        // Process registration
        warpToNextEpoch();
        registry.processQueues();

        // Verify new operator details
        assertTrue(registry.isRegistered(1));
        (address registeredAddr,) = registry.getOperator(1);
        assertEq(registeredAddr, operators[2].wallet.addr);
    }

    function testRegisterWithInvalidSignature() public {
        // Create invalid signature by using wrong private key
        uint256 wrongPrivateKey = 123456789;
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );
        uint256[2] memory invalidSignature = BLSTestingLib.sign(
            wrongPrivateKey, registry.DOMAIN(), messageHash
        );
        Registry.Proof memory proof = Registry.Proof({
            signature: invalidSignature,
            pubkeyG2: operators[0].blsWallet.publicKey
        });

        vm.startPrank(operators[0].wallet.addr);
        vm.expectRevert(Registry.InvalidSignature.selector);
        registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();
    }

    function testRegisterDuplicateOperator() public {
        (uint8 operatorId,) = registerOperator(0);

        vm.startPrank(operators[0].wallet.addr);
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );
        uint256[2] memory signature = BLSTestingLib.sign(
            operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash
        );
        Registry.Proof memory proof = Registry.Proof({
            signature: signature,
            pubkeyG2: operators[0].blsWallet.publicKey
        });

        vm.expectRevert(abi.encodeWithSelector(Registry.AlreadyRegistered.selector, operatorId));
        registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();
    }

    function testRegisterWithZeroSigningKey() public {
        uint256[2] memory zeroKey = [uint256(0), uint256(0)];
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, zeroKey
        );
        uint256[2] memory signature = BLSTestingLib.sign(
            operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash
        );
        Registry.Proof memory proof = Registry.Proof({
            signature: signature,
            pubkeyG2: operators[0].blsWallet.publicKey
        });

        vm.startPrank(operators[0].wallet.addr);
        vm.expectRevert(Registry.InvalidSignature.selector);
        registry.register(zeroKey, proof);
        vm.stopPrank();
    }

    function testRegisterMultipleOperatorsInSameEpoch() public {
        (uint8 firstId,) = registerOperator(0);
        (uint8 secondId,) = registerOperator(1);
        (uint8 thirdId,) = registerOperator(2);

        assertFalse(registry.isActive(firstId));
        assertFalse(registry.isActive(secondId));
        assertFalse(registry.isActive(thirdId));

        assertTrue(registry.isRegistered(firstId));
        assertTrue(registry.isRegistered(secondId));
        assertTrue(registry.isRegistered(secondId));

        assertEq(registry.pendingEntries(), 3);

        warpToNextEpoch();
        registry.processQueues();

        assertTrue(registry.isActive(firstId));
        assertTrue(registry.isActive(secondId));
        assertTrue(registry.isActive(thirdId));

        assertEq(registry.pendingEntries(), 0);
    }

    function testRegisterOperatorActivationEpoch() public {
        (uint8 firstId,) = registerOperator(0);
        uint256 firstEpoch = registry.getActivationEpoch(firstId);
        uint256 currentEpoch = EpochLib.currentEpoch(
            registry.genesisTime(),
            registry.SLOT_DURATION(),
            registry.SLOTS_PER_EPOCH()
        );
        assertEq(firstEpoch, currentEpoch + 1);

        // Register enough operators to fill first epoch's queue
        for (uint256 i = 1; i < registry.MAX_CHURN_ENTRIES(); i++) {
            registerOperator(i);
        }

        // Next operator should be scheduled for following epoch
        (uint8 nextId,) = registerOperator(registry.MAX_CHURN_ENTRIES());
        uint256 nextEpoch = registry.getActivationEpoch(nextId);
        assertEq(nextEpoch, currentEpoch + 2);

        warpToNextEpoch();
        registry.processQueues();

        // Verify first batch is active
        for (uint256 i = 0; i < registry.MAX_CHURN_ENTRIES(); i++) {
            assertTrue(registry.isActive(uint8(i)));
        }

        // Verify next operator is still pending
        assertFalse(registry.isActive(nextId));

        warpToNextEpoch();
        registry.processQueues();

        assertTrue(registry.isActive(nextId));
    }

    function testRegisterUpdatesNextOperatorIdCorrectly() public {
        assertEq(registry.nextOperatorId(), 0);

        (uint8 firstId,) = registerOperator(0);
        assertEq(firstId, 0);
        assertEq(registry.nextOperatorId(), 1);

        (uint8 secondId,) = registerOperator(1);
        assertEq(secondId, 1);
        assertEq(registry.nextOperatorId(), 2);

        deregisterOperator(0);

        (uint8 thirdId,) = registerOperator(2);
        assertEq(thirdId, 0); // Should reuse ID 0
        assertEq(registry.nextOperatorId(), 2); // Should not increment since reusing ID
    }

    function testRegisterUpdatesOperatorMappingsCorrectly() public {
        (uint8 operatorId,) = registerOperator(0);

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(operatorId);
        assertEq(registeredAddr, operators[0].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKeyG1))
        );

        assertEq(registry.operatorIds(operators[0].wallet.addr), operatorId);
        assertTrue(registry.registeredOperators(operatorId));
        assertEq(registry.getActivationEpoch(operatorId), 1);
        assertEq(registry.getDeactivationEpoch(operatorId), 0);

        // Process queues and check operator becomes active
        warpToNextEpoch();
        registry.processQueues();
        assertTrue(registry.isActive(operatorId));
    }

    function testRegisterWithMaxActiveOperatorsReached() public {
        // Check MAX_ACTIVE_OPERATORS is enforced
    }
}

contract GetOperatorTest is RegistrySetup {
    function testGetOperator() public {
        (uint8 operatorId,) = registerOperator(0);

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(operatorId);
        assertEq(registeredAddr, operators[0].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKeyG1))
        );
    }

    function testGetOperatorRevertsForNonExistentId() public {
        // Test getting operator with ID that has never been registered
    }

    function testGetOperatorRevertsForInactiveId() public {
        // Test getting operator after their id is inactive
    }

    function testGetOperatorRevertsWhenQueueNeedsProcessing() public {
        // Test getting operator when queue needs processing
    }

    function testGetOperatorForOperatorWithPendingEntry() public {
        // Test getting operator info while they are in entry queue but not yet active
    }

    function testGetOperatorForOperatorWithPendingExit() public {
        // Test getting operator info while they are in exit queue but still active
    }
}

contract UpdateSigningKeyTest is RegistrySetup {
    function testUpdateSigningKey() public {
        (uint8 operatorId,) = registerOperator(0);

        updateOperatorSigningKey(0, "new-key");

        warpToNextEpoch();
        registry.processQueues();

        (, uint256[2] memory updatedKey) = registry.getOperator(operatorId);
        assertEq(
            keccak256(abi.encode(updatedKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKeyG1))
        );
    }

    function testUpdateSigningKeyNotRegistered() public {
        // Test updating signing key for an unregistered operator
    }

    function testUpdateSigningKeyInvalidSignature() public {
        // Test updating signing key with invalid BLS signature
    }

    function testUpdateSigningKeyQueueProcessing() public {
        // Test that key update is properly queued and processed at next epoch
    }

    function testUpdateSigningKeyUpdatesApk() public {
        // Test that APK is properly updated with new key after processing
    }

    function testUpdateSigningKeyMultipleUpdatesInSameEpoch() public {
        // Test behavior when multiple key updates are queued in same epoch
    }

    function testUpdateSigningKeyPendingExit() public {
        // Test updating key for operator with pending exit
    }

    function testUpdateSigningKeyZeroKey() public {
        // Test updating to zero signing key
    }

    function testUpdateSigningKeyDuplicateKey() public {
        // Test updating to a signing key already in use by another operator
    }
}

contract DeregisterTest is RegistrySetup {
    function testDeregister() public {
        (uint8 operatorId,) = registerOperator(0);

        deregisterOperator(0);

        assertFalse(registry.isRegistered(operatorId));
    }

    function testDeregisterNotRegistered() public {
        // Test deregistering an operator that is not registered
    }

    function testDeregisterQueueProcessing() public {
        // Test that deregistering properly queues the exit and processes it
    }

    function testDeregisterUpdatesApk() public {
        // Test that APK is properly updated after deregistration is processed
    }

    function testDeregisterOperatorBitmap() public {
        // Test that operator bitmap is properly updated after deregistration is processed
    }

    function testDeregisterReusableId() public {
        // Test that deregistered operator ID can be reused for new registration
    }

    function testDeregisterPendingExits() public {
        // Test that pendingExits counter is properly incremented
    }

    function testDeregisterEffectiveEpoch() public {
        // Test that deregistration takes effect at correct epoch based on churn limit
    }
}

contract GetOperatorsApkTest is RegistrySetup {
    function testGetOperatorSigningKeys() public {
        for (uint256 i = 0; i < 4; i++) {
            registerOperator(i);
        }

        warpToNextEpoch();
        registry.processQueues();

        uint8[] memory operatorIds = getOperatorIds(3);
        uint256[2] memory apk = registry.getOperatorsApk(operatorIds);

        uint256[] memory privateKeys = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            privateKeys[i] = operators[i].blsWallet.privateKey;
        }

        uint256[2] memory expectedApk = BLSTestingLib.getPublicKeyG1(privateKeys[0]);
        for (uint256 i = 1; i < privateKeys.length; i++) {
            uint256[2] memory nextKey = BLSTestingLib.getPublicKeyG1(privateKeys[i]);
            expectedApk = BLS.aggregate(expectedApk, nextKey);
        }

        assertEq(keccak256(abi.encode(apk)), keccak256(abi.encode(expectedApk)));
    }

    function testGetOperatorSigningKeysNotRegistered() public {
        uint8[] memory operatorIds = new uint8[](1);
        operatorIds[0] = 1;
        uint256 currentEpoch = getCurrentEpoch();
        console.log("Current Epoch:", currentEpoch);

        vm.expectRevert(abi.encodeWithSelector(Registry.NotActive.selector, 1));
        registry.getOperatorsApk(operatorIds);
    }

    function testGetOperatorsApkEmptyArray() public {
        uint8[] memory emptyIds = new uint8[](0);
        vm.expectRevert("No operator IDs provided");
        registry.getOperatorsApk(emptyIds);
    }

    function testGetOperatorsApkQueueNeedsProcessing() public {
    }

    function testGetOperatorsApkDuplicateOperators() public {
        (uint8 operatorId1,) = registerOperator(0);
        (uint8 operatorId2,) = registerOperator(1);

        warpToNextEpoch();
        registry.processQueues();

        uint8[] memory operatorIds = new uint8[](3);
        operatorIds[0] = operatorId1;
        operatorIds[1] = operatorId2;
        operatorIds[2] = operatorId2; // Duplicate

        vm.expectRevert("Operator IDs must be sorted and unique");
        registry.getOperatorsApk(operatorIds);
    }

    function testGetOperatorsApkDeactivatedOperators() public {
        (uint8 operatorId1,) = registerOperator(0);
        (uint8 operatorId2,) = registerOperator(1);

        warpToNextEpoch();
        registry.processQueues();

        /// TODO: Need to handle register/deregistering in the same epoch
        vm.prank(operators[0].wallet.addr);
        registry.deregister();

        uint8[] memory operatorIds = new uint8[](2);
        operatorIds[0] = operatorId1;
        operatorIds[1] = operatorId2;

        /// Doesn't revert until after we warp to next epoch
        registry.getOperatorsApk(operatorIds);

        warpToNextEpoch();
        registry.processQueues();

        vm.expectRevert(abi.encodeWithSelector(Registry.NotActive.selector, operatorId1));
        registry.getOperatorsApk(operatorIds);
    }

    function testGetOperatorsApkWithPendingKeyUpdates() public {
        (uint8 operatorId,) = registerOperator(0);

        warpToNextEpoch();
        registry.processQueues();

        uint256[2] memory originalKey = operators[0].blsWallet.publicKeyG1;

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );
        uint256[2] memory signature = BLSTestingLib.sign(
            operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash
        );
        Registry.Proof memory proof = Registry.Proof({
            signature: signature,
            pubkeyG2: operators[0].blsWallet.publicKey
        });

        vm.prank(operators[0].wallet.addr);
        registry.updateSigningKey(operators[0].blsWallet.publicKeyG1, proof);

        uint8[] memory operatorIds = new uint8[](1);
        operatorIds[0] = operatorId;

        uint256[2] memory apk = registry.getOperatorsApk(operatorIds);
        assertEq(apk[0], originalKey[0]);
        assertEq(apk[1], originalKey[1]);
    }

    // TODO: Need to handle the case where update signing key and deregister happen in the same block and when both are queued in both orders

}

contract KickTest is RegistrySetup {
    function testKick() public {
        (uint8 operatorId,) = registerOperator(0);

        assertTrue(registry.isRegistered(operatorId));

        vm.prank(owner.addr);
        registry.kick(operatorId);

        assertFalse(registry.isRegistered(operatorId));
    }

    function testKickNotRegistered() public {
        uint8 operatorId = 1;

        vm.prank(owner.addr);
        vm.expectRevert();
        registry.kick(operatorId);
    }

    function testKickNotOwner() public {
        (uint8 operatorId,) = registerOperator(0);

        vm.prank(operators[1].wallet.addr);
        vm.expectRevert();
        registry.kick(operatorId);

        assertTrue(registry.isRegistered(operatorId));
    }

    function testKickUpdatesApkAndBitmap() public {
        (uint8 operatorId,) = registerOperator(0);

        warpToNextEpoch();
        registry.processQueues();

        uint256[2] memory initialApk = registry.apk();
        uint256 initialBitmap = registry.operatorBitmap();

        assertTrue((initialBitmap & (1 << operatorId)) == 1);

        vm.prank(owner.addr);
        registry.kick(operatorId);

        uint256[2] memory finalApk = registry.apk();
        uint256 finalBitmap = registry.operatorBitmap();

        assertFalse(finalApk[0] == initialApk[0]);
        assertFalse(finalApk[1] == initialApk[1]);

        assertTrue((finalBitmap & (1 << operatorId)) == 0);
    }

    function testKickClearsOperatorData() public {
        (uint8 operatorId,) = registerOperator(0);

        (address initialOperator, ) = registry.getOperator(operatorId);

        vm.prank(owner.addr);
        registry.kick(operatorId);

        vm.expectRevert(abi.encodeWithSelector(Registry.NotRegistered.selector, operatorId));
        registry.getOperator(operatorId);

        assertFalse(registry.registeredOperators(operatorId));
        assertEq(registry.operatorIds(initialOperator), 0);
    }

    function testKickWithPendingQueueEntries() public {
        /// TODO: Need to handle queue signing key changes and queued deregistrations
    }
}
