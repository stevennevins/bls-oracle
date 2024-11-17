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

    function warpEpochs(
        uint256 numEpochs
    ) internal {
        console.log("=== Warping Forward %s Epochs ===", numEpochs);
        console.log("Current Time:", block.timestamp);

        uint256 currentSlot = EpochLib.currentSlot(registry.genesisTime(), registry.SLOT_DURATION());
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, registry.SLOTS_PER_EPOCH());

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

        uint256 currentSlot = EpochLib.currentSlot(registry.genesisTime(), registry.SLOT_DURATION());
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, registry.SLOTS_PER_EPOCH());

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
        uint8[] memory operatorIds = new uint8[](5);

        for (uint256 i = 0; i < 4; i++) {
            (operatorIds[i],) = registerOperator(i);
            assertEq(operatorIds[i], i);
        }

        warpToNextEpoch();

        deregisterOperator(1);

        warpToNextEpoch();

        assertFalse(registry.isRegistered(1));

        (uint8 newOperatorId,) = registerOperator(4);

        warpToNextEpoch();

        assertEq(newOperatorId, 1);
        assertTrue(registry.isRegistered(1));
        assertEq(registry.getDeactivationEpoch(1), 0);

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(1);
        assertEq(registeredAddr, operators[4].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[4].blsWallet.publicKeyG1))
        );
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
}

contract DeregisterTest is RegistrySetup {
    function testDeregister() public {
        (uint8 operatorId,) = registerOperator(0);

        deregisterOperator(0);

        assertFalse(registry.isRegistered(operatorId));
    }
}

contract GetOperatorsApkTest is RegistrySetup {
    function testGetOperatorSigningKeys() public {
        for (uint256 i = 0; i < 4; i++) {
            registerOperator(i);
        }

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

        vm.expectRevert(abi.encodeWithSelector(Registry.NotRegistered.selector, 1));
        registry.getOperatorsApk(operatorIds);
    }
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
}
