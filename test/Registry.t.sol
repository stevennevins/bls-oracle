// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test, Vm} from "forge-std/src/Test.sol";
import {Registry} from "../contracts/Registry.sol";
import {BLSWallet, BLSTestingLib} from "./utils/BLSTestingLib.sol";
import {BLS} from "./utils/BLS.sol";
import {EpochLib} from "../contracts/EpochLib.sol";
import {console2 as console} from "forge-std/src/Test.sol";

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

        // Create wallets for each operator
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            string memory label = vm.toString(i);
            operators[i].wallet = vm.createWallet(label);
            operators[i].blsWallet = BLSTestingLib.createWallet(label);
        }
    }

    function warpToNextEpoch() internal {
        uint256 currentSlot = EpochLib.currentSlot(block.timestamp, registry.SLOT_DURATION());
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, registry.SLOTS_PER_EPOCH());
        uint256 nextEpochStartSlot =
            EpochLib.epochStartSlot(currentEpoch + 1, registry.SLOTS_PER_EPOCH());
        uint256 nextEpochStartTime =
            EpochLib.slotToTime(nextEpochStartSlot, block.timestamp, registry.SLOT_DURATION());
        vm.warp(nextEpochStartTime);
    }
}

contract RegisterTest is RegistrySetup {
    function test_Register() public {
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        vm.prank(operators[0].wallet.addr);
        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);
        assertEq(registry.operatorIds(operators[0].wallet.addr), operatorId);
        assertTrue(registry.isRegistered(operatorId));

        (address operator, uint256[2] memory signingKey) = registry.getOperator(operatorId);
        uint256 activationEpoch = registry.getActivationEpoch(operatorId);

        // Check operator is not active before epoch
        assertFalse(registry.isActive(operatorId));

        // Warp to next epoch
        warpToNextEpoch();

        // Check operator is now active
        assertTrue(registry.isActive(operatorId));
    }

    function test_MaxChurnRegistration() public {
        // Register MAX_CHURN_ENTRIES operators
        uint8[] memory operatorIds = new uint8[](5);
        uint256[] memory effectiveEpochs = new uint256[](5);

        for (uint256 i = 0; i < 5; i++) {
            vm.startPrank(operators[i].wallet.addr);

            bytes32 messageHash = registry.calculateRegistrationHash(
                operators[i].wallet.addr, operators[i].blsWallet.publicKeyG1
            );

            uint256[2] memory signature = BLSTestingLib.sign(
                operators[i].blsWallet.privateKey, registry.DOMAIN(), messageHash
            );

            Registry.Proof memory proof =
                Registry.Proof({signature: signature, pubkeyG2: operators[i].blsWallet.publicKey});

            (operatorIds[i], effectiveEpochs[i]) =
                registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();
        }

        // First 4 operators should have same activation epoch
        assertEq(effectiveEpochs[0], effectiveEpochs[1]);
        assertEq(effectiveEpochs[1], effectiveEpochs[2]);
        assertEq(effectiveEpochs[2], effectiveEpochs[3]);

        // 5th operator should have activation epoch 1 greater
        assertEq(effectiveEpochs[4], effectiveEpochs[0] + 1);
    }

    function test_ReuseOperatorId() public {
        uint8[] memory operatorIds = new uint8[](5);

        for (uint256 i = 0; i < 4; i++) {
            vm.startPrank(operators[i].wallet.addr);

            bytes32 messageHash = registry.calculateRegistrationHash(
                operators[i].wallet.addr, operators[i].blsWallet.publicKeyG1
            );

            uint256[2] memory signature = BLSTestingLib.sign(
                operators[i].blsWallet.privateKey, registry.DOMAIN(), messageHash
            );

            Registry.Proof memory proof =
                Registry.Proof({signature: signature, pubkeyG2: operators[i].blsWallet.publicKey});

            (operatorIds[i],) = registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();

            assertEq(operatorIds[i], i);
        }

        warpToNextEpoch();

        vm.startPrank(operators[1].wallet.addr);
        registry.deregister();
        vm.stopPrank();

        warpToNextEpoch();

        assertFalse(registry.isRegistered(1));

        vm.startPrank(operators[4].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[4].wallet.addr, operators[4].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[4].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[4].blsWallet.publicKey});

        (uint8 newOperatorId, uint256 effectiveEpoch) =
            registry.register(operators[4].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        warpToNextEpoch();

        console.log("Effective epoch: %s", effectiveEpoch);

        assertEq(newOperatorId, 1);
        assertTrue(registry.isRegistered(1));
        assertEq(
            registry.getDeactivationEpoch(1),
            0,
            "Deactivation epoch should be reset for new operator"
        );
        assertTrue(registry.isActive(1));

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(1);
        assertEq(registeredAddr, operators[4].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[4].blsWallet.publicKeyG1))
        );
    }
}

contract GetOperatorTest is RegistrySetup {
    function test_GetOperator() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(operatorId);
        assertEq(registeredAddr, operators[0].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKeyG1))
        );
        vm.stopPrank();
    }
}

contract UpdateSigningKeyTest is RegistrySetup {
    function test_UpdateSigningKey() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);

        operators[0].blsWallet = BLSTestingLib.createWallet("new-key");

        messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory updateProof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        registry.updateSigningKey(operators[0].blsWallet.publicKeyG1, updateProof);

        (, uint256[2] memory updatedKey) = registry.getOperator(operatorId);
        assertEq(
            keccak256(abi.encode(updatedKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKeyG1))
        );
        vm.stopPrank();
    }
}

contract DeregisterTest is RegistrySetup {
    function test_Deregister() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);

        registry.deregister();
        assertFalse(registry.isRegistered(operatorId));
        vm.stopPrank();
    }
}

contract GetOperatorsApkTest is RegistrySetup {
    function test_GetOperatorSigningKeys() public {
        for (uint256 i = 0; i < 4; i++) {
            vm.startPrank(operators[i].wallet.addr);

            bytes32 messageHash = registry.calculateRegistrationHash(
                operators[i].wallet.addr, operators[i].blsWallet.publicKeyG1
            );

            uint256[2] memory signature = BLSTestingLib.sign(
                operators[i].blsWallet.privateKey, registry.DOMAIN(), messageHash
            );

            Registry.Proof memory proof =
                Registry.Proof({signature: signature, pubkeyG2: operators[i].blsWallet.publicKey});

            registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();
        }
        uint8[] memory operatorIds = new uint8[](3);
        for (uint256 i = 0; i < 3; i++) {
            operatorIds[i] = uint8(i);
        }

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

        assertEq(
            keccak256(abi.encode(apk)), keccak256(abi.encode(expectedApk)), "APKs should match"
        );
    }

    function test_GetOperatorSigningKeys_NotRegistered() public {
        uint8[] memory operatorIds = new uint8[](1);
        operatorIds[0] = 1;

        vm.expectRevert(abi.encodeWithSelector(Registry.NotRegistered.selector, 1));
        registry.getOperatorsApk(operatorIds);
    }
}

contract KickTest is RegistrySetup {
    function test_Kick() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        assertTrue(registry.isRegistered(operatorId));

        vm.prank(owner.addr);
        registry.kick(operatorId);

        assertFalse(registry.isRegistered(operatorId));
    }

    function test_Kick_NotRegistered() public {
        uint8 operatorId = 1;

        vm.prank(owner.addr);
        vm.expectRevert();
        registry.kick(operatorId);
    }

    function test_Kick_NotOwner() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        (uint8 operatorId, uint256 effectiveEpoch) =
            registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        vm.prank(operators[1].wallet.addr);
        vm.expectRevert();
        registry.kick(operatorId);

        assertTrue(registry.isRegistered(operatorId));
    }
}
