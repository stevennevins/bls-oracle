// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test, Vm} from "forge-std/src/Test.sol";
import {Registry} from "../contracts/Registry.sol";
import {BLSWallet, BLSTestingLib} from "./utils/BLSTestingLib.sol";
import {BLS} from "./utils/BLS.sol";
import {EpochLib} from "../contracts/EpochLib.sol";

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
        uint256 currentSlot = EpochLib.currentSlot(registry.genesisTime(), registry.SLOT_DURATION());
        uint256 currentEpoch = EpochLib.slotToEpoch(currentSlot, registry.SLOTS_PER_EPOCH());
        uint256 nextEpochStartSlot =
            EpochLib.epochStartSlot(currentEpoch + 1, registry.SLOTS_PER_EPOCH());
        uint256 nextEpochStartTime = EpochLib.slotToTime(
            nextEpochStartSlot, registry.genesisTime(), registry.SLOT_DURATION()
        );
        vm.warp(nextEpochStartTime);
    }
}

contract RegisterTest is RegistrySetup {
    function test_Register() public {
        vm.startPrank(operators[0].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);

        assertEq(registry.operatorIds(operators[0].wallet.addr), operatorId);
        assertTrue(registry.isRegistered(operatorId));
        vm.stopPrank();
    }

    function test_ReuseOperatorId() public {
        uint8[] memory operatorIds = new uint8[](5);

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

            operatorIds[i] = registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();

            assertEq(operatorIds[i], i);
        }

        vm.startPrank(operators[1].wallet.addr);
        registry.deregister();
        vm.stopPrank();

        assertFalse(registry.isRegistered(1));

        vm.startPrank(operators[5].wallet.addr);

        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[5].wallet.addr, operators[5].blsWallet.publicKeyG1
        );

        uint256[2] memory signature =
            BLSTestingLib.sign(operators[5].blsWallet.privateKey, registry.DOMAIN(), messageHash);

        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[5].blsWallet.publicKey});

        uint8 newOperatorId = registry.register(operators[5].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        assertEq(newOperatorId, 1);
        assertTrue(registry.isRegistered(1));

        (address registeredAddr, uint256[2] memory registeredKey) = registry.getOperator(1);
        assertEq(registeredAddr, operators[5].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[5].blsWallet.publicKeyG1))
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

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);

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

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);

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

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);

        registry.deregister();
        assertFalse(registry.isRegistered(operatorId));
        vm.stopPrank();
    }
}

contract GetOperatorsApkTest is RegistrySetup {
    function test_GetOperatorSigningKeys() public {
        uint8[] memory operatorIds = new uint8[](3);

        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(operators[i].wallet.addr);

            bytes32 messageHash = registry.calculateRegistrationHash(
                operators[i].wallet.addr, operators[i].blsWallet.publicKeyG1
            );

            uint256[2] memory signature = BLSTestingLib.sign(
                operators[i].blsWallet.privateKey, registry.DOMAIN(), messageHash
            );

            Registry.Proof memory proof =
                Registry.Proof({signature: signature, pubkeyG2: operators[i].blsWallet.publicKey});

            operatorIds[i] = registry.register(operators[i].blsWallet.publicKeyG1, proof);
            vm.stopPrank();
        }

        uint256[2] memory apk = registry.getOperatorsApk(operatorIds);

        uint256[] memory privateKeys = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            privateKeys[i] = operators[i].blsWallet.privateKey;
        }

        uint256[2] memory expectedApk = BLSTestingLib.getPublicKeyG1(privateKeys[0]);
        for (uint256 i = 0; i < privateKeys.length; i++) {
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

contract ApkTest is RegistrySetup {
    function test_ApkCorrectness() public {
        // Register first operator
        vm.startPrank(operators[0].wallet.addr);
        bytes32 messageHash = registry.calculateRegistrationHash(
            operators[0].wallet.addr, operators[0].blsWallet.publicKeyG1
        );
        uint256[2] memory signature =
            BLSTestingLib.sign(operators[0].blsWallet.privateKey, registry.DOMAIN(), messageHash);
        Registry.Proof memory proof =
            Registry.Proof({signature: signature, pubkeyG2: operators[0].blsWallet.publicKey});
        uint8 operatorId1 = registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        // Verify APK equals first operator's key
        uint256[2] memory expectedApk = operators[0].blsWallet.publicKeyG1;
        uint256[2] memory currentApk = registry.apk();
        assertEq(currentApk[0], expectedApk[0]);
        assertEq(currentApk[1], expectedApk[1]);

        // Register second operator
        vm.startPrank(operators[1].wallet.addr);
        messageHash = registry.calculateRegistrationHash(
            operators[1].wallet.addr, operators[1].blsWallet.publicKeyG1
        );
        signature =
            BLSTestingLib.sign(operators[1].blsWallet.privateKey, registry.DOMAIN(), messageHash);
        proof = Registry.Proof({signature: signature, pubkeyG2: operators[1].blsWallet.publicKey});
        uint8 operatorId2 = registry.register(operators[1].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        // Verify APK equals aggregate of both keys
        expectedApk =
            BLS.aggregate(operators[0].blsWallet.publicKeyG1, operators[1].blsWallet.publicKeyG1);
        currentApk = registry.apk();
        assertEq(currentApk[0], expectedApk[0]);
        assertEq(currentApk[1], expectedApk[1]);

        // Update first operator's key
        vm.startPrank(operators[0].wallet.addr);
        uint256[2] memory newKey = operators[2].blsWallet.publicKeyG1; // TODO: Prevent this reusue of keys. Hack for now
        messageHash = registry.calculateRegistrationHash(operators[0].wallet.addr, newKey);
        signature =
            BLSTestingLib.sign(operators[2].blsWallet.privateKey, registry.DOMAIN(), messageHash);
        proof = Registry.Proof({signature: signature, pubkeyG2: operators[2].blsWallet.publicKey});
        registry.updateSigningKey(newKey, proof);
        vm.stopPrank();

        // Verify APK equals aggregate of updated key and second operator's key
        expectedApk = BLS.aggregate(newKey, operators[1].blsWallet.publicKeyG1);
        currentApk = registry.apk();
        assertEq(currentApk[0], expectedApk[0]);
        assertEq(currentApk[1], expectedApk[1]);

        // Deregister second operator
        vm.startPrank(operators[1].wallet.addr);
        registry.deregister();
        vm.stopPrank();

        // Verify APK equals only the first operator's updated key
        expectedApk = newKey;
        currentApk = registry.apk();
        assertEq(currentApk[0], expectedApk[0]);
        assertEq(currentApk[1], expectedApk[1]);
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

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);
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

        uint8 operatorId = registry.register(operators[0].blsWallet.publicKeyG1, proof);
        vm.stopPrank();

        vm.prank(operators[1].wallet.addr);
        vm.expectRevert();
        registry.kick(operatorId);

        assertTrue(registry.isRegistered(operatorId));
    }
}
