// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test, Vm} from "forge-std/src/Test.sol";
import {Registry} from "../contracts/Registry.sol";
import {BLSWallet, BLSTestingLib} from "./utils/BLSTestingLib.sol";

contract RegistryTest is Test {
    struct Operator {
        Vm.Wallet wallet;
        BLSWallet blsWallet;
    }

    Registry public registry;
    Vm.Wallet public owner;
    Operator[10] public operators;
    uint256 constant NUM_OPERATORS = 10;

    function setUp() public {
        owner = vm.createWallet("owner");
        registry = new Registry(owner.addr);

        // Create wallets for each operator
        for (uint256 i = 0; i < NUM_OPERATORS; i++) {
            string memory label = vm.toString(i);
            operators[i].wallet = vm.createWallet(label);
            operators[i].blsWallet = BLSTestingLib.createWallet(label);
        }
    }

    function test_Register() public {
        vm.startPrank(operators[0].wallet.addr);
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);
        assertEq(registry.operatorIds(operators[0].wallet.addr), operatorId);
        assertTrue(registry.isRegistered(operatorId));
        vm.stopPrank();
    }

    function test_GetOperator() public {
        vm.startPrank(operators[0].wallet.addr);
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);

        (address registeredAddr, uint256[4] memory registeredKey) = registry.getOperator(operatorId);
        assertEq(registeredAddr, operators[0].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[0].blsWallet.publicKey))
        );
        vm.stopPrank();
    }

    function test_UpdateSigningKey() public {
        vm.startPrank(operators[0].wallet.addr);
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);

        uint256[4] memory newSigningKey = BLSTestingLib.createWallet("new-key").publicKey;
        registry.updateSigningKey(newSigningKey);

        (, uint256[4] memory updatedKey) = registry.getOperator(operatorId);
        assertEq(keccak256(abi.encode(updatedKey)), keccak256(abi.encode(newSigningKey)));
        vm.stopPrank();
    }

    function test_Deregister() public {
        vm.startPrank(operators[0].wallet.addr);
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);

        registry.deregister();
        assertFalse(registry.isRegistered(operatorId));
        vm.stopPrank();
    }

    function test_GetOperatorSigningKeys() public {
        uint8[] memory operatorIds = new uint8[](3);

        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(operators[i].wallet.addr);
            operatorIds[i] = registry.register(operators[i].blsWallet.publicKey);
            vm.stopPrank();
        }

        uint256[2] memory apk = registry.getOperatorsApk(operatorIds);

        uint256[] memory privateKeys = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            privateKeys[i] = operators[i].blsWallet.privateKey;
        }

        uint256[4] memory expectedApk = BLSTestingLib.getPublicKey(privateKeys);

        assertEq(
            keccak256(abi.encode(apk)), keccak256(abi.encode(expectedApk)), "APKs should match"
        );
    }

    function test_ReuseOperatorId() public {
        uint8[] memory operatorIds = new uint8[](5);

        for (uint256 i = 0; i < 5; i++) {
            vm.startPrank(operators[i].wallet.addr);
            operatorIds[i] = registry.register(operators[i].blsWallet.publicKey);
            vm.stopPrank();

            assertEq(operatorIds[i], i + 1);
        }

        vm.startPrank(operators[1].wallet.addr);
        registry.deregister();
        vm.stopPrank();

        assertFalse(registry.isRegistered(2));

        vm.startPrank(operators[5].wallet.addr);
        uint8 newOperatorId = registry.register(operators[5].blsWallet.publicKey);
        vm.stopPrank();

        assertEq(newOperatorId, 2);
        assertTrue(registry.isRegistered(2));

        (address registeredAddr, uint256[4] memory registeredKey) = registry.getOperator(2);
        assertEq(registeredAddr, operators[5].wallet.addr);
        assertEq(
            keccak256(abi.encode(registeredKey)),
            keccak256(abi.encode(operators[5].blsWallet.publicKey))
        );
    }

    function test_GetOperatorSigningKeys_NotRegistered() public {
        uint8[] memory operatorIds = new uint8[](1);
        operatorIds[0] = 1;

        vm.expectRevert(abi.encodeWithSelector(Registry.NotRegistered.selector, 1));
        registry.getOperatorsApk(operatorIds);
    }

    function test_Kick() public {
        vm.startPrank(operators[0].wallet.addr);
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);
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
        uint8 operatorId = registry.register(operators[0].blsWallet.publicKey);
        vm.stopPrank();

        vm.prank(operators[1].wallet.addr);
        vm.expectRevert();
        registry.kick(operatorId);

        assertTrue(registry.isRegistered(operatorId));
    }
}
