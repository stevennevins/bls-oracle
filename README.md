# A BN254 Testing Library for the rest of us

This library provides tools to facilitate testing BLS signatures on the BN254 curve within a foundry testing environment for smart contracts. Built upon [Kevin Charm's BLS BN254 implementation](https://github.com/kevincharm/bls-bn254).

## What is this?

This library helps you test BLS signature operations in Solidity smart contracts. It provides a simple interface by wrapping a TypeScript CLI that handles the complex cryptographic operations.

### Key Features

- Generate BLS public keys from private keys
- Sign messages and verify signatures (single and aggregated)
- Hash messages to curve points with domain separation
- Full testing utilities for BLS operations on BN254 curve

### How it Works

The library uses Foundry's FFI (Foreign Function Interface) to bridge Solidity contract interactions with the TypeScript CLI.

Install dependencies

```bash
npm install
```

Compile typescript

```bash
tsc
```

Test contracts

```bash
forge test
```

## Solidity API

### Library Overview

#### Struct BLSWallet

A struct that represents a BLS wallet containing a private key and public key.

 ```solidity
struct BLSWallet {
    uint256 privateKey;
    uint256[4] publicKey;
}
```

#### Functions

Generates a BLS wallet with a public key and private key from seed.

```solidity
function createWallet(string memory seed) returns (BLSWallet memory)
```

Generates a BLS public key from a private key.

```solidity
function getPublicKey(uint256 privateKey) returns (uint256[4])
```

Generates an aggregated BLS public key from multiple private keys.

```solidity
function getPublicKey(uint256[] privateKeys) returns (uint256[4])
```

Signs a message with a private key using domain separation.

```solidity
function sign(uint256 privateKey, string domain, string message) returns (uint256[2])
```

Signs a bytes32 message with a private key using domain separation.

```solidity
function sign(uint256 privateKey, string domain, bytes32 message) returns (uint256[2])
```

Creates an aggregated signature from multiple private keys using domain separation.

```solidity
function sign(uint256[] privateKeys, string domain, string message) returns (uint256[2])
```

Creates an aggregated signature from multiple private keys for a bytes32 message using domain separation.

```solidity
function sign(uint256[] privateKeys, string domain, bytes32 message) returns (uint256[2])
```

Hashes a message to a curve point using domain separation.

```solidity
function hashToPoint(string domain, string message) returns (uint256[2])
```

Hashes a bytes32 message to a curve point using domain separation.

```solidity
function hashToPoint(string domain, bytes32 message) returns (uint256[2])
```

### BLS

Verifies a single BLS signature.

```solidity
function verifySingle(uint256[2] signature, uint256[4] pubkey, uint256[2] message) returns (bool, bool)
```

Verifies multiple BLS signatures.

```solidity
function verifyMultiple(uint256[2][] signatures, uint256[4][] pubKeys, uint256[2][] messages) returns (bool, bool)
```

## Typescript CLI Commands

The library provides the following CLI commands:

- `get-pubkey`: Generate a BLS public key from a private key
- `get-agg-pubkey`: Generate an aggregated public key
- `hash`: Hash a message to a curve point
- `sign`: Sign a message with a private key
- `sign-agg`: Create an aggregated signature

## Solidity usage examples

### Basic Usage Examples

#### Generating a Public Key

```solidity
uint256 privateKey = uint256(0x1234);
uint256[4] memory pubKey = BLSTestingLib.getPublicKey(privateKey);
```

#### Generating an Aggregated Public Key

```solidity
uint256[] memory privateKeys = new uint256[](2);
privateKeys[0] = uint256(0x1234);
privateKeys[1] = uint256(0x5678);
uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);
```

#### Signing a Message

```solidity
uint256 privateKey = uint256(0x1234);
string memory domain = "domain-message";
string memory message = "message";
uint256[2] memory sig = BLSTestingLib.sign(privateKey, domain, message);
```

#### Signing a Bytes32 Message

```solidity
uint256 privateKey = uint256(0x1234);
string memory domain = "domain-message";
bytes32 message = bytes32(uint256(0x1234567890));
uint256[2] memory sig = BLSTestingLib.sign(privateKey, domain, message);
```

#### Creating an Aggregated Signature

```solidity
uint256[] memory privateKeys = new uint256[](2);
privateKeys[0] = uint256(0x1234);
privateKeys[1] = uint256(0x5678);
string memory domain = "domain-message";
string memory message = "message";
uint256[2] memory aggregatedSig = BLSTestingLib.sign(privateKeys, domain, message);
```

#### Hashing a Message to a Curve Point

```solidity
string memory domain = "domain-message";
string memory message = "message";
uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);
```

### End to End Usage Examples verifying with the pairing check precompile

#### Verifying a Single Signature

```solidity
uint256 privateKey = uint256(0x1234);
string memory domain = "domain-message";
string memory message = "message";
uint256[4] memory pubKey = BLSTestingLib.getPublicKey(privateKey);
uint256[2] memory sig = BLSTestingLib.sign(privateKey, domain, message);
uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);
(bool pairingSuccess, bool callSuccess) = bls.verifySingle(sig, pubKey, messagePoint);
require(callSuccess, "Precompile call failed");
require(pairingSuccess, "Pairing check failed");
```

#### Verifying an Aggregated Signature

```solidity
uint256[] memory privateKeys = new uint256[](2);
privateKeys[0] = uint256(0x1234);
privateKeys[1] = uint256(0x5678);
string memory domain = "domain-message";
string memory message = "message";

uint256[4] memory aggregatedPubKey = BLSTestingLib.getPublicKey(privateKeys);
uint256[2] memory aggregatedSig = BLSTestingLib.sign(privateKeys, domain, message);
uint256[2] memory messagePoint = BLSTestingLib.hashToPoint(domain, message);

(bool pairingSuccess, bool callSuccess) = bls.verifySingle(aggregatedSig, aggregatedPubKey, messagePoint);
require(callSuccess, "Precompile call failed");
require(pairingSuccess, "Pairing check failed");
```

#### Verifying Multiple Signatures for unique messages

```solidity
uint256[] memory privateKeys = new uint256[](2);
privateKeys[0] = uint256(0x1234);
privateKeys[1] = uint256(0x5678);
string[] memory messages = new string[](2);
messages[0] = "message-1";
messages[1] = "message-2";
uint256[2][] memory sigs = new uint256[2][](2);
uint256[4][] memory pubKeys = new uint256[4][](2);
uint256[2][] memory messagePoints = new uint256[2][](2);
for (uint256 i = 0; i < privateKeys.length; i++) {
    pubKeys[i] = BLSTestingLib.getPublicKey(privateKeys[i]);
    sigs[i] = BLSTestingLib.sign(privateKeys[i], domain, messages[i]);
    messagePoints[i] = BLSTestingLib.hashToPoint(domain, messages[i]);
}
(bool pairingSuccess, bool callSuccess) = bls.verifyBatch(sigs, pubKeys, messagePoints);
require(callSuccess, "Precompile call failed");
require(pairingSuccess, "Batch pairing check failed");
```

#### Verify Multiple Signatures for unique messages with mixed aggregation

```solidity
BLSWallet memory wallet1 = BLSTestingLib.createWallet("wallet-1");
BLSWallet memory wallet2 = BLSTestingLib.createWallet("wallet-2"); 
BLSWallet memory wallet3 = BLSTestingLib.createWallet("wallet-3");
BLSWallet memory wallet4 = BLSTestingLib.createWallet("wallet-4");

string memory domain = "test-domain";
string[] memory messages = new string[](3);
messages[0] = "message-for-aggregate";
messages[1] = "message-for-wallet3";
messages[2] = "message-for-wallet4";

uint256[] memory aggPrivateKeys = new uint256[](2);
aggPrivateKeys[0] = wallet1.privateKey;
aggPrivateKeys[1] = wallet2.privateKey;

uint256[2][] memory signatures = new uint256[2][](3);
uint256[4][] memory pubKeys = new uint256[4][](3);
uint256[2][] memory messagePoints = new uint256[2][](3);

signatures[0] = BLSTestingLib.sign(aggPrivateKeys, domain, messages[0]);
pubKeys[0] = BLSTestingLib.getPublicKey(aggPrivateKeys);
messagePoints[0] = BLSTestingLib.hashToPoint(domain, messages[0]);

signatures[1] = BLSTestingLib.sign(wallet3.privateKey, domain, messages[1]);
pubKeys[1] = wallet3.publicKey;
messagePoints[1] = BLSTestingLib.hashToPoint(domain, messages[1]);

signatures[2] = BLSTestingLib.sign(wallet4.privateKey, domain, messages[2]);
pubKeys[2] = wallet4.publicKey;
messagePoints[2] = BLSTestingLib.hashToPoint(domain, messages[2]);

(bool pairingSuccess, bool callSuccess) = bls.verifyBatch(signatures, pubKeys, messagePoints);

require(callSuccess, "Precompile call failed");
require(pairingSuccess, "Batch verification failed");
```
