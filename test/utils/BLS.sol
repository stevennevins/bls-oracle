// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ModexpInverse, ModexpSqrt} from "./ModExp.sol";
import {BN256G2} from "./BN256G2.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Naehrig 254 bit curve (BN-254)
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We use G1 points for signatures and messages, and G2 points for public keys
/// @dev Adapted from https://github.com/thehubbleproject/hubble-contracts
library BLS {
    // Field order
    uint256 private constant N =
        21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583;

    // Negated generator of G2
    uint256 private constant N_G2_X1 =
        11_559_732_032_986_387_107_991_004_021_392_285_783_925_812_861_821_192_530_917_403_151_452_391_805_634;
    uint256 private constant N_G2_X0 =
        10_857_046_999_023_057_135_944_570_762_232_829_481_370_756_359_578_518_086_990_519_993_285_655_852_781;
    uint256 private constant N_G2_Y1 =
        17_805_874_995_975_841_540_914_202_342_111_839_520_379_459_829_704_422_454_583_296_818_431_106_115_052;
    uint256 private constant N_G2_Y0 =
        13_392_588_948_715_843_804_641_432_497_768_002_650_278_120_570_034_223_513_918_757_245_338_268_106_653;

    uint256 private constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 private constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice Param A of BN254
    uint256 private constant A = 0;
    /// @notice Param B of BN254
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 = 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 = 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    error BNAddFailed(uint256[4] input);
    error InvalidFieldElement(uint256 x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    function verifySingle(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[12] memory input = prepareVerifyMessage(signature, pubkey, message);
        return verifyPairing(input);
    }

    function verifyApk(
        uint256[4] memory pubkeyG2,
        uint256[2] memory pubkeyG1
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[12] memory input = prepareApkInput(pubkeyG2, pubkeyG1);
        return verifyPairing(input);
    }

    function verifyMultiple(
        uint256[2][] memory signatures,
        uint256[4][] memory pubKeys,
        uint256[2][] memory messages
    ) external view returns (bool, bool) {
        require(
            signatures.length == pubKeys.length && signatures.length == messages.length,
            "Array lengths must match"
        );

        uint256 k = signatures.length;
        uint256[] memory input = prepareVerifyMultipleInput(signatures, pubKeys, messages);
        return verifyPairingBatch(input, k);
    }

    // New helper functions
    function prepareVerifyMessage(
        uint256[2] memory signature,
        uint256[4] memory pubkey,
        uint256[2] memory message
    ) internal pure returns (uint256[12] memory input) {
        input = [
            signature[0],
            signature[1],
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0,
            message[0],
            message[1],
            pubkey[1],
            pubkey[0],
            pubkey[3],
            pubkey[2]
        ];
    }

    function prepareApkInput(
        uint256[4] memory pubkeyG2,
        uint256[2] memory pubkeyG1
    ) internal pure returns (uint256[12] memory input) {
        input = [
            1,
            2,
            pubkeyG2[1],
            pubkeyG2[0],
            pubkeyG2[3],
            pubkeyG2[2],
            pubkeyG1[0],
            pubkeyG1[1],
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0
        ];
    }

    function prepareVerifyMultipleInput(
        uint256[2][] memory signatures,
        uint256[4][] memory pubKeys,
        uint256[2][] memory messages
    ) internal pure returns (uint256[] memory input) {
        uint256 k = signatures.length;
        input = new uint256[](k * 12);

        for (uint256 i = 0; i < k; i++) {
            uint256 j = i * 12;
            input[j + 0] = signatures[i][0];
            input[j + 1] = signatures[i][1];
            input[j + 2] = N_G2_X1;
            input[j + 3] = N_G2_X0;
            input[j + 4] = N_G2_Y1;
            input[j + 5] = N_G2_Y0;
            input[j + 6] = messages[i][0];
            input[j + 7] = messages[i][1];
            input[j + 8] = pubKeys[i][1];
            input[j + 9] = pubKeys[i][0];
            input[j + 10] = pubKeys[i][3];
            input[j + 11] = pubKeys[i][2];
        }
    }

    function verifyPairing(
        uint256[12] memory input
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    function verifyPairingBatch(
        uint256[] memory input,
        uint256 k
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[1] memory out;
        assembly {
            callSuccess :=
                staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(mul(k, 12), 0x20), out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Hash to BN254 G1
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return Point in G1
    function hashToPoint(
        bytes memory domain,
        bytes memory message
    ) internal view returns (uint256[2] memory) {
        uint256[2] memory u = hashToField(domain, message);
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        if (!success) revert BNAddFailed(bnAddInput);
        return p0;
    }

    /// @notice Check if `signature` is a valid signature
    /// @param signature Signature to check
    function isValidSignature(
        uint256[2] memory signature
    ) internal pure returns (bool) {
        if ((signature[0] >= N) || (signature[1] >= N)) {
            return false;
        } else {
            return isOnCurveG1(signature);
        }
    }

    /// @notice Check if `publicKey` is a valid public key
    /// @param publicKey PK to check
    function isValidPublicKey(
        uint256[4] memory publicKey
    ) internal pure returns (bool) {
        if (
            (publicKey[0] >= N) || (publicKey[1] >= N) || (publicKey[2] >= N || (publicKey[3] >= N))
        ) {
            return false;
        } else {
            return isOnCurveG2(publicKey);
        }
    }

    /// @notice Check if `point` is in G1
    /// @param point Point to check
    function isOnCurveG1(
        uint256[2] memory point
    ) internal pure returns (bool _isOnCurve) {
        assembly {
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            let t2 := mulmod(t0, t0, N)
            t2 := mulmod(t2, t0, N)
            t2 := addmod(t2, 3, N)
            t1 := mulmod(t1, t1, N)
            _isOnCurve := eq(t1, t2)
        }
    }

    /// @notice Check if `point` is in G2
    /// @param point Point to check
    function isOnCurveG2(
        uint256[4] memory point
    ) internal pure returns (bool _isOnCurve) {
        assembly {
            // x0, x1
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            // x0 ^ 2
            let t2 := mulmod(t0, t0, N)
            // x1 ^ 2
            let t3 := mulmod(t1, t1, N)
            // 3 * x0 ^ 2
            let t4 := add(add(t2, t2), t2)
            // 3 * x1 ^ 2
            let t5 := addmod(add(t3, t3), t3, N)
            // x0 * (x0 ^ 2 - 3 * x1 ^ 2)
            t2 := mulmod(add(t2, sub(N, t5)), t0, N)
            // x1 * (3 * x0 ^ 2 - x1 ^ 2)
            t3 := mulmod(add(t4, sub(N, t3)), t1, N)

            // x ^ 3 + b
            t0 := addmod(t2, 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5, N)
            t1 := addmod(t3, 0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2, N)

            // y0, y1
            t2 := mload(add(point, 64))
            t3 := mload(add(point, 96))
            // y ^ 2
            t4 := mulmod(addmod(t2, t3, N), addmod(t2, sub(N, t3), N), N)
            t3 := mulmod(shl(1, t2), t3, N)

            // y ^ 2 == x ^ 3 + b
            _isOnCurve := and(eq(t0, t4), eq(t1, t3))
        }
    }

    /// @notice sqrt(xx) mod N
    /// @param xx Input
    function sqrt(
        uint256 xx
    ) internal pure returns (uint256 x, bool hasRoot) {
        x = ModexpSqrt.run(xx);
        hasRoot = mulmod(x, x, N) == xx;
    }

    /// @notice a^{-1} mod N
    /// @param a Input
    function inverse(
        uint256 a
    ) internal pure returns (uint256) {
        return ModexpInverse.run(a);
    }

    /// @notice Hash a message to the field
    /// @param domain Domain separation tag
    /// @param message Message to hash
    function hashToField(
        bytes memory domain,
        bytes memory message
    ) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsgTo96(domain, message);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return [a0, a1];
    }

    /// @notice Expand arbitrary message to 96 pseudorandom bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param dst Domain separation tag
    /// @param message Message to expand
    function expandMsgTo96(
        bytes memory dst,
        bytes memory message
    ) internal pure returns (bytes memory) {
        uint256 domainLen = dst.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(dst);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 =
            abi.encodePacked(zpad, message, uint8(0), uint8(96), uint8(0), dst, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), dst, uint8(domainLen));
        bytes32 bi = keccak256(b_i);

        bytes memory out = new bytes(96);
        uint256 ell = 3;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), dst, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(
        uint256 u
    ) internal view returns (uint256[2] memory p) {
        if (u >= N) revert InvalidFieldElement(u);

        uint256 tv1 = mulmod(mulmod(u, u, N), C1, N);
        uint256 tv2 = addmod(1, tv1, N);
        tv1 = addmod(1, N - tv1, N);
        uint256 tv3 = inverse(mulmod(tv1, tv2, N));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, N), tv3, N), C3, N);
        uint256 x1 = addmod(C2, N - tv5, N);
        uint256 x2 = addmod(C2, tv5, N);
        uint256 tv7 = mulmod(tv2, tv2, N);
        uint256 tv8 = mulmod(tv7, tv3, N);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, N), N), N);

        bool hasRoot;
        uint256 gx;
        if (legendre(g(x1)) == 1) {
            p[0] = x1;
            gx = g(x1);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else if (legendre(g(x2)) == 1) {
            p[0] = x2;
            gx = g(x2);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else {
            p[0] = x3;
            gx = g(x3);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = N - p[1];
        }
    }

    /// @notice g(x) = y^2 = x^3 + 3
    function g(
        uint256 x
    ) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, N), x, N), B, N);
    }

    /// @notice https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    function sgn0(
        uint256 x
    ) private pure returns (uint256) {
        return x % 2;
    }

    /// @notice Compute Legendre symbol of u
    /// @param u Field element
    /// @return 1 if u is a quadratic residue, -1 if not, or 0 if u = 0 (mod p)
    function legendre(
        uint256 u
    ) private view returns (int8) {
        uint256 x = modexpLegendre(u);
        if (x == N - 1) {
            return -1;
        }
        if (x != 0 && x != 1) {
            revert MapToPointFailed(u);
        }
        return int8(int256(x));
    }

    function sub(
        uint256[2] memory pk1,
        uint256[2] memory pk2
    ) internal view returns (uint256[2] memory) {
        if (pk2[0] == 0 && pk2[1] == 0) {
            // revert("Invalid pk");
            return pk1;
        } else {
            uint256[2] memory negPk2 = [pk2[0], N - (pk2[1] % N)];
            return aggregate(pk1, negPk2);
        }
    }

    function aggregate(
        uint256[2] memory pk1,
        uint256[2] memory pk2
    ) internal view returns (uint256[2] memory apk) {
        uint256[4] memory input;
        input[0] = pk1[0];
        input[1] = pk1[1];
        input[2] = pk2[0];
        input[3] = pk2[1];
        bool success;
        assembly {
            success := staticcall(gas(), 6, input, 0x80, apk, 0x40)
        }
        if (!success) revert BNAddFailed(input);
    }

    function sub(
        uint256[4] memory pk1,
        uint256[4] memory pk2
    ) internal view returns (uint256[4] memory) {
        if (pk2[0] == 0 && pk2[1] == 0 && pk2[2] == 0 && pk2[3] == 0) {
            // revert("Invalid pk");
            return pk1;
        } else {
            // To negate a G2 point, we negate both y-coordinates
            uint256[4] memory negPk2 = [pk2[0], pk2[1], N - (pk2[2] % N), N - (pk2[3] % N)];
            return aggregate(pk1, negPk2);
        }
    }

    function aggregate(
        uint256[4] memory pk1,
        uint256[4] memory pk2
    ) internal view returns (uint256[4] memory apk) {
        (uint256 x1, uint256 x2, uint256 y1, uint256 y2) =
            BN256G2.ECTwistAdd(pk1[0], pk1[1], pk1[2], pk1[3], pk2[0], pk2[1], pk2[2], pk2[3]);
        return [x1, x2, y1, y2];
    }

    /// @notice This is cheaper than an addchain for exponent (N-1)/2
    function modexpLegendre(
        uint256 u
    ) private view returns (uint256 output) {
        bytes memory input = new bytes(192);
        bool success;
        assembly {
            let p := add(input, 32)
            mstore(p, 32) // len(u)
            p := add(p, 32)
            mstore(p, 32) // len(exp)
            p := add(p, 32)
            mstore(p, 32) // len(mod)
            p := add(p, 32)
            mstore(p, u) // u
            p := add(p, 32)
            mstore(p, C5) // (N-1)/2
            p := add(p, 32)
            mstore(p, N) // N

            success :=
                staticcall(
                    gas(),
                    5,
                    add(input, 32),
                    192,
                    0x00, // scratch space <- result
                    32
                )
            output := mload(0x00) // output <- result
        }
        if (!success) {
            revert ModExpFailed(u, C5, N);
        }
    }

    function mul(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success);
    }

    /**
     * @notice adapted from https://github.com/HarryR/solcrypto/blob/master/contracts/altbn128.sol
     */
    function hashToG1(
        bytes32 _x
    ) internal view returns (uint256[2] memory) {
        uint256 beta = 0;
        uint256 y = 0;

        uint256 x = uint256(_x) % N;

        while (true) {
            (beta, y) = findYFromX(x);

            // y^2 == beta
            if (beta == mulmod(y, y, N)) {
                return [x, y];
            }

            x = addmod(x, 1, N);
        }
        return [uint256(0), uint256(0)];
    }

    /**
     * Given X, find Y
     *
     *   where y = sqrt(x^3 + b)
     *
     * Returns: (x^3 + b), y
     */
    function findYFromX(
        uint256 x
    ) internal view returns (uint256, uint256) {
        // beta = (x^3 + b) % p
        uint256 beta = addmod(mulmod(mulmod(x, x, N), x, N), 3, N);

        // y^2 = x^3 + b
        // this acts like: y = sqrt(beta) = beta^((p+1) / 4)
        uint256 y =
            expMod(beta, 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52, N);

        return (beta, y);
    }

    function expMod(
        uint256 _base,
        uint256 _exponent,
        uint256 _modulus
    ) internal view returns (uint256 retval) {
        bool success;
        uint256[1] memory output;
        uint256[6] memory input;
        input[0] = 0x20; // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20; // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20; // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "BN254.expMod: call failure");
        return output[0];
    }
}
