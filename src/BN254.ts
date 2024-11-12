const mcl = require('mcl-wasm')
import type { G1, G2, Fr, Fp } from 'mcl-wasm'
import { FIELD_ORDER, G1_X, G1_Y, G2_X, G2_Y } from './constants'
import { createFp2 } from './pointOps'
import { reverseEndianness } from './utils'

export class BN254 {
    public readonly G1: G1
    public readonly G2: G2

    private constructor() {
        const { g1, g2 } = this.createGeneratorPoints()
        this.G1 = g1
        this.G2 = g2
    }

    public static async create() {
        await mcl.init(mcl.BN_SNARK1)
        mcl.setETHserialization(true)
        mcl.setMapToMode(0) // FT
        return new BN254()
    }

    public generateKeyPair(privateKeyHex: `0x${string}`): { secretKey: Fr; pubKeyG2: G2, pubKeyG1: G1} {
        if (!mcl.mod) {
            throw new Error('mcl not ready')
        }
        const secretKey: Fr = new mcl.Fr()
        secretKey.setHashOf(privateKeyHex)
        const pubKeyG2 = mcl.mul(this.G2, secretKey)
        const pubKeyG1 = mcl.mul(this.G1, secretKey)
        pubKeyG2.normalize()
        pubKeyG1.normalize()
        return { secretKey, pubKeyG2: pubKeyG2, pubKeyG1 }
    }

    public createGeneratorPoints(): { g1: G1; g2: G2 } {
        if (!mcl.mod) {
            throw new Error('mcl not ready')
        }
        const g1 = new mcl.G1()
        const g1x: Fp = new mcl.Fp()
        const g1y: Fp = new mcl.Fp()
        const g1z: Fp = new mcl.Fp()
        g1x.setStr(G1_X, 16)
        g1y.setStr(G1_Y, 16)
        g1z.setInt(1)
        g1.setX(g1x)
        g1.setY(g1y)
        g1.setZ(g1z)

        const g2 = new mcl.G2()
        const g2x = createFp2(G2_X[0], G2_X[1])
        const g2y = createFp2(G2_Y[0], G2_Y[1])
        const g2z = createFp2('0x01', '0x00')
        g2.setX(g2x)
        g2.setY(g2y)
        g2.setZ(g2z)

        return { g1, g2 }
    }
}

export function serializeG1(point: G1): [bigint, bigint] {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    point.normalize()
    const x = BigInt(`0x${reverseEndianness(point.getX().serializeToHexStr(), 32)}`)
    const y = BigInt(`0x${reverseEndianness(point.getY().serializeToHexStr(), 32)}`)

    // Check for coordinate overflow
    if (x >= FIELD_ORDER || y >= FIELD_ORDER) {
        throw new Error('G1 point coordinates must be less than field modulus')
    }
    return [x, y]
}

export function serializeG2(point: G2): [bigint, bigint, bigint, bigint] {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    point.normalize()
    const x = point.getX()
    const y = point.getY()
    const x0 = BigInt(`0x${reverseEndianness(x.get_a().serializeToHexStr(), 32)}`)
    const x1 = BigInt(`0x${reverseEndianness(x.get_b().serializeToHexStr(), 32)}`)
    const y0 = BigInt(`0x${reverseEndianness(y.get_a().serializeToHexStr(), 32)}`)
    const y1 = BigInt(`0x${reverseEndianness(y.get_b().serializeToHexStr(), 32)}`)
    return [x0, x1, y0, y1]
}

/**
 * Deserializes coordinates to a G1 point.
 * @param x X-coordinate.
 * @param y Y-coordinate.
 */
export function deserializeG1(x: bigint, y: bigint): G1 {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    const point = new mcl.G1()
    const z = new mcl.Fp()
    z.setInt(1)

    const xFp = new mcl.Fp()
    const yFp = new mcl.Fp()
    xFp.setStr(x.toString().padStart(64, '0'), 16)
    yFp.setStr(y.toString().padStart(64, '0'), 16)

    point.setX(xFp)
    point.setY(yFp)
    point.setZ(z)

    return point
}

/**
 * Deserializes coordinates to a G2 point.
 * @param x0 X-coordinate component a.
 * @param x1 X-coordinate component b.
 * @param y0 Y-coordinate component a.
 * @param y1 Y-coordinate component b.
 */
export function deserializeG2(x0: bigint, x1: bigint, y0: bigint, y1: bigint): G2 {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    const point = new mcl.G2()
    const Mx = new mcl.Fp2()
    const Mx_a = new mcl.Fp()
    const Mx_b = new mcl.Fp()
    Mx_a.setStr(x0.toString(16).padStart(64, '0'), 16)
    Mx_b.setStr(x1.toString(16).padStart(64, '0'), 16)
    Mx.set_a(Mx_a)
    Mx.set_b(Mx_b)

    const My = new mcl.Fp2()
    const My_a = new mcl.Fp()
    const My_b = new mcl.Fp()
    My_a.setStr(y0.toString(16).padStart(64, '0'), 16)
    My_b.setStr(y1.toString(16).padStart(64, '0'), 16)
    My.set_a(My_a)
    My.set_b(My_b)

    const Mz = new mcl.Fp2()
    const Mz_a = new mcl.Fp()
    const Mz_b = new mcl.Fp()
    Mz_a.setInt(1)
    Mz_b.setInt(0)
    Mz.set_a(Mz_a)
    Mz.set_b(Mz_b)

    point.setX(Mx)
    point.setY(My)
    point.setZ(Mz)

    return point
}

export function signMessage(message: G1, secretKey: Fr): G1 {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    const signature: G1 = mcl.mul(message, secretKey)
    signature.normalize()
    return signature
}

/**
 * Aggregates multiple BLS public keys into a single public key
 * @param publicKeys Array of G2 points representing individual public keys
 * @returns Aggregated public key as G2 point
 */
export function aggregatePublicKeys(publicKeys: G2[]): G2 {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    if (!publicKeys.length) {
        throw new Error('Cannot aggregate empty public array')
    }

    return publicKeys.reduce((aggregated, publicKey) => {
        return mcl.add(aggregated, publicKey)
    })
}

/**
 * Aggregates multiple BLS signatures into a single signature
 * @param signatures Array of G1 points representing individual signatures
 * @returns Aggregated signature as G1 point
 * @throws Error if signatures array is empty
 */
export function aggregateSignatures(signatures: G1[]): G1 {
    if (!mcl.mod) {
        throw new Error('mcl not ready')
    }
    if (!signatures.length) {
        throw new Error('Cannot aggregate empty signature array')
    }

    return signatures.reduce((aggregated, signature) => {
        return mcl.add(aggregated, signature)
    })
}
