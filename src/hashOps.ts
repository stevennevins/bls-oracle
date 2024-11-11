
import { hexlify, getBytes, keccak256, solidityPacked } from 'ethers'
import { mod } from './fieldOps'
import { toHex } from './utils'
import { FIELD_ORDER } from './constants'

export function hashToField(domain: Uint8Array, msg: Uint8Array, count: number): bigint[] {
    const u = 48
    const _msg = expandMsg(domain, msg, count * u)
    const els: bigint[] = []
    for (let i = 0; i < count; i++) {
        const el = mod(BigInt(hexlify(_msg.slice(i * u, (i + 1) * u))), FIELD_ORDER)
        els.push(el)
    }
    return els
}


export function expandMsg(domain: Uint8Array, msg: Uint8Array, outLen: number): Uint8Array {
    if (domain.length > 255) {
        throw new Error('bad domain size')
    }

    const domainLen = domain.length
    if (domainLen > 255) {
        throw new Error('InvalidDSTLength')
    }
    const zpad = new Uint8Array(136)
    const b_0 = solidityPacked(
        ['bytes', 'bytes', 'uint8', 'uint8', 'uint8', 'bytes', 'uint8'],
        [zpad, msg, outLen >> 8, outLen & 0xff, 0, domain, domainLen],
    )
    const b0 = keccak256(b_0)

    const b_i = solidityPacked(['bytes', 'uint8', 'bytes', 'uint8'], [b0, 1, domain, domain.length])
    let bi = keccak256(b_i)

    const out = new Uint8Array(outLen)
    const ell = Math.floor((outLen + 32 - 1) / 32) // keccak256 blksize
    for (let i = 1; i < ell; i++) {
        const b_i = solidityPacked(
            ['bytes32', 'uint8', 'bytes', 'uint8'],
            [toHex(BigInt(b0) ^ BigInt(bi)), 1 + i, domain, domain.length],
        )
        const bi_bytes = getBytes(bi)
        for (let j = 0; j < 32; j++) {
            out[(i - 1) * 32 + j] = bi_bytes[j]
        }
        bi = keccak256(b_i)
    }
    const bi_bytes = getBytes(bi)
    for (let j = 0; j < 32; j++) {
        out[(ell - 1) * 32 + j] = bi_bytes[j]
    }
    return out
}