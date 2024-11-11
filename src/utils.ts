import { getBytes } from 'ethers'

export function toHex(n: bigint): `0x${string}` {
    return ('0x' + n.toString(16).padStart(64, '0')) as `0x${string}`
}

export function reverseEndianness(hex: string, n: number) {
    const bytes = getBytes('0x' + hex)
    if (bytes.byteLength !== n) throw new Error(`Invalid length: ${bytes.byteLength}`)
    return Array.from(bytes)
        .reverse()
        .map((v) => v.toString(16).padStart(2, '0'))
        .join('')
}