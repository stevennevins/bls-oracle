import { Command } from 'commander'
import { getBytes, isHexString, toUtf8Bytes } from 'ethers'
import { BN254, serializeG1 } from '../../BN254'
import { hashToPoint } from "../../pointOps"

export async function hashMessage(dst: string, msg: string) {
    const bls = await BN254.create()
    const dstBytes = toUtf8Bytes(dst)
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const point = hashToPoint(dstBytes, msgBytes)
    return serializeG1(point)
}

export const hashMessageCommand = new Command('hash')
    .description('Hash a message to a BLS curve point')
    .argument('<domain>', 'Domain string')
    .argument('<message>', 'Message to hash (hex or utf8)')
    .action(async (domain: string, message: string) => {
        try {
            const hash = await hashMessage(domain, message)
            console.log(hash.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
