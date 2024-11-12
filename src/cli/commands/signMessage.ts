import { Command } from 'commander'
import { getBytes, isHexString, toUtf8Bytes } from 'ethers'
import { BN254, serializeG1, signMessage } from '../../BN254'
import { hashToPoint } from "../../pointOps"

async function signMessageWithKey(privateKey: `0x${string}`, domain: string, msg: string) {
    const bls = await BN254.create()
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const dstBytes = toUtf8Bytes(domain)
    const point = hashToPoint(dstBytes, msgBytes)
    const { secretKey } = bls.generateKeyPair(privateKey)
    const signature = signMessage(point, secretKey)
    return serializeG1(signature)
}

export const sign = new Command('sign')
    .description('Sign a message with a private key')
    .argument('<privateKey>', 'Private key (hex)')
    .argument('<domain>', 'Domain string')
    .argument('<message>', 'Message to sign (hex or utf8)')
    .action(async (privateKey: `0x${string}`, domain: string, message: string) => {
        try {
            const signature = await signMessageWithKey(privateKey, domain, message)
            console.log(signature.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
