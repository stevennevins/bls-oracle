import { Command } from 'commander'
import { getBytes, isHexString, toUtf8Bytes } from 'ethers'
import { BN254, serializeG1, aggregateSignatures, signMessage} from '../../BN254'
import { hashToPoint } from "../../pointOps"

async function signAggregateMessages(privateKeys: `0x${string}`[], domain: string, msg: string) {
    const bls = await BN254.create()
    const msgBytes = isHexString(msg) ? getBytes(msg) : toUtf8Bytes(msg)
    const dstBytes = toUtf8Bytes(domain)
    const msgPoint = hashToPoint(dstBytes, msgBytes)
    const signatures = privateKeys.map(privateKey => {
        const { secretKey } = bls.generateKeyPair(privateKey)
        return signMessage(msgPoint, secretKey)
    })

    const aggregatedSig = aggregateSignatures(signatures)
    return serializeG1(aggregatedSig)
}

export const signAggMessageCommand = new Command('sign-agg')
    .description('Sign a message with multiple private keys and aggregate the signatures')
    .argument('<privateKeyList>', 'Comma-separated list of private keys (hex)')
    .argument('<domain>', 'Domain string')
    .argument('<message>', 'Message to sign (hex or utf8)')
    .action(async (privateKeyList: string, domain: string, message: string) => {
        const privateKeys = privateKeyList.split(',') as `0x${string}`[]
        
        if (privateKeys.length === 0) {
            console.error('At least one private key is required')
            process.exit(1)
        }

        try {
            const signature = await signAggregateMessages(privateKeys, domain, message)
            console.log(signature.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
