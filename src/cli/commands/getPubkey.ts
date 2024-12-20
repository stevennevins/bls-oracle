import { Command } from 'commander'
import { BN254, serializeG2 } from '../../BN254'

async function getPubKey(privateKey: `0x${string}`) {
    const bls = await BN254.create()
    const { pubKeyG2 } = bls.generateKeyPair(privateKey)
    return serializeG2(pubKeyG2)
}

export const getPubkey= new Command('get-pubkey')
    .description('Get BLS public key from private key')
    .argument('<privateKey>', 'Private key in hex format')
    .action(async (privateKey: string) => {
        try {
            const pubKey = await getPubKey(privateKey as `0x${string}`)
            console.log(pubKey.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
