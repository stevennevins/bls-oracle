import { Command } from 'commander'
import { BN254, serializeG1 } from '../../BN254'

async function getPubKeyG1(privateKey: `0x${string}`) {
    const bls = await BN254.create()
    const { pubKeyG1 } = bls.generateKeyPair(privateKey)
    return serializeG1(pubKeyG1)
}

export const getPubkeyG1 = new Command('get-pubkey-g1')
    .description('Get BLS public key from private key')
    .argument('<privateKey>', 'Private key in hex format')
    .action(async (privateKey: string) => {
        try {
            const pubKey = await getPubKeyG1(privateKey as `0x${string}`)
            console.log(pubKey.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
