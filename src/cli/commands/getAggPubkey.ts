import { Command } from 'commander'
import { BN254, serializeG2, aggregatePublicKeys } from '../../BN254'

async function getAggregatedPubKey(privateKeys: `0x${string}`[]) {
    const bls = await BN254.create()

    if (privateKeys.length === 0) {
        throw new Error('No private keys provided')
    }

    const pubKeys = privateKeys.map(privateKey => {
        const { pubKeyG2 } = bls.generateKeyPair(privateKey)
        return pubKeyG2
    })
    const aggregatedPubKey = aggregatePublicKeys(pubKeys)
    return serializeG2(aggregatedPubKey)
}

export const getAggPubkey = new Command('get-agg-pubkey')
    .description('Get aggregated BLS public key from multiple private keys')
    .argument('<privateKeyList>', 'Comma-separated list of private keys (hex)')
    .action(async (privateKeyList: string) => {
        const privateKeys = privateKeyList.split(',') as `0x${string}`[]

        if (privateKeys.length === 0) {
            console.error('At least one private key is required')
            process.exit(1)
        }

        try {
            const aggPubKey = await getAggregatedPubKey(privateKeys)
            console.log(aggPubKey.toString())
        } catch (err) {
            console.error(err)
            process.exit(1)
        }
    })
