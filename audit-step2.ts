import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import axios from 'axios';
import { PureBitcoinSwap } from './src/lib/PureBitcoinSwap';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;
const rpc = async (method: string, params: any[] = []) => {
    const res = await axios.post(`http://user:password@127.0.0.1:18443/wallet/miner`, { jsonrpc: '1.0', id: 'audit', method, params });
    if (res.data.error) throw new Error(`${method}: ${JSON.stringify(res.data.error)}`);
    return res.data.result;
};
const taggedHash = (tag: string, msg: Buffer): Buffer => Buffer.from((bitcoin.crypto.taggedHash as any)(tag, msg));

async function main() {
    const initiator = PureBitcoinSwap.generateKeyPair();
    const acceptor = PureBitcoinSwap.generateKeyPair();
    const preimage = Buffer.alloc(32, 0x42);
    const hashLock = Buffer.from(bitcoin.crypto.sha256(preimage));
    const height: number = await rpc('getblockcount');
    const lockTime = height + 288;
    const htlc = PureBitcoinSwap.createTaprootHtlc(
        Buffer.from(initiator.publicKey), hashLock,
        Buffer.from(initiator.publicKey), Buffer.from(acceptor.publicKey),
        lockTime, network);
    const fundTxid = await rpc('sendtoaddress', [htlc.address!, 0.001]);
    const fundTx = bitcoin.Transaction.fromHex(await rpc('getrawtransaction', [fundTxid]));
    const vout = fundTx.outs.findIndex((o: any) => Buffer.from(o.script).equals(Buffer.from(htlc.output!)));
    const value = fundTx.outs[vout].value;

    const claimScript = PureBitcoinSwap.createHtlcClaimScript(hashLock, Buffer.from(initiator.publicKey));
    const refundScript = PureBitcoinSwap.createHtlcRefundScript(Buffer.from(acceptor.publicKey), lockTime);
    const lh1 = PureBitcoinSwap.tapleafHash(claimScript), lh2 = PureBitcoinSwap.tapleafHash(refundScript);
    const [a, b] = Buffer.compare(lh1, lh2) < 0 ? [lh1, lh2] : [lh2, lh1];
    const merkleRoot = Buffer.from(taggedHash('TapBranch', Buffer.concat([a, b])));

    const dest = await rpc('getnewaddress');
    const sweep = new bitcoin.Transaction();
    sweep.version = 2;
    sweep.addInput(Buffer.from(fundTxid, 'hex').reverse(), vout);
    sweep.addOutput(bitcoin.address.toOutputScript(dest, network), value - 1000n);
    const sighash = sweep.hashForWitnessV1(0, [htlc.output!], [value], bitcoin.Transaction.SIGHASH_DEFAULT);
    const tweaked = PureBitcoinSwap.getTweakedKeyPair(initiator, merkleRoot, network);
    sweep.setWitness(0, [Buffer.from(tweaked.signSchnorr(sighash))]);

    const sweepTxid = await rpc('sendrawtransaction', [sweep.toHex()]);
    console.log('sweep broadcast:', sweepTxid);
    await rpc('generatetoaddress', [1, await rpc('getnewaddress')]);
    const conf = await rpc('getrawtransaction', [sweepTxid, true]);
    console.log('sweep confirmations:', conf.confirmations, '| in block:', conf.blockhash ? 'YES' : 'NO');
}
main().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
