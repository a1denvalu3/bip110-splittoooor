import { PureBitcoinSwap } from '../src/lib/PureBitcoinSwap';
import { SIGHASH_ALL_UNIFIED } from '../src/lib/unifiedSighash';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import axios from 'axios';

bitcoin.initEccLib(ecc);
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

class BitcoinRpc {
    private readonly url: string;
    private readonly walletUrl: string;
    constructor(port: number) {
        this.url = `http://user:password@127.0.0.1:${port}/`;
        this.walletUrl = `http://user:password@127.0.0.1:${port}/wallet/miner`;
    }
    async call(method: string, params: any[] = []): Promise<any> {
        const walletMethods = new Set(['getnewaddress', 'sendtoaddress', 'listunspent', 'getbalance']);
        try {
            const response = await axios.post(walletMethods.has(method) ? this.walletUrl : this.url, {
                jsonrpc: '1.0', id: 'regtest', method, params
            });
            return response.data.result;
        } catch (error: any) {
            throw new Error(`RPC Error [${method}]: ${error.response?.data?.error?.message || error.message}`);
        }
    }
}

const mainRpc = new BitcoinRpc(18443);
const bip110Rpc = new BitcoinRpc(18444);

async function waitForRpc(rpc: BitcoinRpc): Promise<void> {
    for (let attempt = 0; attempt < 30; attempt++) {
        try { await rpc.call('getblockcount'); return; }
        catch { await sleep(500); }
    }
    throw new Error('Node RPC did not become ready');
}

async function setupWallet(rpc: BitcoinRpc): Promise<void> {
    try { await rpc.call('createwallet', ['miner']); }
    catch (error: any) {
        if (!error.message.includes('already exists') && !error.message.includes('already loaded')) throw error;
    }
}

async function waitForHeight(rpc: BitcoinRpc, expected: number): Promise<void> {
    for (let attempt = 0; attempt < 20; attempt++) {
        if (await rpc.call('getblockcount') === expected) return;
        await sleep(500);
    }
    throw new Error(`Node did not reach shared height ${expected}`);
}

async function findOutputIndex(rpc: BitcoinRpc, txid: string, scriptHex: string): Promise<number> {
    const transaction = await rpc.call('getrawtransaction', [txid, true]);
    const index = transaction.vout.findIndex((output: any) => output.scriptPubKey.hex === scriptHex);
    if (index < 0) throw new Error(`Output ${scriptHex} was not found in ${txid}`);
    return index;
}

async function run(): Promise<void> {
    console.log('Starting native SIGHASH_UNIFIED split verification');
    await Promise.all([waitForRpc(mainRpc), waitForRpc(bip110Rpc)]);
    await setupWallet(mainRpc);
    await setupWallet(bip110Rpc);
    try { await mainRpc.call('addnode', ['bitcoind-bip110:18444', 'add']); } catch {}

    const sharedMiner = await mainRpc.call('getnewaddress');
    await mainRpc.call('generatetoaddress', [110, sharedMiner]);
    await waitForHeight(bip110Rpc, 110);

    const owner = PureBitcoinSwap.generateKeyPair();
    const split = PureBitcoinSwap.createSplitPayment(Buffer.from(owner.publicKey), bitcoin.networks.regtest);
    const fundingTxid = await mainRpc.call('sendtoaddress', [split.payment.address, 10]);
    await mainRpc.call('generatetoaddress', [1, sharedMiner]);
    await waitForHeight(bip110Rpc, 111);

    const vout = await findOutputIndex(mainRpc, fundingTxid, Buffer.from(split.payment.output!).toString('hex'));
    const destination = bitcoin.payments.p2tr({
        internalPubkey: PureBitcoinSwap.getXOnlyPubKey(Buffer.from(owner.publicKey)),
        network: bitcoin.networks.regtest
    });
    const splitTransaction = PureBitcoinSwap.buildUnifiedSplitTx(
        owner, fundingTxid, vout, 1_000_000_000n, 999_998_000n,
        destination.address!, split.payment, split.script, bitcoin.networks.regtest
    );

    const witness = splitTransaction.ins[0].witness;
    if (witness.length !== 1 || witness[0].length !== 65 || witness[0][64] !== SIGHASH_ALL_UNIFIED) {
        throw new Error('Split transaction does not carry a canonical SIGHASH_ALL|UNIFIED key-path signature');
    }

    const splitTxid = await bip110Rpc.call('sendrawtransaction', [splitTransaction.toHex()]);
    try {
        await mainRpc.call('sendrawtransaction', [splitTransaction.toHex()]);
        throw new Error('Bitcoin Core accepted a SIGHASH_UNIFIED transaction');
    } catch (error: any) {
        if (error.message === 'Bitcoin Core accepted a SIGHASH_UNIFIED transaction') throw error;
        console.log(`Bitcoin correctly rejected the unified signature: ${error.message}`);
    }

    const blakeMiner = await bip110Rpc.call('getnewaddress');
    await bip110Rpc.call('generatetoaddress', [1, blakeMiner]);
    if (await mainRpc.call('gettxout', [fundingTxid, vout]) === null) throw new Error('Original output was spent on Bitcoin');
    if (await bip110Rpc.call('gettxout', [fundingTxid, vout]) !== null) throw new Error('Original output remains on BLAKE2b');
    if (await bip110Rpc.call('gettxout', [splitTxid, 0]) === null) throw new Error('BLAKE2b split destination is missing');
    console.log(`Native split verified: ${splitTxid}`);
}

run().catch(error => {
    console.error(`Split test failed: ${error.message}`);
    process.exit(1);
});
