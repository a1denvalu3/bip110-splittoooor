// Harness: ECDSA signature parsing behavior of ecpair/tiny-secp256k1 as used in server.ts
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

const pair = ECPair.makeRandom();
const msgHash = bitcoin.crypto.sha256(Buffer.from('delete-offer:abc123'));
const sigCompact = Buffer.from(pair.sign(msgHash)); // 64-byte compact
console.log('compact sig len:', sigCompact.length);
console.log('verify compact:', pair.verify(msgHash, sigCompact));

// 1. High-S malleability: flip s -> n - s
const n = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const r = sigCompact.subarray(0, 32);
const s = BigInt('0x' + sigCompact.subarray(32).toString('hex'));
const sFlipped = n - s;
const malleated = Buffer.concat([r, Buffer.from(sFlipped.toString(16).padStart(64, '0'), 'hex')]);
try {
    console.log('verify high-S malleated:', pair.verify(msgHash, malleated));
} catch (e: any) {
    console.log('high-S malleated THROWS:', e.message);
}

// 2. DER-encoded signature (what the accept-endpoint regex 128..144 hex chars admits)
const der = bitcoin.script.signature.encode(sigCompact, 0x01).subarray(0, -1); // DER without sighash byte
console.log('\nDER sig len:', der.length, 'hex chars:', der.length * 2);
try {
    console.log('verify DER:', pair.verify(msgHash, der));
} catch (e: any) {
    console.log('DER THROWS:', e.message);
}

// 3. Regex-passing but invalid curve point pubkey: 02 + 64 zeros
const badPub = Buffer.from('02' + '00'.repeat(32), 'hex');
try {
    const p = ECPair.fromPublicKey(badPub);
    console.log('\nfromPublicKey(02+zeros) OK, verify:', p.verify(msgHash, sigCompact));
} catch (e: any) {
    console.log('\nfromPublicKey(02+zeros) THROWS:', e.message);
}

// 4. Garbage 64-byte signature
try {
    console.log('verify zeros sig:', pair.verify(msgHash, Buffer.alloc(64, 0)));
} catch (e: any) {
    console.log('zeros sig THROWS:', e.message);
}

// 5. Odd-length hex signature (regex allows 128..144 ANY length, e.g. 129)
const oddHex = 'aa'.repeat(64) + 'b'; // 129 hex chars
console.log('\nodd hex len 129 -> Buffer.from len:', Buffer.from(oddHex, 'hex').length);
try {
    console.log('verify odd-hex sig:', pair.verify(msgHash, Buffer.from(oddHex, 'hex')));
} catch (e: any) {
    console.log('odd-hex THROWS:', e.message);
}

// 6. Does sign() ever produce high-S? (ecpair normalizes to low-S by default)
const sVal = BigInt('0x' + sigCompact.subarray(32).toString('hex'));
console.log('\nsigner produced low-S:', sVal <= n / 2n);
