import { expect } from 'chai';
import { PureBitcoinSwap } from '../src/lib/PureBitcoinSwap';
import * as bitcoin from 'bitcoinjs-lib';
import { hashForUnifiedKeypath, SIGHASH_ALL_UNIFIED } from '../src/lib/unifiedSighash';

describe('Pure Bitcoinjs-Lib Optimized Swap Tests', () => {
    // Generate roles
    const initiator = PureBitcoinSwap.generateKeyPair();
    const acceptor = PureBitcoinSwap.generateKeyPair();

    // Convert Uint8Array to Buffer for standard bitcoinjs-lib compatibility
    const initiatorPubKey = Buffer.from(initiator.publicKey);
    const acceptorPubKey = Buffer.from(acceptor.publicKey);

    // Swap parameters
    const preimage = 'highly-optimized-bip110-swap-secret';
    const hashLock = PureBitcoinSwap.computeHashLock(preimage);

    // Timelocks
    const lockTime = 2000; // Block height

    it('1. Split deposit leaf is inert and contains no legacy fork-gating conditionals', () => {
        const splitScript = PureBitcoinSwap.createSplitScript(initiatorPubKey);
        const decompiled = bitcoin.script.decompile(splitScript);
        expect(decompiled).to.deep.equal([bitcoin.opcodes.OP_RETURN]);
    });

    it('matches the upstream Taproot SIGHASH_ALL|UNIFIED test vector', () => {
        const transaction = bitcoin.Transaction.fromHex('0100000001c912714ed02bfbe45aa3b7c1f92b3bfc59e94ddb7ea263a3648dbb9c897bd2b403000000000000000002e39d6002000000001514b1a1b9552e930d457b46ee4e0a54a8033d8da9cd69a36c050000000015142d72d2372c8425e95b93dfd296ad9fc276e104cd00000000');
        const hash = hashForUnifiedKeypath(transaction, 0, [{
            value: 62739988n,
            script: Buffer.from('512096e0394492f9208afc6f8249db5a85c7c4b303f0eb4babb53c2a4c60b717fd1f', 'hex')
        }]);
        expect(SIGHASH_ALL_UNIFIED).to.equal(0x21);
        expect(hash.toString('hex')).to.equal('973f75abf22f12402d185957809b0f29c3912d8359a5cff14c0f6709ec4ac88c');
    });

    it('2. Claim Script should be exactly 69 bytes with zero conditional opcodes', () => {
        const claimScript = PureBitcoinSwap.createHtlcClaimScript(hashLock, acceptorPubKey);
        expect(claimScript.length).to.equal(69); // 33-byte hashLock push + 33-byte recipientPubKey push + 3 single-byte opcodes = 69 bytes!

        const decompiled = bitcoin.script.decompile(claimScript)!;
        expect(decompiled[0]).to.equal(bitcoin.opcodes.OP_SHA256);
        expect((decompiled[1] as Buffer).toString('hex')).to.equal(hashLock.toString('hex'));
        expect(decompiled[2]).to.equal(bitcoin.opcodes.OP_EQUALVERIFY);
        expect((decompiled[3] as Buffer).toString('hex')).to.equal(PureBitcoinSwap.getXOnlyPubKey(acceptorPubKey).toString('hex'));
        expect(decompiled[4]).to.equal(bitcoin.opcodes.OP_CHECKSIG);

        // Verify no conditional opcodes exist in the leaf
        const hasConditional = decompiled.some(op => 
            op === bitcoin.opcodes.OP_IF || 
            op === bitcoin.opcodes.OP_ELSE || 
            op === bitcoin.opcodes.OP_ENDIF
        );
        expect(hasConditional).to.be.false;
    });

    it('3. Refund Script should be exactly 39 bytes with zero conditional opcodes', () => {
        const refundScript = PureBitcoinSwap.createHtlcRefundScript(initiatorPubKey, lockTime);
        expect(refundScript.length).to.equal(39); // 2 + 1 + 1 + 1 + 32 + 1 + 1 = 39 bytes!

        const decompiled = bitcoin.script.decompile(refundScript)!;
        expect((decompiled[0] as Buffer).toString('hex')).to.equal(Buffer.from(bitcoin.script.number.encode(lockTime)).toString('hex'));
        expect(decompiled[1]).to.equal(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY);
        expect(decompiled[2]).to.equal(bitcoin.opcodes.OP_DROP);
        expect((decompiled[3] as Buffer).toString('hex')).to.equal(PureBitcoinSwap.getXOnlyPubKey(initiatorPubKey).toString('hex'));
        expect(decompiled[4]).to.equal(bitcoin.opcodes.OP_CHECKSIG);

        // Verify no conditional opcodes exist in the leaf
        const hasConditional = decompiled.some(op => 
            op === bitcoin.opcodes.OP_IF || 
            op === bitcoin.opcodes.OP_ELSE || 
            op === bitcoin.opcodes.OP_ENDIF
        );
        expect(hasConditional).to.be.false;
    });

    it('4. Taproot HTLC Address Generation should be completely deterministic', () => {
        // NUMS tweak: internal key = H + u*G (key path unspendable)
        const numsTweak = PureBitcoinSwap.generateNumsTweak();

        const htlcPayment1 = PureBitcoinSwap.createTaprootHtlc(
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );

        const htlcPayment2 = PureBitcoinSwap.createTaprootHtlc(
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );

        // Addresses must be absolutely identical and valid testnet p2tr addresses starting with "tb1p"
        expect(htlcPayment1.address).to.equal(htlcPayment2.address);
        expect(htlcPayment1.address!.startsWith('tb1p')).to.be.true;
    });

    it('5. Taproot HTLC Verification Primitives should correctly validate matching and mismatching parameters', () => {
        const numsTweak = PureBitcoinSwap.generateNumsTweak();

        const htlcPayment = PureBitcoinSwap.createTaprootHtlc(
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );

        const address = htlcPayment.address!;
        const output = htlcPayment.output!;

        // 1. Check with correct parameters
        const isAddressValid = PureBitcoinSwap.verifyTaprootHtlcAddress(
            address,
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );
        expect(isAddressValid).to.be.true;

        const isOutputValid = PureBitcoinSwap.verifyTaprootHtlcOutput(
            Buffer.from(output),
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );
        expect(isOutputValid).to.be.true;

        // 2. Check with wrong NUMS tweak
        const wrongNumsTweak = PureBitcoinSwap.generateNumsTweak();
        const badAddressCheck1 = PureBitcoinSwap.verifyTaprootHtlcAddress(
            address,
            wrongNumsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );
        expect(badAddressCheck1).to.be.false;

        // 3. Check with wrong recipient pubkey
        const wrongRecipient = Buffer.from(PureBitcoinSwap.generateKeyPair().publicKey);
        const badAddressCheck2 = PureBitcoinSwap.verifyTaprootHtlcAddress(
            address,
            numsTweak,
            hashLock,
            wrongRecipient,
            initiatorPubKey,
            lockTime
        );
        expect(badAddressCheck2).to.be.false;

        // 4. Check with wrong lockTime
        const badAddressCheck3 = PureBitcoinSwap.verifyTaprootHtlcAddress(
            address,
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime + 1
        );
        expect(badAddressCheck3).to.be.false;
    });

    it('5b. deriveHtlcInternalKey should be deterministic for the same tweak', () => {
        const numsTweak = PureBitcoinSwap.generateNumsTweak();
        const key1 = PureBitcoinSwap.deriveHtlcInternalKey(numsTweak);
        const key2 = PureBitcoinSwap.deriveHtlcInternalKey(numsTweak);

        expect(key1.length).to.equal(32);
        expect(key1.equals(key2)).to.be.true;
        // The internal key must differ from the raw NUMS point (u*G was added)
        expect(key1.equals(PureBitcoinSwap.HTLC_NUMS_POINT)).to.be.false;
    });

    it('5c. deriveHtlcInternalKey should reject invalid tweak lengths', () => {
        expect(() => PureBitcoinSwap.deriveHtlcInternalKey(Buffer.alloc(0))).to.throw('32-byte');
        expect(() => PureBitcoinSwap.deriveHtlcInternalKey(Buffer.alloc(31))).to.throw('32-byte');
        expect(() => PureBitcoinSwap.deriveHtlcInternalKey(Buffer.alloc(33))).to.throw('32-byte');
        expect(() => PureBitcoinSwap.deriveHtlcInternalKey('not-a-buffer' as any)).to.throw('32-byte');
    });

    it('5d. Neither participant can key-path spend the HTLC (NUMS internal key)', () => {
        const numsTweak = PureBitcoinSwap.generateNumsTweak();
        const htlcPayment = PureBitcoinSwap.createTaprootHtlc(
            numsTweak,
            hashLock,
            acceptorPubKey,
            initiatorPubKey,
            lockTime
        );
        // P2TR output script: OP_1 <32-byte tweaked output key>
        const outputKey = Buffer.from(htlcPayment.output!).subarray(2);
        expect(outputKey.length).to.equal(32);

        // Reconstruct the merkle root from the two tapleaf hashes
        const claimLeafHash = PureBitcoinSwap.tapleafHash(
            PureBitcoinSwap.createHtlcClaimScript(hashLock, acceptorPubKey)
        );
        const refundLeafHash = PureBitcoinSwap.tapleafHash(
            PureBitcoinSwap.createHtlcRefundScript(initiatorPubKey, lockTime)
        );
        const sortedLeaves = [claimLeafHash, refundLeafHash].sort(Buffer.compare);
        const merkleRoot = Buffer.from(
            bitcoin.crypto.taggedHash('TapBranch', Buffer.concat(sortedLeaves))
        );

        // A key-path spend requires the TapTweak tweak of a participant's key to
        // land on the output key. With internal key H + u*G (dlog unknown), no
        // participant key can satisfy this for either initiator or acceptor.
        for (const participant of [initiator, acceptor]) {
            const tweakedPair = PureBitcoinSwap.getTweakedKeyPair(participant, merkleRoot);
            const tweakedXOnly = PureBitcoinSwap.getXOnlyPubKey(Buffer.from(tweakedPair.publicKey));
            expect(tweakedXOnly.equals(outputKey)).to.be.false;
        }
    });

    it('5e. Backing ownership check accepts both split and own address script forms', () => {
        // Pinned to a real mainnet incident (2026-09-02): this key's own-address
        // output was rejected as collateral.
        const key = Buffer.from('0234f0ebf2e22243ab2f7e378ef0898d1c177e986568a6bee2f3c027b5353ad093', 'hex');
        const ownOutput = PureBitcoinSwap.createOwnPayment(key, bitcoin.networks.bitcoin).payment.output!;
        const splitOutput = PureBitcoinSwap.createSplitPayment(key, bitcoin.networks.bitcoin).payment.output!;
        const ownHex = '51205b62542b3f71b1c24d143cdf79a0c22e3a21b00935a9c44515204d9dad056ec3';
        const splitHex = '51204af977e2ada8d13e9ffd31d5a663f46f373e632f74281dd2cd1d90b726bb87a0';
        expect(Buffer.from(ownOutput).toString('hex')).to.equal(ownHex);
        expect(Buffer.from(splitOutput).toString('hex')).to.equal(splitHex);

        // bitcoinjs-lib v7 payments return Uint8Array, not Buffer. The
        // server-side ownership check must compare via Buffer.from(...) and
        // must never use Buffer.isBuffer as a filter guard.
        const onChain = Buffer.from(ownHex, 'hex');
        const candidates = [splitOutput, ownOutput].filter(output => !!output);
        expect(candidates.some(expected => onChain.equals(Buffer.from(expected)))).to.be.true;
    });

    it('6. Multi-input Taproot HTLC Funding should build a valid transaction with multiple signed inputs', () => {
        const recipientKeyPair = PureBitcoinSwap.generateKeyPair();
        const recipientPubKey = Buffer.from(recipientKeyPair.publicKey);

        const payment = bitcoin.payments.p2tr({
            internalPubkey: PureBitcoinSwap.getXOnlyPubKey(recipientPubKey),
            network: bitcoin.networks.regtest
        });

        const htlcAddr = payment.address!;
        const changeAddr = payment.address!;

        const input1 = {
            txid: '1111111111111111111111111111111111111111111111111111111111111111',
            vout: 0,
            amount: 100000n,
            keyPair: recipientKeyPair,
            merkleRoot: Buffer.alloc(0),
            paymentOutput: payment.output!
        };

        const input2 = {
            txid: '2222222222222222222222222222222222222222222222222222222222222222',
            vout: 1,
            amount: 150000n,
            keyPair: recipientKeyPair,
            merkleRoot: Buffer.alloc(0),
            paymentOutput: payment.output!
        };

        const tx = PureBitcoinSwap.buildMultiInputHtlcFundingTx(
            [input1, input2],
            180000n,
            htlcAddr,
            changeAddr,
            10000n
        );

        expect(tx).to.be.an.instanceOf(bitcoin.Transaction);
        expect(tx.ins.length).to.equal(2);
        expect(tx.outs.length).to.equal(2);
        
        expect(tx.outs[0].value).to.equal(180000n);
        expect(tx.outs[1].value).to.equal(60000n);

        expect(tx.ins[0].witness).to.not.be.undefined;
        expect(tx.ins[0].witness!.length).to.equal(1);
        expect(tx.ins[1].witness).to.not.be.undefined;
        expect(tx.ins[1].witness!.length).to.equal(1);
    });

    it('7. HTLC funding can include a coordinator payment without reducing the contract output', () => {
        const recipientKeyPair = PureBitcoinSwap.generateKeyPair();
        const recipientPubKey = Buffer.from(recipientKeyPair.publicKey);
        const payment = bitcoin.payments.p2tr({
            internalPubkey: PureBitcoinSwap.getXOnlyPubKey(recipientPubKey),
            network: bitcoin.networks.regtest
        });
        const coordinator = bitcoin.payments.p2wpkh({
            hash: Buffer.alloc(20, 3),
            network: bitcoin.networks.regtest
        }).address!;
        const input = {
            txid: '33'.repeat(32), vout: 0, amount: 200000n,
            keyPair: recipientKeyPair, merkleRoot: Buffer.alloc(0), paymentOutput: payment.output!
        };
        const tx = PureBitcoinSwap.buildMultiInputHtlcFundingTx(
            [input], 180000n, payment.address!, payment.address!, 10000n,
            bitcoin.networks.regtest, coordinator, 2500n
        );
        expect(tx.outs.map(output => output.value)).to.deep.equal([180000n, 2500n, 7500n]);
        expect(Buffer.from(tx.outs[1].script).equals(bitcoin.address.toOutputScript(coordinator, bitcoin.networks.regtest))).to.equal(true);
    });

    it('8. Funding fails closed instead of silently underfunding the HTLC', () => {
        const keyPair = PureBitcoinSwap.generateKeyPair();
        const pubKey = Buffer.from(keyPair.publicKey);
        const payment = bitcoin.payments.p2tr({ internalPubkey: PureBitcoinSwap.getXOnlyPubKey(pubKey), network: bitcoin.networks.regtest });
        const input = { txid: '44'.repeat(32), vout: 0, amount: 100000n, keyPair, merkleRoot: Buffer.alloc(0), paymentOutput: payment.output! };
        expect(() => PureBitcoinSwap.buildMultiInputHtlcFundingTx(
            [input], 100000n, payment.address!, undefined, 5000n
        )).to.throw('Insufficient input');
    });

    it('9. Funding refuses to burn positive change when no change address is supplied', () => {
        const keyPair = PureBitcoinSwap.generateKeyPair();
        const pubKey = Buffer.from(keyPair.publicKey);
        const payment = bitcoin.payments.p2tr({ internalPubkey: PureBitcoinSwap.getXOnlyPubKey(pubKey), network: bitcoin.networks.regtest });
        const input = { txid: '55'.repeat(32), vout: 0, amount: 120000n, keyPair, merkleRoot: Buffer.alloc(0), paymentOutput: payment.output! };
        expect(() => PureBitcoinSwap.buildMultiInputHtlcFundingTx(
            [input], 100000n, payment.address!, undefined, 5000n
        )).to.throw('change address');
    });
});
