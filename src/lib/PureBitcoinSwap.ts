import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory, ECPairAPI, ECPairInterface } from 'ecpair';
import { hashForUnifiedKeypath, SIGHASH_ALL_UNIFIED } from './unifiedSighash';
import { randomBytes } from 'crypto';

// Initialize Elliptic Curve library in bitcoinjs-lib for Schnorr and Taproot
bitcoin.initEccLib(ecc);
const ECPair: ECPairAPI = ECPairFactory(ecc);

export class PureBitcoinSwap {
    // Generate a random keypair for testing/development
    static generateKeyPair(): ECPairInterface {
        return ECPair.makeRandom({ network: bitcoin.networks.testnet });
    }

    // Helper to extract the 32-byte X-only public key from a compressed 33-byte public key
    static getXOnlyPubKey(pubKey: Buffer): Buffer {
        return pubKey.subarray(1, 33);
    }

    // Helper to compute standard SHA256 of a string preimage
    static computeHashLock(preimage: string): Buffer {
        return Buffer.from(bitcoin.crypto.sha256(Buffer.from(preimage, 'utf8')));
    }

    /**
     * 1. Inert leaf used only to keep deposit addresses separate from ordinary
     * wallet addresses. Splitting itself is a key-path spend protected by
     * SIGHASH_UNIFIED; this leaf is never revealed or executed.
     */
    static createSplitScript(ownerPubKey: Buffer): Buffer {
        this.getXOnlyPubKey(ownerPubKey); // validate the expected key shape
        return Buffer.from(bitcoin.script.compile([
            bitcoin.opcodes.OP_RETURN
        ]));
    }

    /**
     * 2. Claim Leaf (Success Path) - 100% BIP110 compliant, 0 conditional branching opcodes!
     * OP_SHA256 <hashLock> OP_EQUALVERIFY <recipientPubKey> OP_CHECKSIG
     */
    static createHtlcClaimScript(hashLock: Buffer, recipientPubKey: Buffer): Buffer {
        const xOnlyRecipient = this.getXOnlyPubKey(recipientPubKey);
        return Buffer.from(bitcoin.script.compile([
            bitcoin.opcodes.OP_SHA256,
            hashLock,
            bitcoin.opcodes.OP_EQUALVERIFY,
            xOnlyRecipient,
            bitcoin.opcodes.OP_CHECKSIG
        ]));
    }

    /**
     * 3. Refund Leaf (Timeout Path) - 100% BIP110 compliant, 0 conditional branching opcodes!
     * <lockTime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refundPubKey> OP_CHECKSIG
     */
    static createHtlcRefundScript(refundPubKey: Buffer, lockTime: number): Buffer {
        const xOnlyRefund = this.getXOnlyPubKey(refundPubKey);
        const locktimeBuffer = bitcoin.script.number.encode(lockTime);
        return Buffer.from(bitcoin.script.compile([
            locktimeBuffer,
            bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
            bitcoin.opcodes.OP_DROP,
            xOnlyRefund,
            bitcoin.opcodes.OP_CHECKSIG
        ]));
    }

    /**
     * 4. Build a Taproot Output committing to both MAST leaves.
     *
     * The internal key is K = H + u*G, where H is the BIP341 NUMS point with
     * unknown discrete logarithm and u (numsTweak) is a 32-byte scalar shared
     * between the swap participants. Since dlog(K) = dlog(H) + u and dlog(H)
     * is unknown, NO party can ever key-path spend the escrow — only the
     * claim and refund script leaves are usable. The counterparty verifies
     * the construction by re-deriving K from the published u and checking
     * that it yields the expected HTLC address.
     */
    static readonly HTLC_NUMS_POINT = Buffer.from('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex');

    // K = H + u*G. Throws if u is not a valid 32-byte scalar.
    static deriveHtlcInternalKey(numsTweak: Buffer): Buffer {
        if (!Buffer.isBuffer(numsTweak) || numsTweak.length !== 32) {
            throw new Error('NUMS tweak must be a 32-byte scalar');
        }
        const result = ecc.xOnlyPointAddTweak(new Uint8Array(this.HTLC_NUMS_POINT), new Uint8Array(numsTweak));
        if (!result) throw new Error('Invalid NUMS tweak scalar');
        return Buffer.from(result.xOnlyPubkey);
    }

    // Generate a random NUMS tweak (u) to share with the counterparty.
    static generateNumsTweak(): Buffer {
        for (;;) {
            const tweak = randomBytes(32);
            try { this.deriveHtlcInternalKey(tweak); return tweak; } catch { /* retry */ }
        }
    }

    static createTaprootHtlc(
        numsTweak: Buffer, // u scalar; internal key = H + u*G (key path unspendable)
        hashLock: Buffer,
        recipientPubKey: Buffer,
        refundPubKey: Buffer,
        lockTime: number,
        network: bitcoin.Network = bitcoin.networks.testnet
    ): bitcoin.payments.Payment {
        const claimScript = this.createHtlcClaimScript(hashLock, recipientPubKey);
        const refundScript = this.createHtlcRefundScript(refundPubKey, lockTime);

        const claimLeaf = { output: new Uint8Array(claimScript) };
        const refundLeaf = { output: new Uint8Array(refundScript) };

        return bitcoin.payments.p2tr({
            internalPubkey: this.deriveHtlcInternalKey(numsTweak),
            scriptTree: [claimLeaf, refundLeaf],
            network
        });
    }

    // Helper to compute Taproot Tapleaf Hash
    static tapleafHash(script: Buffer): Buffer {
        const prefix = Buffer.concat([
            Buffer.from([0xc0]), // leafVersion
            Buffer.from([script.length]), // compact size
            script
        ]);
        return Buffer.from(bitcoin.crypto.taggedHash('TapLeaf', prefix));
    }

    // Helper to mathematically calculate the Taproot Tweaked Keypair (including odd y-parity negation)
    // Helper to negate the private key for Schnorr signing if the public key has odd y-parity
    static getSchnorrKeyPair(keyPair: ECPairInterface, network: bitcoin.Network = bitcoin.networks.regtest): ECPairInterface {
        const isOdd = keyPair.publicKey[0] === 0x03;
        if (!isOdd) return keyPair;
        
        const curveOrder = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
        let privKeyBuffer = Buffer.from(keyPair.privateKey!);
        const privInt = BigInt('0x' + privKeyBuffer.toString('hex'));
        const negatedInt = curveOrder - privInt;
        let negatedHex = negatedInt.toString(16);
        while (negatedHex.length < 64) negatedHex = '0' + negatedHex;
        privKeyBuffer = Buffer.from(negatedHex, 'hex');
        
        return ECPair.fromPrivateKey(privKeyBuffer, { network });
    }

    static getTweakedKeyPair(keyPair: ECPairInterface, merkleRoot: Buffer, network: bitcoin.Network = bitcoin.networks.regtest): ECPairInterface {
        const xOnlyKey = this.getXOnlyPubKey(Buffer.from(keyPair.publicKey));
        const tweak = Buffer.from(bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([xOnlyKey, merkleRoot])));
        
        const isOdd = keyPair.publicKey[0] === 0x03;
        let privKeyBuffer = Buffer.from(keyPair.privateKey!);
        if (isOdd) {
            const curveOrder = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
            const privInt = BigInt('0x' + privKeyBuffer.toString('hex'));
            const negatedInt = curveOrder - privInt;
            let negatedHex = negatedInt.toString(16);
            while (negatedHex.length < 64) negatedHex = '0' + negatedHex;
            privKeyBuffer = Buffer.from(negatedHex, 'hex');
        }
        
        const tweakedPrivateKeyBuffer = ecc.privateAdd(privKeyBuffer, tweak)!;
        return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKeyBuffer), { network });
    }

    // Helper to build Split Payment setup
    static createSplitPayment(ownerPubKey: Buffer, network: bitcoin.Network = bitcoin.networks.regtest) {
        const script = this.createSplitScript(ownerPubKey);
        const payment = bitcoin.payments.p2tr({
            internalPubkey: this.getXOnlyPubKey(ownerPubKey),
            scriptTree: { output: script },
            redeem: { output: script, redeemVersion: 0xc0 },
            network
        });
        const leafHash = this.tapleafHash(script);
        return { payment, script, leafHash };
    }

    /**
     * Builds and signs a BLAKE2b-chain split spend using SIGHASH_UNIFIED.
     * Bitcoin nodes do not recognize the 0x20 opt-in bit and reject this
     * signature, so the original output remains spendable on Bitcoin.
     */
    static buildUnifiedSplitTx(
        ownerKeyPair: ECPairInterface,
        fundTxid: string,
        outputIndex: number,
        inputSats: bigint,
        outputSats: bigint,
        destAddr: string,
        splitPayment: bitcoin.payments.Payment,
        splitScript: Buffer,
        network: bitcoin.Network = bitcoin.networks.regtest
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(fundTxid, 'hex').reverse(), outputIndex);
        tx.addOutput(bitcoin.address.toOutputScript(destAddr, network), outputSats);

        const leafHash = this.tapleafHash(splitScript);
        const sighash = hashForUnifiedKeypath(tx, 0, [{
            value: inputSats,
            script: splitPayment.output!
        }]);
        const tweakedPair = this.getTweakedKeyPair(ownerKeyPair, leafHash, network);
        const sig = Buffer.concat([
            Buffer.from(tweakedPair.signSchnorr(sighash)),
            Buffer.from([SIGHASH_ALL_UNIFIED])
        ]);
        tx.setWitness(0, [sig]);

        return tx;
    }

    /**
     * Builds and signs an HTLC funding transaction spending from a split destination P2TR keypath UTXO.
     */
    static buildHtlcFundingTx(
        ownerKeyPair: ECPairInterface,
        splitTxid: string,
        outputIndex: number,
        inputSats: bigint,
        outputSats: bigint,
        htlcAddr: string,
        splitDestPayment: bitcoin.payments.Payment,
        merkleRoot: Buffer = Buffer.alloc(0),
        changeAddr?: string,
        feeSats: bigint = 5000n,
        network: bitcoin.Network = bitcoin.networks.regtest
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(splitTxid, 'hex').reverse(), outputIndex);
        
        const finalOutputSats = outputSats;
        const changeSats = inputSats - finalOutputSats - feeSats;
        if (finalOutputSats <= 0n || feeSats < 0n || changeSats < 0n) throw new Error('Insufficient input for the exact HTLC amount and fee');
        if (changeSats > 0n && !changeAddr) throw new Error('A change address is required; refusing to donate change as miner fee');

        // 1. Add HTLC contract output
        tx.addOutput(bitcoin.address.toOutputScript(htlcAddr, network), finalOutputSats);

        // 2. Add change output if there's leftover change and a change address is provided
        if (changeSats > 0n && changeAddr) {
            tx.addOutput(bitcoin.address.toOutputScript(changeAddr, network), changeSats);
        }

        const sighash = tx.hashForWitnessV1(
            0, [splitDestPayment.output!], [inputSats], bitcoin.Transaction.SIGHASH_DEFAULT
        );

        // Sign the funding spend (P2TR Keypath spend with the given merkleRoot tweak)
        const tweakedPair = this.getTweakedKeyPair(ownerKeyPair, merkleRoot, network);
        const sig = Buffer.from(tweakedPair.signSchnorr(sighash));

        tx.setWitness(0, [sig]);

        return tx;
    }

    /**
     * Builds and signs an HTLC funding transaction spending from multiple split destination UTXOs.
     */
    static buildMultiInputHtlcFundingTx(
        inputs: Array<{
            txid: string;
            vout: number;
            amount: bigint;
            keyPair: ECPairInterface;
            merkleRoot: Buffer;
            paymentOutput: Buffer | Uint8Array;
        }>,
        outputSats: bigint,
        htlcAddr: string,
        changeAddr?: string,
        feeSats: bigint = 5000n,
        network: bitcoin.Network = bitcoin.networks.regtest,
        coordinatorAddress?: string,
        coordinatorFeeSats: bigint = 0n
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;

        // Add all inputs
        for (const input of inputs) {
            tx.addInput(Buffer.from(input.txid, 'hex').reverse(), input.vout);
        }

        const totalInputSats = inputs.reduce((sum, input) => sum + input.amount, 0n);
        const finalOutputSats = outputSats;
        const changeSats = totalInputSats - finalOutputSats - coordinatorFeeSats - feeSats;
        if (inputs.length === 0 || finalOutputSats <= 0n || feeSats < 0n || coordinatorFeeSats < 0n || changeSats < 0n) {
            throw new Error('Insufficient input for the exact HTLC amount, coordinator fee, and miner fee');
        }
        if (changeSats > 0n && !changeAddr) throw new Error('A change address is required; refusing to donate change as miner fee');

        // 1. Add HTLC contract output
        tx.addOutput(bitcoin.address.toOutputScript(htlcAddr, network), finalOutputSats);

        if (coordinatorFeeSats > 0n) {
            if (!coordinatorAddress) throw new Error('Coordinator address is required for a non-zero coordinator fee');
            tx.addOutput(bitcoin.address.toOutputScript(coordinatorAddress, network), coordinatorFeeSats);
        }

        // 2. Add change output if there's leftover change and a change address is provided
        if (changeSats > 0n && changeAddr) {
            tx.addOutput(bitcoin.address.toOutputScript(changeAddr, network), changeSats);
        }

        // Prepare the inputs' output scripts and amounts array for the witness signature sighash
        const prevOutScripts = inputs.map(input => input.paymentOutput);
        const prevAmounts = inputs.map(input => input.amount);

        // Generate signatures and set witness for each input
        for (let i = 0; i < inputs.length; i++) {
            const input = inputs[i];
            const sighash = tx.hashForWitnessV1(
                i, prevOutScripts, prevAmounts, bitcoin.Transaction.SIGHASH_DEFAULT
            );

            // Sign the funding spend (P2TR Keypath spend with the given merkleRoot tweak)
            const tweakedPair = this.getTweakedKeyPair(input.keyPair, input.merkleRoot, network);
            const sig = Buffer.from(tweakedPair.signSchnorr(sighash));

            tx.setWitness(i, [sig]);
        }

        return tx;
    }

    /**
     * Builds and signs an HTLC claim transaction spending via the ClaimLeaf scriptpath.
     */
    static buildHtlcClaimTx(
        recipientKeyPair: ECPairInterface,
        htlcFundTxid: string,
        outputIndex: number,
        inputSats: bigint,
        outputSats: bigint,
        claimDestAddr: string,
        hashLock: Buffer,
        preimage: Buffer,
        htlcPayment: bitcoin.payments.Payment,
        numsTweak: Buffer,
        refundPubKey: Buffer,
        lockTime: number,
        network: bitcoin.Network = bitcoin.networks.regtest
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(htlcFundTxid, 'hex').reverse(), outputIndex);
        tx.addOutput(bitcoin.address.toOutputScript(claimDestAddr, network), outputSats);

        const claimScript = this.createHtlcClaimScript(hashLock, Buffer.from(recipientKeyPair.publicKey));
        const leafHash = this.tapleafHash(claimScript);

        const sighash = tx.hashForWitnessV1(
            0, [htlcPayment.output!], [inputSats], bitcoin.Transaction.SIGHASH_DEFAULT, leafHash
        );
        const schnorrKey = this.getSchnorrKeyPair(recipientKeyPair, network);
        const sig = Buffer.from(schnorrKey.signSchnorr(sighash));

        // Reconstruct the scriptTree to get the correct control block
        const claimLeafInfo = { output: claimScript };
        const refundScript = this.createHtlcRefundScript(refundPubKey, lockTime);
        const refundLeafInfo = { output: refundScript };

        const claimPayment = bitcoin.payments.p2tr({
            internalPubkey: this.deriveHtlcInternalKey(numsTweak),
            scriptTree: [claimLeafInfo, refundLeafInfo] as any,
            redeem: {
                output: claimScript,
                redeemVersion: 0xc0
            },
            network
        });

        const controlBlock = claimPayment.witness![1];

        tx.setWitness(0, [
            sig,
            preimage,
            claimScript,
            controlBlock
        ]);

        return tx;
    }

    /**
     * Builds and signs an HTLC refund transaction spending via the RefundLeaf scriptpath.
     */
    static buildHtlcRefundTx(
        refundKeyPair: ECPairInterface,
        htlcFundTxid: string,
        outputIndex: number,
        inputSats: bigint,
        outputSats: bigint,
        refundDestAddr: string,
        hashLock: Buffer,
        recipientPubKey: Buffer,
        htlcPayment: bitcoin.payments.Payment,
        numsTweak: Buffer,
        lockTime: number,
        network: bitcoin.Network = bitcoin.networks.regtest
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;
        
        // nLockTime MUST be set on the transaction for OP_CHECKLOCKTIMEVERIFY to pass!
        tx.locktime = lockTime;
        
        tx.addInput(Buffer.from(htlcFundTxid, 'hex').reverse(), outputIndex);
        tx.addOutput(bitcoin.address.toOutputScript(refundDestAddr, network), outputSats);

        // Inputs must set sequence to less than 0xffffffff for locktime to be enabled!
        tx.ins[0].sequence = 0xfffffffe;

        const refundScript = this.createHtlcRefundScript(Buffer.from(refundKeyPair.publicKey), lockTime);
        const leafHash = this.tapleafHash(refundScript);

        const sighash = tx.hashForWitnessV1(
            0, [htlcPayment.output!], [inputSats], bitcoin.Transaction.SIGHASH_DEFAULT, leafHash
        );
        const schnorrKey = this.getSchnorrKeyPair(refundKeyPair, network);
        const sig = Buffer.from(schnorrKey.signSchnorr(sighash));

        // Reconstruct scriptTree to get correct control block
        const claimScript = this.createHtlcClaimScript(hashLock, recipientPubKey);
        const claimLeafInfo = { output: claimScript };
        const refundLeafInfo = { output: refundScript };

        const refundPayment = bitcoin.payments.p2tr({
            internalPubkey: this.deriveHtlcInternalKey(numsTweak),
            scriptTree: [claimLeafInfo, refundLeafInfo] as any,
            redeem: {
                output: refundScript,
                redeemVersion: 0xc0
            },
            network
        });

        const controlBlock = refundPayment.witness![1];

        tx.setWitness(0, [
            sig,
            refundScript,
            controlBlock
        ]);

        return tx;
    }

    /**
     * Builds and signs a withdrawal transaction spending from either a split contract (P2TR splitAddress)
     * or a standard own address (P2TR ownAddress) to an arbitrary external address.
     */
    static buildWithdrawalTx(
        ownerKeyPair: ECPairInterface,
        txid: string,
        vout: number,
        inputSats: bigint,
        withdrawSats: bigint,
        destAddress: string,
        isSplitAddress: boolean,
        isMainChain: boolean,
        changeAddress?: string,
        feeSats: bigint = 5000n,
        network: bitcoin.Network = bitcoin.networks.regtest
    ): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = 2;
        tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);

        const finalWithdrawSats = withdrawSats;
        const changeSats = inputSats - finalWithdrawSats - feeSats;
        if (finalWithdrawSats <= 0n || feeSats < 0n || changeSats < 0n) throw new Error('Insufficient input for the exact withdrawal amount and fee');
        if (changeSats > 0n && !changeAddress) throw new Error('A change address is required; refusing to donate change as miner fee');

        // 1. Add withdrawal output
        tx.addOutput(bitcoin.address.toOutputScript(destAddress, network), finalWithdrawSats);

        // 2. Add change output if leftover change exists and changeAddress is specified
        if (changeSats > 0n && changeAddress) {
            tx.addOutput(bitcoin.address.toOutputScript(changeAddress, network), changeSats);
        }

        const pubKey = Buffer.from(ownerKeyPair.publicKey);
        void isMainChain; // retained for API compatibility; signing is identical on both chains

        if (isSplitAddress) {
            // Need script tree for split contract
            const splitPaymentInfo = this.createSplitPayment(pubKey, network);

            const sighash = tx.hashForWitnessV1(
                0, [splitPaymentInfo.payment.output!], [inputSats], bitcoin.Transaction.SIGHASH_DEFAULT
            );
            const tweakedPair = this.getTweakedKeyPair(ownerKeyPair, splitPaymentInfo.leafHash, network);
            const sig = Buffer.from(tweakedPair.signSchnorr(sighash));
            tx.setWitness(0, [sig]);
        } else {
            // Simple P2TR Keypath spend from ownAddress (requires standard TapTweak committing to empty script root)
            const ownPayment = bitcoin.payments.p2tr({
                internalPubkey: this.getXOnlyPubKey(pubKey),
                network
            });

            const sighash = tx.hashForWitnessV1(
                0, [ownPayment.output!], [inputSats], bitcoin.Transaction.SIGHASH_DEFAULT
            );
            const tweakedPair = this.getTweakedKeyPair(ownerKeyPair, Buffer.alloc(0), network);
            const sig = Buffer.from(tweakedPair.signSchnorr(sighash));
            tx.setWitness(0, [sig]);
        }

        return tx;
    }

    /**
     * Verifies that a given Taproot HTLC address matches the expected script leaves and parameters.
     */
    static verifyTaprootHtlcAddress(
        addressToVerify: string,
        numsTweak: Buffer,
        hashLock: Buffer,
        recipientPubKey: Buffer,
        refundPubKey: Buffer,
        lockTime: number,
        network: bitcoin.Network = bitcoin.networks.testnet
    ): boolean {
        try {
            const expectedHtlc = this.createTaprootHtlc(
                numsTweak,
                hashLock,
                recipientPubKey,
                refundPubKey,
                lockTime,
                network
            );
            return expectedHtlc.address === addressToVerify;
        } catch {
            return false;
        }
    }

    /**
     * Verifies that a given output scriptPubkey matches the expected script leaves and parameters.
     */
    static verifyTaprootHtlcOutput(
        outputToVerify: Buffer,
        numsTweak: Buffer,
        hashLock: Buffer,
        recipientPubKey: Buffer,
        refundPubKey: Buffer,
        lockTime: number,
        network: bitcoin.Network = bitcoin.networks.testnet
    ): boolean {
        try {
            const expectedHtlc = this.createTaprootHtlc(
                numsTweak,
                hashLock,
                recipientPubKey,
                refundPubKey,
                lockTime,
                network
            );
            if (!expectedHtlc.output || !outputToVerify) return false;
            return Buffer.from(expectedHtlc.output).equals(Buffer.from(outputToVerify));
        } catch {
            return false;
        }
    }
}
