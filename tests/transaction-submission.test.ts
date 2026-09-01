import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { parseRawTransactionHex } from '../webapp/backend/transactionSubmission';

describe('BIP110 raw transaction submission', () => {
    const makeTransaction = () => {
        const tx = new bitcoin.Transaction();
        tx.addInput(Buffer.alloc(32, 1), 0);
        tx.addOutput(Buffer.from([bitcoin.opcodes.OP_TRUE]), 1_000n);
        return tx;
    };

    it('canonicalizes and summarizes valid transaction hex', () => {
        const tx = makeTransaction();
        const parsed = parseRawTransactionHex(`  ${tx.toHex().toUpperCase()}  `);

        expect(parsed.hex).to.equal(tx.toHex());
        expect(parsed.txid).to.equal(tx.getId());
        expect(parsed.inputCount).to.equal(1);
        expect(parsed.outputCount).to.equal(1);
        expect(parsed.byteLength).to.equal(tx.byteLength());
    });

    for (const invalid of ['', 'not hex', 'abc', '00']) {
        it(`rejects malformed input: ${JSON.stringify(invalid)}`, () => {
            expect(() => parseRawTransactionHex(invalid)).to.throw();
        });
    }
});
