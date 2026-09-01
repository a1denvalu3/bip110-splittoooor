import * as bitcoin from 'bitcoinjs-lib';

export const SIGHASH_UNIFIED = 0x20;
export const SIGHASH_ALL_UNIFIED = bitcoin.Transaction.SIGHASH_ALL | SIGHASH_UNIFIED;

export interface SpentOutput { value: bigint; script: Buffer | Uint8Array; }

const sha256 = (value: Buffer): Buffer => Buffer.from(bitcoin.crypto.sha256(value));
const taggedHash = (tag: string, message: Buffer): Buffer => {
    const tagHash = sha256(Buffer.from(tag, 'utf8'));
    return sha256(Buffer.concat([tagHash, tagHash, message]));
};
const uint32LE = (value: number): Buffer => {
    const result = Buffer.allocUnsafe(4);
    result.writeUInt32LE(value >>> 0);
    return result;
};
const int64LE = (value: bigint): Buffer => {
    if (value < 0n || value > 0x7fffffffffffffffn) throw new Error('Spent-output value is outside the signed 64-bit range');
    const result = Buffer.allocUnsafe(8);
    result.writeBigInt64LE(value);
    return result;
};
const compactSize = (value: number): Buffer => {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid CompactSize value');
    if (value < 0xfd) return Buffer.from([value]);
    if (value <= 0xffff) {
        const result = Buffer.allocUnsafe(3);
        result[0] = 0xfd;
        result.writeUInt16LE(value, 1);
        return result;
    }
    if (value <= 0xffffffff) return Buffer.concat([Buffer.from([0xfe]), uint32LE(value)]);
    const result = Buffer.allocUnsafe(9);
    result[0] = 0xff;
    result.writeBigUInt64LE(BigInt(value), 1);
    return result;
};
const serializeScript = (script: Buffer | Uint8Array): Buffer => {
    const bytes = Buffer.from(script);
    return Buffer.concat([compactSize(bytes.length), bytes]);
};
const serializeOutput = (output: SpentOutput): Buffer => Buffer.concat([int64LE(output.value), serializeScript(output.script)]);

export function hashForUnifiedKeypath(
    transaction: bitcoin.Transaction,
    inputIndex: number,
    spentOutputs: SpentOutput[],
    hashType: number = SIGHASH_ALL_UNIFIED
): Buffer {
    if (hashType !== SIGHASH_ALL_UNIFIED) throw new Error('Only SIGHASH_ALL|UNIFIED is supported');
    if (!Number.isSafeInteger(inputIndex) || inputIndex < 0 || inputIndex >= transaction.ins.length) throw new Error('Unified sighash input index is out of range');
    if (spentOutputs.length !== transaction.ins.length) throw new Error('Unified sighash requires the spent output for every input');

    const prevouts = Buffer.concat(transaction.ins.map(input => Buffer.concat([Buffer.from(input.hash), uint32LE(input.index)])));
    const amounts = Buffer.concat(spentOutputs.map(output => int64LE(output.value)));
    const scripts = Buffer.concat(spentOutputs.map(output => serializeScript(output.script)));
    const sequences = Buffer.concat(transaction.ins.map(input => uint32LE(input.sequence)));
    const outputs = Buffer.concat(transaction.outs.map(output => serializeOutput({ value: output.value, script: output.script })));
    const message = Buffer.concat([
        Buffer.from([0x00, hashType]), uint32LE(transaction.version), uint32LE(transaction.locktime), Buffer.from([0x00]),
        sha256(prevouts), sha256(amounts), sha256(scripts), sha256(sequences), sha256(outputs),
        Buffer.from([0x02]), uint32LE(inputIndex), Buffer.from([0x00])
    ]);
    return taggedHash('UnifiedSighash', message);
}
