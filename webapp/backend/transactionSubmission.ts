import * as bitcoin from 'bitcoinjs-lib';

export const MAX_STANDARD_TRANSACTION_BYTES = 400_000;

export interface ParsedRawTransaction {
    hex: string;
    txid: string;
    byteLength: number;
    virtualSize: number;
    inputCount: number;
    outputCount: number;
}

/** Decode canonical, fully signed Bitcoin transaction hex before relaying it. */
export function parseRawTransactionHex(value: unknown): ParsedRawTransaction {
    if (typeof value !== 'string') throw new Error('Raw transaction must be provided as hexadecimal text');

    const hex = value.trim();
    if (!hex) throw new Error('Raw transaction hex is required');
    if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
        throw new Error('Raw transaction must contain only an even number of hexadecimal characters');
    }

    const byteLength = hex.length / 2;
    if (byteLength > MAX_STANDARD_TRANSACTION_BYTES) {
        throw new Error(`Raw transaction exceeds the ${MAX_STANDARD_TRANSACTION_BYTES.toLocaleString('en-US')}-byte relay limit`);
    }

    let transaction: bitcoin.Transaction;
    try {
        transaction = bitcoin.Transaction.fromHex(hex);
    } catch {
        throw new Error('Raw transaction could not be decoded');
    }

    if (transaction.ins.length === 0 || transaction.outs.length === 0) {
        throw new Error('Raw transaction must contain at least one input and one output');
    }

    return {
        hex: transaction.toHex(),
        txid: transaction.getId(),
        byteLength,
        virtualSize: transaction.virtualSize(),
        inputCount: transaction.ins.length,
        outputCount: transaction.outs.length
    };
}
