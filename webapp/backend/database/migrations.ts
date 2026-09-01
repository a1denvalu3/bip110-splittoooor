import { dbRun } from './connection';

export async function runMigrations(): Promise<void> {
    console.log("[MIGRATION] Initiating database schema synchronization...");
    try {
        await dbRun(`
            CREATE TABLE IF NOT EXISTS offers (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                initiatorPubKey TEXT NOT NULL,
                initiatorB110Amount INTEGER NOT NULL,
                acceptorPubKey TEXT,
                acceptorBtcAmount INTEGER NOT NULL,
                hashLock TEXT NOT NULL,
                lockTime INTEGER NOT NULL,
                secondLockTime INTEGER,
                lockTimeOffset INTEGER,
                b110HtlcAddress TEXT,
                btcHtlcAddress TEXT,
                b110HtlcTxid TEXT,
                btcHtlcTxid TEXT,
                b110HtlcVout INTEGER,
                btcHtlcVout INTEGER,
                initiatorSettlementTxid TEXT,
                acceptorSettlementTxid TEXT,
                preimage TEXT,
                networkMode TEXT NOT NULL,
                createdAt INTEGER NOT NULL,
                backingTxid TEXT,
                backingVout INTEGER,
                backingChain TEXT,
                acceptorClaimed INTEGER DEFAULT 0,
                numsTweak TEXT,
                acceptorFundingTxid TEXT,
                acceptorFundingVout INTEGER
            )
        `);
        const additiveColumns = [
            ['secondLockTime', 'INTEGER'],
            ['lockTimeOffset', 'INTEGER'],
            ['b110HtlcVout', 'INTEGER'],
            ['btcHtlcVout', 'INTEGER']
            ,['initiatorSettlementTxid', 'TEXT']
            ,['acceptorSettlementTxid', 'TEXT']
            ,['numsTweak', 'TEXT']
            ,['acceptorFundingTxid', 'TEXT']
            ,['acceptorFundingVout', 'INTEGER']
        ];
        for (const [name, type] of additiveColumns) {
            try { await dbRun(`ALTER TABLE offers ADD COLUMN ${name} ${type}`); }
            catch (err: any) { if (!String(err.message).includes('duplicate column name')) throw err; }
        }
        await dbRun(`UPDATE offers SET lockTimeOffset = 1008 WHERE lockTimeOffset IS NULL`);

        // One live offer per backing outpoint / acceptor funding outpoint.
        // Existing duplicates are removed first, keeping the newest row.
        await dbRun(`
            DELETE FROM offers
            WHERE status NOT IN ('CLAIMED', 'REFUNDED')
              AND backingTxid IS NOT NULL AND backingVout IS NOT NULL
              AND rowid NOT IN (
                SELECT MAX(rowid) FROM offers
                WHERE status NOT IN ('CLAIMED', 'REFUNDED')
                  AND backingTxid IS NOT NULL AND backingVout IS NOT NULL
                GROUP BY backingTxid, backingVout
              )
        `);
        await dbRun(`
            CREATE UNIQUE INDEX IF NOT EXISTS idx_offers_backing_unique
            ON offers(backingTxid, backingVout)
            WHERE status NOT IN ('CLAIMED', 'REFUNDED')
        `);
        await dbRun(`
            DELETE FROM offers
            WHERE status IN ('ACCEPTED', 'FUNDED_INITIATOR', 'FUNDED_ACCEPTOR')
              AND acceptorFundingTxid IS NOT NULL AND acceptorFundingVout IS NOT NULL
              AND rowid NOT IN (
                SELECT MAX(rowid) FROM offers
                WHERE status IN ('ACCEPTED', 'FUNDED_INITIATOR', 'FUNDED_ACCEPTOR')
                  AND acceptorFundingTxid IS NOT NULL AND acceptorFundingVout IS NOT NULL
                GROUP BY acceptorFundingTxid, acceptorFundingVout
              )
        `);
        await dbRun(`
            CREATE UNIQUE INDEX IF NOT EXISTS idx_offers_acceptor_funding_unique
            ON offers(acceptorFundingTxid, acceptorFundingVout)
            WHERE status IN ('ACCEPTED', 'FUNDED_INITIATOR', 'FUNDED_ACCEPTOR')
        `);
        console.log("[MIGRATION] Migration checks complete. Offers table verified.");
    } catch (err: any) {
        console.error("[MIGRATION] Critical schema migration failure:", err.message);
        throw err;
    }
}
