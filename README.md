# Replay-Protected Atomic Swap Between Bitcoin and the BLAKE2b Fork

A replay-protected atomic swap protocol for Bitcoin and the BLAKE2b proof-of-work fork. Coin separation uses the fork's native `SIGHASH_UNIFIED` signing mode from [Bitcoin Knots PR #357](https://github.com/bitcoinknots/bitcoin/pull/357). HTLCs remain compact Taproot MAST contracts implemented with `bitcoinjs-lib` and `tiny-secp256k1`.

---

## Technical Overview

The original BIP110 activation did not acquire enough proof of work. The fork subsequently changed its mining algorithm to BLAKE2b and introduced `SIGHASH_UNIFIED`, an opt-in signature digest domain that legacy Bitcoin does not recognize.

To overcome this restriction while ensuring cross-chain atomic swaps remain completely secure and replay-protected, this protocol utilizes two key design paradigms:
1. **Native coin separation**: A Taproot key-path spend signed with `SIGHASH_ALL|SIGHASH_UNIFIED` (`0x21`) confirms on the BLAKE2b chain and is invalid on Bitcoin. The original outpoint remains available on Bitcoin.
2. **Pure Multi-Contract MAST Leaves**: HTLC claim and refund logic stays flattened into independent Taproot leaves.

---

## Native Coin Split

For an outpoint shared by both chains, the wallet constructs one BLAKE2b-chain transaction and signs its Taproot key path over the unified digest. Its Schnorr signature is 65 bytes and ends in `0x21`. A Bitcoin node rejects the undefined Taproot hash type, while an activated BLAKE2b node verifies the fork-specific digest. After confirmation, the new output exists only on BLAKE2b and the original output exists only on Bitcoin.

The deposit output includes a one-byte inert `OP_RETURN` leaf solely so deposit addresses remain distinct from ordinary wallet/change addresses. That leaf is never revealed and provides no replay protection.

---

## Script Leaf Specifications

By eliminating sCrypt boilerplate and hand-crafting script elements, we achieve extremely compact, fee-efficient bytecode sizes:

### 1. Split Deposit Leaf
* **OPCODE Structure**: `OP_RETURN`
* **Bytecode Size**: **1 byte**
* **Spend path**: Taproot key path with `SIGHASH_ALL|SIGHASH_UNIFIED`

### 2. HTLC Claim Leaf
* **OPCODE Structure**: `OP_SHA256 <hashLock> OP_EQUALVERIFY <recipientPubKey> OP_CHECKSIG`
* **Bytecode Size**: **69 bytes** (100% compliant with BIP110's opcode ban; contains 0 conditional branches)

### 3. HTLC Refund Leaf
* **OPCODE Structure**: `<lockTime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refundPubKey> OP_CHECKSIG`
* **Bytecode Size**: **39 bytes** (100% compliant with BIP110's opcode ban; contains 0 conditional branches)

---

## Integration Tests & Verification

The integration suite runs against Bitcoin Core v26.0 and BLAKE2b-enabled Bitcoin Knots 29.4.1 rc4. Regtest activates the `blake2b` buried deployment at block 112, after 110 shared maturity blocks and one shared funding block.

### Prerequisites
Make sure Docker is running on your host machine.

### Setup and Running Nodes
1. Install dependencies:
   ```bash
   npm install
   ```
2. Spin up the containerized Bitcoin Core (RPC port 18443) and Bitcoin Knots (RPC port 18444) nodes:
   ```bash
   docker-compose up -d
   ```
   * **BLAKE2b Activation:** Compose schedules `-testactivationheight=blake2b@112` on the Knots regtest node.
   * **Dual-Node P2P Connection:** The Core and Knots nodes are automatically connected to each other over P2P at startup via an automated `addnode` initialization sequence. This establishes a fully connected block propagation topology prior to the hard fork split.

### Running Verification Tests

#### 1. Coin Split Primitive Test
Asserts that Knots accepts a `SIGHASH_UNIFIED` Taproot key-path transaction, Bitcoin rejects its `0x21` hash type, and the shared outpoint separates correctly:
```bash
npm run test:split
```

#### 2. Full Double-Sided Atomic Swap Test
Simulates the entire swap end-to-end: double-sided splitting, double-sided HTLC funding, preimage extraction, and final claims:
```bash
npm run test:swap
```

#### 3. Swap Failure & Refund Test
Verifies all failure modes under real consensus rules: rejects claims with incorrect preimages, rejects premature refund spends, and successfully executes timelock-expired refund spends using the `RefundLeaf` scriptpath:
```bash
npm run test:refund
```

---

## Running the Interactive WebApp (Regtest Simulation)

You can run the full-stack interactive atomic swap web application locally to test and simulate splits, orders, claims, and refunds via a premium web UI.

### 1. Boot up the Nodes & Backend Server
This command will spin up the docker containers (Core + Knots), wipe any previous regtest DB to start fresh from zero, and launch the Express backend on port `4000`:
```bash
npm run server
```

### 2. Start the Frontend Client
This command will start the Vite React development server:
```bash
npm run frontend
```

### 3. Open the Web Portal
Once both services are running, open your web browser and navigate to:
```
http://localhost:3000
```

* **Step-by-Step Simulation Guide**:
  1. **Tab 1: Unified Wallet & Coin Faucet**: Mine 110 shared blocks, use the Bitcoin faucet once so the deposit confirms in shared block 111, then mine one BLAKE2b block to activate the fork at 112. Do not create two independent faucet transactions: an unsplit coin must be the same `txid:vout` on both chains.
  2. **Tab 2: Bilateral Splitter**: Select your deposited unsplit UTXO, download your recovery backup, then click **"Split Coins (SIGHASH_UNIFIED)"**. The transaction is broadcast only to the BLAKE2b chain and cannot replay on Bitcoin.
  3. **Tab 3: Marketplace Lobby**: Publish a swap offer to sell your isolated BIP110 coins in exchange for Mainnet BTC, customized with custom premiums or discounts.
  4. **Tab 4: My Swaps & Offers**: Monitor your listings, delete outstanding listings, walk back acceptances, or accept your own listing as a counterparty (by generating a new active P2TR address in Tab 1!).
  5. **Tab 5: Swap Wizard**: Orchestrate the end-to-end atomic swap using the step-by-step visual workflow to fund escrows, extract revealed preimages, settle claims, or simulate expired refund scripts.

### Relaying a Wallet Transaction to BIP110

After the networks have separated, a wallet may broadcast a transaction only to Bitcoin even though the same pre-split inputs remain spendable on BIP110. In **Unified Wallet**, expand **Relay a Transaction to BIP110**, copy the signed raw transaction hex from the wallet, review the locally decoded transaction ID and size, and submit it. The backend relays it only to the BIP110 chain: through the Knots RPC node in regtest, or the configured BIP110 RPC/Esplora source in mainnet mode.

The relay accepts canonical serialized transaction hex, not a PSBT, private key, seed phrase, or wallet file. The BIP110 node still performs all normal consensus and mempool-policy validation.

## Production Mainnet Chain Data Configuration

Each chain can independently use either an Esplora-compatible HTTP API or a Bitcoin JSON-RPC node. Set the corresponding `*_RPC_HOST` to select RPC; otherwise the explorer URL is used. RPC configuration uses separate host, port, username, and password variables. Only explorer endpoints are configured as URLs.

For example, use mempool.space for Bitcoin and a local Knots/BIP110 RPC node:

```bash
BITCOIN_EXPLORER_URL=https://mempool.space \
BIP110_RPC_HOST=127.0.0.1 \
BIP110_RPC_PORT=8332 \
BIP110_RPC_USER=splittoooor \
BIP110_RPC_PASSWORD='replace-me' \
npm run server:mainnet
```

Or configure RPC for both chains:

```bash
BITCOIN_RPC_HOST=127.0.0.1 \
BITCOIN_RPC_PORT=8332 \
BITCOIN_RPC_USER=bitcoin \
BITCOIN_RPC_PASSWORD='replace-me' \
BIP110_RPC_HOST=127.0.0.1 \
BIP110_RPC_PORT=8334 \
BIP110_RPC_USER=bip110 \
BIP110_RPC_PASSWORD='replace-me' \
npm run server:mainnet
```

RPC mode creates and persists a disabled-private-keys wallet named `watchonly`. Addresses are imported when the frontend first scans them, so the backend must see an address before it receives funds. Preserve the node wallet directory across restarts. Raw transaction lookup on a pruned node only works while the relevant block remains available; transactions cached by Redis remain available to the backend for the configured cache lifetime.

Explorer mode requires chain height, transaction status, address UTXOs, and raw transaction broadcast. Recommended fees may be supplied by either Mempool's `/api/v1/fees/recommended` endpoint or Esplora's `/api/fee-estimates` endpoint.
Reads from either source are shared through Redis and a bounded process-local cache, so repeated per-address UTXO requests do not repeatedly hit the upstream. The wallet endpoint retains expired values briefly as display-only stale fallbacks when an explorer is unavailable or rate-limited; transaction-safety checks still fail closed. `npm run server:mainnet` starts the bundled Redis service automatically.

```bash
BITCOIN_EXPLORER_URL=https://mempool.space \
BIP110_EXPLORER_URL=https://your-bip110-mempool.example \
npm run server:mainnet
```

Multiple Bitcoin explorers can be configured as a comma-separated pool. The current request is retried against the next endpoint whenever an explorer returns HTTP 429, and that endpoint remains active until a later 429 rotates the pool again. `BITCOIN_EXPLORER_URL` remains the single-endpoint fallback.

```bash
BITCOIN_EXPLORER_URLS=https://mempool.space,https://another-esplora.example \
npm run server:mainnet
```

Use `REDIS_URL` to point at an external Redis instance. Cache lifetimes can be tuned with
`EXPLORER_TIP_CACHE_SECONDS`, `EXPLORER_UTXO_CACHE_SECONDS`,
`EXPLORER_CONFIRMATION_CACHE_SECONDS`, `EXPLORER_RAW_TX_CACHE_SECONDS`, and
`EXPLORER_FEE_CACHE_SECONDS`. Defaults are 20, 60, 60, 86400, and 60 seconds respectively.

Coordinator fees are disabled by default. To require funding transactions from makers (initiators)
and takers (acceptors) to pay the coordinator, configure percentage values and a receive address:

```bash
MAKER_FEE_PERCENT=0.25 \
TAKER_FEE_PERCENT=0.50 \
COORDINATOR_RECEIVE_ADDR=bc1p... \
npm run server:mainnet
```

Percentages are applied to the swap amount on the chain being locked and rounded up to the next satoshi.
Outputs to the receive address are summed. `COORDINATOR_RECEIVE_ADDR` may be omitted while both fees remain
at their default `0` percent.

The frontend uses same-origin `/api` in production. Set `VITE_API_BASE_URL` at build time only when the backend is hosted on a different origin.

---

## References

* **Formalized Scheme Specification Gist**: [Double-Sided Replay-Protected Atomic Swap Gist](https://gist.github.com/a1denvalu3/7641b514bdb3b9de1b0f87a96c19cbf4)
* **Engines Used**: `bitcoinjs-lib` (v7), `tiny-secp256k1` (v2), and standard Bitcoin Regtest nodes.
