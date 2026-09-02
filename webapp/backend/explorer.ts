import axios, { AxiosError, AxiosInstance } from 'axios';

export type ExplorerChain = 'main' | 'bip110';

export interface ExplorerUtxo {
    txid: string;
    vout: number;
    amount: number;
    confirmations: number;
}

export interface RecommendedFees {
    fastestFee: number;
    halfHourFee: number;
    hourFee: number;
    economyFee: number;
    minimumFee: number;
}

type HttpClient = Pick<AxiosInstance, 'get' | 'post'>;

export class ExplorerRequestError extends Error {
    readonly operation: string;
    readonly status?: number;

    constructor(operation: string, cause: unknown) {
        const axiosError = cause as AxiosError;
        const status = axiosError.response?.status;
        const responseMessage = typeof axiosError.response?.data === 'string'
            ? axiosError.response.data
            : undefined;
        const detail = responseMessage || axiosError.message || String(cause);
        super(`${operation} failed${status ? ` (HTTP ${status})` : ''}: ${detail}`);
        this.name = 'ExplorerRequestError';
        this.operation = operation;
        this.status = status;
    }
}

export class MempoolExplorerClient {
    readonly baseUrl: string;
    private readonly http: HttpClient;
    private readonly timeoutMs: number;

    constructor(baseUrl: string, http: HttpClient = axios, timeoutMs = 5000) {
        const normalizedUrl = baseUrl.trim().replace(/\/+$/, '').replace(/\/api$/, '');
        if (!normalizedUrl) throw new Error('Explorer base URL is required');

        let parsed: URL;
        try {
            parsed = new URL(normalizedUrl);
        } catch {
            throw new Error(`Invalid explorer base URL: ${baseUrl}`);
        }
        if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
            throw new Error('Explorer base URL must use HTTPS outside localhost');
        }

        this.baseUrl = normalizedUrl;
        this.http = http;
        this.timeoutMs = timeoutMs;
    }

    private api(path: string): string {
        return `${this.baseUrl}/api${path}`;
    }

    async getTransactionConfirmations(txid: string): Promise<number> {
        try {
            const response = await this.http.get(this.api(`/tx/${encodeURIComponent(txid)}/status`), {
                timeout: this.timeoutMs
            });
            if (typeof response.data?.confirmed !== 'boolean') {
                throw new Error('Explorer returned an invalid transaction-status response');
            }
            return response.data.confirmed ? 1 : 0;
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            throw new ExplorerRequestError('Transaction status lookup', error);
        }
    }

    async getRawTransaction(txid: string): Promise<string> {
        try {
            const response = await this.http.get(this.api(`/tx/${encodeURIComponent(txid)}/hex`), {
                timeout: this.timeoutMs
            });
            if (typeof response.data !== 'string' || !/^[0-9a-f]+$/i.test(response.data) || response.data.length % 2 !== 0) {
                throw new Error('Explorer returned invalid raw transaction hex');
            }
            return response.data;
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            throw new ExplorerRequestError('Raw transaction lookup', error);
        }
    }

    async getAddressUtxos(address: string): Promise<ExplorerUtxo[]> {
        try {
            const response = await this.http.get(this.api(`/address/${encodeURIComponent(address)}/utxo`), {
                timeout: this.timeoutMs
            });
            if (!Array.isArray(response.data)) {
                throw new Error('Explorer returned an invalid UTXO response');
            }
            return response.data.map((utxo: any) => {
                if (
                    typeof utxo?.txid !== 'string' ||
                    !Number.isInteger(utxo?.vout) ||
                    !Number.isSafeInteger(utxo?.value) ||
                    typeof utxo?.status?.confirmed !== 'boolean'
                ) {
                    throw new Error('Explorer returned a malformed UTXO');
                }
                return {
                    txid: utxo.txid,
                    vout: utxo.vout,
                    amount: utxo.value,
                    confirmations: utxo.status.confirmed ? 1 : 0
                };
            });
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            throw new ExplorerRequestError('Address UTXO lookup', error);
        }
    }

    // Esplora outspend lookup. Returns null when the transaction (or the
    // output index) does not exist on this chain at all, meaning the outpoint
    // is chain-exclusive. Uses the plural /outspends endpoint: some esplora
    // deployments answer the singular /outspend/:vout with 200 {"spent":false}
    // even for transaction ids they have never seen, which would make a
    // chain-exclusive outpoint look live and replayable.
    async getOutspend(txid: string, vout: number): Promise<{ spent: boolean; confirmed: boolean } | null> {
        try {
            const response = await this.http.get(this.api(`/tx/${encodeURIComponent(txid)}/outspends`), {
                timeout: this.timeoutMs
            });
            if (!Array.isArray(response.data)) {
                throw new Error('Explorer returned an invalid outspend response');
            }
            const outspend = response.data[vout];
            if (outspend === undefined) return null;
            if (typeof outspend?.spent !== 'boolean') {
                throw new Error('Explorer returned an invalid outspend response');
            }
            const confirmed = outspend.spent
                ? outspend.status?.confirmed === true
                : false;
            return { spent: outspend.spent, confirmed };
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            const status = (error as AxiosError).response?.status;
            if (status === 404) return null;
            throw new ExplorerRequestError('Outspend lookup', error);
        }
    }

    async broadcastTransaction(hex: string): Promise<string> {
        try {
            const response = await this.http.post(this.api('/tx'), hex, {
                timeout: this.timeoutMs,
                headers: { 'Content-Type': 'text/plain' }
            });
            if (typeof response.data !== 'string' || !/^[0-9a-f]{64}$/i.test(response.data.trim())) {
                throw new Error('Explorer returned an invalid transaction id');
            }
            return response.data.trim();
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            throw new ExplorerRequestError('Transaction broadcast', error);
        }
    }

    async getTipHeight(): Promise<number> {
        try {
            const response = await this.http.get(this.api('/blocks/tip/height'), {
                timeout: this.timeoutMs
            });
            const height = Number(response.data);
            if (!Number.isSafeInteger(height) || height < 0) {
                throw new Error('Explorer returned an invalid chain height');
            }
            return height;
        } catch (error) {
            if (error instanceof ExplorerRequestError) throw error;
            throw new ExplorerRequestError('Chain-tip lookup', error);
        }
    }

    async getRecommendedFees(): Promise<RecommendedFees> {
        let mempoolError: unknown;
        try {
            const response = await this.http.get(this.api('/v1/fees/recommended'), {
                timeout: this.timeoutMs
            });
            const keys: (keyof RecommendedFees)[] = [
                'fastestFee', 'halfHourFee', 'hourFee', 'economyFee', 'minimumFee'
            ];
            const fees = {} as RecommendedFees;
            for (const key of keys) {
                const value = Number(response.data?.[key]);
                if (!Number.isFinite(value) || value <= 0) {
                    throw new Error(`Explorer returned an invalid ${key}`);
                }
                fees[key] = value;
            }
            return fees;
        } catch (error) {
            mempoolError = error;
        }

        try {
            const response = await this.http.get(this.api('/fee-estimates'), {
                timeout: this.timeoutMs
            });
            const estimates = response.data;
            if (!estimates || typeof estimates !== 'object' || Array.isArray(estimates)) {
                throw new Error('Explorer returned invalid fee estimates');
            }

            const feeForTarget = (target: number): number => {
                const value = Number(estimates[String(target)]);
                if (!Number.isFinite(value) || value <= 0) {
                    throw new Error(`Explorer returned an invalid ${target}-block fee estimate`);
                }
                return value;
            };

            return {
                fastestFee: feeForTarget(1),
                halfHourFee: feeForTarget(3),
                hourFee: feeForTarget(6),
                economyFee: feeForTarget(144),
                minimumFee: feeForTarget(1008)
            };
        } catch (esploraError) {
            const mempoolDetail = mempoolError instanceof Error
                ? mempoolError.message
                : String(mempoolError);
            const esploraDetail = esploraError instanceof Error
                ? esploraError.message
                : String(esploraError);
            throw new ExplorerRequestError(
                'Recommended-fee lookup',
                new Error(`Mempool endpoint failed: ${mempoolDetail}; Esplora endpoint failed: ${esploraDetail}`)
            );
        }
    }

    async assertHealthy(name: string): Promise<void> {
        await Promise.all([this.getTipHeight(), this.getRecommendedFees()]);
        console.log(`[BOOT] ${name} explorer health check passed: ${this.baseUrl}`);
    }
}

export class RotatingExplorerClient {
    readonly sourceId: string;
    private activeIndex = 0;

    constructor(
        private readonly clients: MempoolExplorerClient[],
        private readonly onRotate?: (from: string, to: string, error: unknown) => void
    ) {
        if (clients.length === 0) throw new Error('At least one explorer endpoint is required');
        this.sourceId = clients.map(client => client.baseUrl).join(',');
    }

    get baseUrl(): string {
        return this.clients[this.activeIndex].baseUrl;
    }

    private async request<T>(operation: (client: MempoolExplorerClient) => Promise<T>): Promise<T> {
        let lastError: unknown;
        for (let attempt = 0; attempt < this.clients.length; attempt++) {
            const client = this.clients[this.activeIndex];
            try {
                return await operation(client);
            } catch (error) {
                lastError = error;
                if (!this.isTransient(error) || this.clients.length === 1) {
                    throw error;
                }
                const from = client.baseUrl;
                this.activeIndex = (this.activeIndex + 1) % this.clients.length;
                this.onRotate?.(from, this.clients[this.activeIndex].baseUrl, error);
            }
        }
        throw lastError;
    }

    // Failures worth failing over from: no response at all (timeout, DNS,
    // refused, TLS), throttling (429), or upstream/CDN errors (5xx).
    // 4xx responses are deterministic answers and must not rotate.
    private isTransient(error: unknown): boolean {
        if (!(error instanceof ExplorerRequestError)) return false;
        if (error.status === undefined) return true;
        return error.status === 429 || error.status >= 500;
    }

    getTransactionConfirmations(txid: string): Promise<number> {
        return this.request(client => client.getTransactionConfirmations(txid));
    }

    getRawTransaction(txid: string): Promise<string> {
        return this.request(client => client.getRawTransaction(txid));
    }

    getAddressUtxos(address: string): Promise<ExplorerUtxo[]> {
        return this.request(client => client.getAddressUtxos(address));
    }

    broadcastTransaction(hex: string): Promise<string> {
        return this.request(client => client.broadcastTransaction(hex));
    }

    getTipHeight(): Promise<number> {
        return this.request(client => client.getTipHeight());
    }

    getOutspend(txid: string, vout: number): Promise<{ spent: boolean; confirmed: boolean } | null> {
        return this.request(client => client.getOutspend(txid, vout));
    }

    getRecommendedFees(): Promise<RecommendedFees> {
        return this.request(client => client.getRecommendedFees());
    }

    async assertHealthy(name: string): Promise<void> {
        await Promise.all([this.getTipHeight(), this.getRecommendedFees()]);
        console.log(`[BOOT] ${name} explorer health check passed: ${this.baseUrl}`);
    }
}
