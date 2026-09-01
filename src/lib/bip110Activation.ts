// First block using the BLAKE2b proof-of-work rules on the fork chain.
export const BLAKE2B_ACTIVATION_HEIGHT = 961_640;

export type Bip110Activation = {
    ready: boolean;
    status: string;
    activationHeight: number | null;
    requiredHeight: number | null;
    source: 'rpc' | 'height' | 'unavailable';
};

export function activationFromBlockchainInfo(info: any): Bip110Activation {
    const deployment = info?.blake2b ?? info?.deployments?.blake2b;
    const status = String(deployment?.active ? 'active' : 'inactive').toLowerCase();
    const activationHeight = Number.isSafeInteger(deployment?.height) ? deployment.height : null;

    return {
        ready: deployment?.active === true,
        status,
        activationHeight,
        requiredHeight: activationHeight,
        source: 'rpc'
    };
}

export function mainnetActivationFromHeight(height: number): Bip110Activation {
    const validHeight = Number.isSafeInteger(height) && height >= 0;
    return {
        ready: validHeight && height >= BLAKE2B_ACTIVATION_HEIGHT,
        status: validHeight && height >= BLAKE2B_ACTIVATION_HEIGHT ? 'active' : 'awaiting-activation-height',
        activationHeight: BLAKE2B_ACTIVATION_HEIGHT,
        requiredHeight: BLAKE2B_ACTIVATION_HEIGHT,
        source: 'height'
    };
}

export const unavailableActivation = (): Bip110Activation => ({
    ready: false,
    status: 'unavailable',
    activationHeight: null,
    requiredHeight: null,
    source: 'unavailable'
});
