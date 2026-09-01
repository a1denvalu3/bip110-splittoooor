import { expect } from 'chai';
import {
    BLAKE2B_ACTIVATION_HEIGHT,
    activationFromBlockchainInfo,
    mainnetActivationFromHeight
} from '../src/lib/bip110Activation';

describe('BLAKE2b activation safety gate', () => {
    it('unlocks only for the active buried deployment', () => {
        expect(activationFromBlockchainInfo({ blake2b: { active: false, height: 102 } }).ready).to.equal(false);
        expect(activationFromBlockchainInfo({ blake2b: { active: true, height: 102 } })).to.include({
            ready: true,
            activationHeight: 102,
            source: 'rpc'
        });
        expect(activationFromBlockchainInfo({ deployments: { blake2b: { active: true, height: 102 } } }).ready).to.equal(true);
    });

    it('uses the Knots height for mainnet activation readiness', () => {
        expect(mainnetActivationFromHeight(BLAKE2B_ACTIVATION_HEIGHT - 1)).to.include({
            ready: false,
            requiredHeight: BLAKE2B_ACTIVATION_HEIGHT
        });
        expect(mainnetActivationFromHeight(BLAKE2B_ACTIVATION_HEIGHT)).to.include({
            ready: true,
            activationHeight: BLAKE2B_ACTIVATION_HEIGHT
        });
    });

    it('fails closed for missing deployment information', () => {
        expect(activationFromBlockchainInfo({}).ready).to.equal(false);
    });
});
