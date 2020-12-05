import { deriveKey, pathToIndexList } from './eip2334';
import bls from 'bls-eth-wasm';
import * as TYPES from '../types';
const bip39 = require('bip39');

describe('EIP-2334 Deterministic Account Hierachy', () => {
  jest.setTimeout(10000);
  describe('pathToIndexList', () => {
    it('returns an array of integers', async () => {
      expect(pathToIndexList('m/12381/3600/3/5')).toEqual(expect.arrayContaining([12381,3600,3,5]));
      expect(pathToIndexList('m/12381/3600/3/5/9389473')).toEqual(expect.arrayContaining([12381,3600,3,5,9389473]));
    });
    it('fails with too short of a path', async () => {
      expect(() => { pathToIndexList('m/12381/3600/3') }).toThrow();
    });
    it('fails with an incorrect root level', async () => {
      expect(() => { pathToIndexList('n/12381/3600/3/5') }).toThrow();
    });
    it('fails with incorrect purpose', async () => {
      expect(() => { pathToIndexList('m/12/3600/3/5') }).toThrow();
    });
    it('fails with incorrect coin type', async () => {
      expect(() => { pathToIndexList('m/12381/30/3/5') }).toThrow();
    });
    it('fails with non-integers after the root path', async () => {
      expect(() => { pathToIndexList('m/12381/3600/five/2') }).toThrow();
    });
    it('fails with negative integers', async () => {
      expect(() => { pathToIndexList('m/12381/3600/-2/2') }).toThrow();
    });
    it('fails with integers larger than 2 ^ 32', async () => {
      expect(() => { pathToIndexList('m/12381/3600/2/4294967299') }).toThrow();
    });
  });

  describe('deriveKey', () => {
    const mnemonic = bip39.generateMnemonic(256);
    let seed;
    beforeEach( async () => {
      seed = await bip39.mnemonicToSeed(mnemonic);
      await bls.init(bls.BLS12_381);
    });
    it('generates multiple BLS keys for unique paths', async () => {
      let key1 = deriveKey(seed, 'm/12381/3600/0/1');
      let key2 = deriveKey(seed, 'm/12381/3600/7/1');
      let key3 = deriveKey(seed, 'm/12381/3600/2/554456');

      const sk1 = bls.deserializeHexStrToSecretKey(key1.toString('hex'));
      const pub1 = bls.toHexStr(sk1.getPublicKey().serialize());
      expect(key1.toString('hex')).toEqual(expect.stringMatching(TYPES.PRIVATE_KEY));
      expect(pub1).toEqual(expect.stringMatching(TYPES.PUBLIC_KEY));

      const sk2 = bls.deserializeHexStrToSecretKey(key2.toString('hex'));
      const pub2 = bls.toHexStr(sk2.getPublicKey().serialize());
      expect(key2.toString('hex')).toEqual(expect.stringMatching(TYPES.PRIVATE_KEY));
      expect(pub2).toEqual(expect.stringMatching(TYPES.PUBLIC_KEY));

      const sk3 = bls.deserializeHexStrToSecretKey(key3.toString('hex'));
      const pub3 = bls.toHexStr(sk3.getPublicKey().serialize());
      expect(key3.toString('hex')).toEqual(expect.stringMatching(TYPES.PRIVATE_KEY));
      expect(pub3).toEqual(expect.stringMatching(TYPES.PUBLIC_KEY));
    });
    it('generates the same keys for the same seed/path', async() => {
      let key1 = deriveKey(seed, 'm/12381/3600/3/1');
      let key2 = deriveKey(seed, 'm/12381/3600/3/1');
      expect(key1).toEqual(key2);
    });
  });

});
