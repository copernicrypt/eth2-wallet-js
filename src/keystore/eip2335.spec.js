import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';
import { Eip2335 } from './eip2335';
import * as types from '../types';
import storeMock from '../../__mocks__/eip2335.json';
import walletMock from '../../__mocks__/wallet.json';

const TEST_PASSWORD = 'testpassword🔑';
const TEST_PASSWORD_HEX = '7465737470617373776f7264f09f9491';
const TEST_SECRET_HEX = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

describe('Store', () => {
  let store;
  beforeAll(async () => { store = new Eip2335(storeMock.crypto.cipher.function); });

  describe('getDecryptionKey', () => {
    it('returns a valid key', async () => {
      let key = await store.getDecryptionKey(TEST_PASSWORD, storeMock.crypto.kdf.params.salt );
      await expect(key).toEqual(storeMock.testing.decryption_key);
    });
  });

  describe('verifyPassword', () => {
    it('returns true with valid password', async () => {
      let decryptionKey = await store.getDecryptionKey(Buffer.from(TEST_PASSWORD_HEX, 'hex').toString(), storeMock.crypto.kdf.params.salt);
      let result = await store.verifyPassword(decryptionKey, storeMock.crypto.cipher.message, storeMock.crypto.checksum.message);
      expect(result).toBe(true);
    });
  });

  describe('decrypt', () => {
    it('returns the decrypted key', async () => {
      let result = await store.decrypt(storeMock, TEST_PASSWORD);
      expect(result).toEqual(TEST_SECRET_HEX);
    });
  });

  describe('encrypt', () => {
    it('returns a key object', async () => {
      let result = await store.encrypt(TEST_SECRET_HEX, TEST_PASSWORD);
      //console.log(result);
    });
  });

});
