import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';
import { matchers } from 'jest-json-schema';
import { Eip2335 } from './eip2335';
import * as types from '../types';
import pbkdfMock from '../../__mocks__/eip2335/pbkdf2-1.json';
import scryptMock from '../../__mocks__/eip2335/scrypt-1.json';
import walletMock from '../../__mocks__/wallet.json';
import schema from '../schemas/eip2335';

const TEST_PASSWORD = 'testpassword🔑';
const TEST_PASSWORD_WRONG= 'wrongpassword';
const TEST_PASSWORD_HEX = '7465737470617373776f7264f09f9491';
const TEST_PASSWORD_WRONG_HEX = '77726f6e6770617373776f7264';
const TEST_SECRET_HEX = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';
expect.extend(matchers);

describe('EIP2335 Keys', () => {
  let pbkdfStore;
  let scryptStore;
  let mockList;
  beforeAll(async () => {
    pbkdfStore = new Eip2335(pbkdfMock.crypto.cipher.function);
    scryptStore = new Eip2335(scryptMock.crypto.cipher.function);
    mockList = [ { store: pbkdfStore, mock: pbkdfMock }, { store: scryptStore, mock: scryptMock }];
  });

  describe('getDecryptionKey', () => {
    it('returns a valid key', async () => {
      for(let i=0; i < mockList.length; i++) {
        let key = await mockList[i].store.getDecryptionKey(mockList[i].mock.crypto.kdf.function, TEST_PASSWORD, mockList[i].mock.crypto.kdf.params.salt );
        await expect(key).toEqual(mockList[i].mock.testing.decryption_key);
      };
    });
  });

  describe('verifyPassword', () => {
    it('returns true with valid password', async () => {
      for(let i=0; i < mockList.length; i++) {
        let decryptionKey = await mockList[i].store.getDecryptionKey(mockList[i].mock.crypto.kdf.function, Buffer.from(TEST_PASSWORD_HEX, 'hex').toString(), mockList[i].mock.crypto.kdf.params.salt);
        let result = await mockList[i].store.verifyPassword(decryptionKey, mockList[i].mock.crypto.cipher.message, mockList[i].mock.crypto.checksum.message);
        expect(result).toBe(true);
      }
    });
    it('returns false with invalid password', async () => {
      for(let i=0; i < mockList.length; i++) {
        let decryptionKey = await mockList[i].store.getDecryptionKey(mockList[i].mock.crypto.kdf.function, Buffer.from(TEST_PASSWORD_WRONG_HEX, 'hex').toString(), mockList[i].mock.crypto.kdf.params.salt);
        let result = await mockList[i].store.verifyPassword(decryptionKey, mockList[i].mock.crypto.cipher.message, mockList[i].mock.crypto.checksum.message);
        expect(result).toBe(false);
      }
    })
  });

  describe('decrypt', () => {
    it('returns the decrypted key', async () => {
      for(let i=0; i < mockList.length; i++) {
        let result = await mockList[i].store.decrypt(pbkdfMock, TEST_PASSWORD);
        expect(result).toEqual(TEST_SECRET_HEX);
      }
    });
    it('throws with invalid password', async () => {
      for(let i=0; i < mockList.length; i++) {
        await expect(mockList[i].store.decrypt(pbkdfMock, TEST_PASSWORD_WRONG))
          .rejects.toMatchObject(expect.any(Error));
        }
    });
  });

  describe('encrypt', () => {
    it('returns a key object', async () => {
      for(let i=0; i < mockList.length; i++) {
        expect(schema).toBeValidSchema();
        let result = await mockList[i].store.encrypt(TEST_SECRET_HEX, TEST_PASSWORD);
        expect(result).toMatchSchema(schema);
      }
    });
  });

  describe('encrypt/decrypt batch', () => {
    it('decrypts the same key used during encrypt', async () => {
      for(let i=0; i < mockList.length; i++) {
        for(let p=0; p < walletMock.key_list.length; p++) {
          let encrypted = await mockList[i].store.encrypt(walletMock.key_list[p].private_key, TEST_PASSWORD);
          expect(encrypted).toMatchSchema(schema);
          let decrypted = await mockList[i].store.decrypt(encrypted, TEST_PASSWORD);
          expect(decrypted).toEqual(walletMock.key_list[p].private_key);
        }
      }
    });
  });

});
