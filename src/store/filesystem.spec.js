import  { v4 as uuidv4 } from 'uuid';
import { Filesystem } from './filesystem';
import * as types from '../types';
import eip2335Mock from '../../__mocks__/eip2335.json';

const TESTPATH = 'testPath';
const TESTKEY = { key_id: uuidv4(), public_key: 'a71a0e76c3a91b3e6a12c6e641b095852670dcb6079778ce4921fbc9c9df42b2bbf2c89b2fe0da45fe678872c07eed3b' };
const TESTKEY_WRONG = 'b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9';
const KEYSEARCHOBJ = {
  key_id: expect.stringMatching(types.UUID),
  public_key: expect.stringMatching(types.PUBLIC_KEY),
  key_object: expect.any(Object)
}

describe('filesystem STORE', () => {
  let store;
  beforeAll(async() => { store = new Filesystem(); });

  describe('keyDelete', () => {
    let keyId = uuidv4();
    beforeAll( async () => { await store.keyWrite(TESTKEY, { path: TESTPATH, keyId }) });
    afterAll( async () => { await store.pathDelete(TESTPATH); })
    it('should return true when key exists', async() => {
      await expect(store.keyDelete(keyId, TESTPATH))
        .resolves.toBe(true);
    });
    it('should throw when key does not exist', async() => {
      await expect(store.keyDelete(uuidv4(), TESTPATH))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyWrite', () => {
    afterEach( async() => { await store.pathDelete(TESTPATH); });
    it('should return true when file is written', async () => {
      await expect(store.keyWrite(TESTKEY, { path: TESTPATH }))
        .resolves.toBe(true);
    });
    it('should throw when the key already exists.', async () => {
      let keyId = uuidv4();
      await expect(store.keyWrite(TESTKEY, { path: TESTPATH, keyId }))
        .resolves.toBe(true);
      await expect(store.keyWrite(TESTKEY, { path: TESTPATH, keyId }))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('should throw when the public key exists', async () => {
      await expect(store.keyWrite(TESTKEY, { path: TESTPATH, publicKey: TESTKEY.public_key }))
        .resolves.toBe(true);
      await expect(store.keyWrite(TESTKEY, { path: TESTPATH, publicKey: TESTKEY.public_key }))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keySearch', () => {
    beforeAll( async () => {
      await store.keyWrite(TESTKEY, { keyId: TESTKEY.key_id, path: TESTPATH, publicKey: TESTKEY.public_key });
      await store.keyWrite(eip2335Mock, { keyId: eip2335Mock.uuid, path: TESTPATH, publicKey: eip2335Mock.pubkey });
    });
    afterAll( async () => await store.pathDelete(TESTPATH));
    it('returns a key object when using a valid keyId with simple object', async () => {
      await expect(store.keySearch(TESTKEY.key_id, TESTPATH))
        .resolves.toMatchObject(KEYSEARCHOBJ);
    })
    it('returns a key object when using a valid keyId with EIP2335', async () => {
      await expect(store.keySearch(eip2335Mock.uuid, TESTPATH))
        .resolves.toMatchObject(KEYSEARCHOBJ);
    });
    it('returns a key object when using a valid publicKey', async () => {
      await expect(store.keySearch(eip2335Mock.pubkey, TESTPATH))
        .resolves.toMatchObject(KEYSEARCHOBJ);
    });
    it('returns a key object when using a valid publicKey with EIP2335', async () => {
      await expect(store.keySearch(eip2335Mock.pubkey, TESTPATH))
        .resolves.toMatchObject(KEYSEARCHOBJ);
    });
    it('throws when using an invalid keyId', async () => {
      await expect(store.keySearch(uuidv4(), TESTPATH))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('throws when when using an invalid publicKey', async () => {
      await expect(store.keySearch(TESTKEY_WRONG, TESTPATH))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

});
