import fs from 'fs';
import  { v4 as uuidv4 } from 'uuid';
import { Filesystem } from './filesystem';
import * as types from '../types';
import eip2335Mock from '../../__mocks__/eip2335/pbkdf2-1.json';

const TESTPATH = 'testPath';
const TESTKEY = { key_id: uuidv4(), public_key: 'a71a0e76c3a91b3e6a12c6e641b095852670dcb6079778ce4921fbc9c9df42b2bbf2c89b2fe0da45fe678872c07eed3b' };
const TESTKEY_WRONG = 'b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9';
const KEYSEARCHOBJ = {
  key_id: expect.stringMatching(types.UUID),
  public_key: expect.stringMatching(types.PUBLIC_KEY),
  key_object: expect.any(Object)
}
const MNEMONIC_OBJECT = {
  algorithm: expect.any(String),
  iv: expect.any(String),
  data: expect.any(String)
}
const TEST_MNEMONIC_PHRASE = 'panther index connect repair pass clip easily meat mountain pencil toss flash';
const TEST_MNEMONIC_JSON = {"algorithm":"aes-256-cbc","iv":"2bba9ea8dc55098afcbd9406754cd982","data":"dc4c509a76d57591a4c4dfbd48ac2b25dab38b9c74f7545f849b74b3831fba078e8c8d289570671772e71614e4b39b9a7c83880c01766aea1c71720a8e997e40d922f82cbbe57f02be7bdb092e7f1885"}

describe('filesystem STORE', () => {
  let store;
  beforeAll(async() => { store = new Filesystem(); });

  describe('keyDelete', () => {
    let keyId = uuidv4();
    beforeAll( async () => { await store.keyWrite(TESTKEY, { path: TESTPATH, keyId: keyId }) });
    afterAll( async () => { await store.pathDelete(TESTPATH); })
    it('should return true when key exists and remove all traces of key', async() => {
      await expect(store.keyDelete(keyId, TESTPATH))
        .resolves.toBe(true);
      let keyList = await store.keyList(TESTPATH);
      expect(keyList).toEqual(expect.not.arrayContaining([keyId]));
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

  describe('pathBackup', () => {
    let keyId = uuidv4();
    beforeAll( async () => { await store.keyWrite(TESTKEY, { path: TESTPATH, keyId }) });
    afterAll( async () => { await store.pathDelete(TESTPATH); });

    it('should save a backup file', async () => {
      await store.pathBackup(TESTPATH);
      await expect(fs.promises.access(store.pathGet(`${TESTPATH}.zip`)))
        .resolves.toBeUndefined();
    });
    it('should fail with a nonexistent wallet', async () => {
      await expect(store.pathBackup('fakewallet')).
        rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('pathRestore', () => {
    afterAll( async () => {
      await store.pathDelete(TESTPATH);
      fs.promises.unlink(store.pathGet(`${TESTPATH}.zip`));
    });
    it('should recreate a wallet', async () => {
      await store.pathRestore(store.pathGet(`${TESTPATH}.zip`));
      expect(store.indexExists(TESTPATH)).resolves.toBe(true);
    });
    it('should fail with nonexistent file', async () => {
      await expect(store.pathRestore(store.pathGet(`fakefile.zip`)))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('mnemonicCreate', () => {
    beforeAll( async () => { await store.indexCreate(TESTPATH); });
    afterAll( async () => { await store.pathDelete(TESTPATH); });
    it('should create a mnemonic file', async () => {
      await store.mnemonicCreate(TEST_MNEMONIC_JSON, TESTPATH);
      await expect(store.mnemonicGet(TESTPATH))
        .resolves.toMatchObject(TEST_MNEMONIC_JSON);
    });
  });

  describe('mnemonicGet', () => {
    beforeAll( async () => {
      await store.indexCreate(TESTPATH);
      await store.mnemonicCreate(TEST_MNEMONIC_JSON, TESTPATH);
    });
    afterAll( async () => { await store.pathDelete(TESTPATH); });
    it('should return a mnemonic json file', async () => {
      await expect(store.mnemonicGet(TESTPATH))
        .resolves.toMatchObject(TEST_MNEMONIC_JSON);
    });
  });

});
