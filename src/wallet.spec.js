import _ from 'lodash';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { Wallet } from './wallet';
import * as types from './types';
import walletMock from '../__mocks__/wallet.json';
import attestMock from '../__mocks__/attestations.json';

const TEST_PASSWORD = 'test';
const TEST_PASSWORD_WRONG = 'testwrong';
const KEY_OBJECT = {
  wallet_id: expect.stringMatching(types.ANY),
  key_id: expect.stringMatching(types.UUID),
  public_key: expect.stringMatching(types.PUBLIC_KEY)
}
const TEST_MNEMONIC = 'explain fix pink title village payment sell under critic adapt zone upset';
let walletDeleteList = [];

describe('Wallet', () => {
  let keystore;
  beforeAll(async () => { keystore = new Wallet(); await keystore.init(); });
  //afterAll(() =>  );
  beforeEach(async () => {
    await keystore.walletCreate({ wallet_id: walletMock.wallet_list[0] });
  });
  afterEach(async () => {
    await keystore.walletDelete(walletMock.wallet_list[0]);
  });
  afterAll( async () => {
    for(let i=0; i < walletDeleteList.length; i++) {
      let result = await keystore.walletDelete(walletDeleteList[i]);
    }
  });

  describe('depositData', () => {
    let withdrawPubKey = 'b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9';
    let keyId;
    beforeEach(async () => {
      keyId = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: keyId });
    });
    it('should return valid deposit data', async () => {
      let data = await keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD, { raw: false, withdrawal_public_key: walletMock.key_list[1].public_key});
      expect(data).toEqual(walletMock.deposit_data);
    });
    it('should return valid raw data', async () => {
      let data = await keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD, { withdrawal_public_key: walletMock.key_list[1].public_key});
      expect(data).toEqual(walletMock.deposit_data_raw);
    });
    it('should throw with incorrect password', async () => {
      await expect(keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD_WRONG, { withdrawal_public_key: walletMock.key_list[1].public_key}))
        .rejects.toMatchObject(expect.any(Object));
    });
    it('should throw if withdrawal opts are not specified', async () => {
      await expect(keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyCreate', () => {
    it('should return an object with the properties wallet_id, key_id, public_key', async () => {
      let result = await keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD);
      expect(result).toMatchObject(KEY_OBJECT);
    });
    it('should not allow duplicate key IDs', async () => {
      let key_id = uuidv4();
      await expect( keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD, { keyId: key_id }))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD, { keyId: key_id }))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyDelete', () => {
    let keyId = uuidv4();
    beforeEach(async () => {
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: keyId });
    });
    it('should return true with a correct password, keyId, and walletId', async () => {
      await expect(keystore.keyDelete(walletMock.wallet_list[0], keyId, TEST_PASSWORD))
        .resolves.toBe(true);
    });
    it('should throw with an incorrect password', async () => {
      await expect(keystore.keyDelete(walletMock.wallet_list[0], keyId, TEST_PASSWORD_WRONG))
        .rejects.toMatchObject(expect.any(Object));
    });
    it('should throw with an incorrect keyId', async () => {
      let keyIdWrong = uuidv4();
      await expect(keystore.keyDelete(walletMock.wallet_list[0], keyIdWrong, TEST_PASSWORD))
        .rejects.toMatchObject(expect.any(Object));
    });
    it('should throw with an incorrect walletId', async () => {
      await expect(keystore.keyDelete(walletMock.wallet_list[1], keyId, TEST_PASSWORD))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('keyImport', () => {
    it('should return an object with the properties wallet_id, key_id, public_key', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD);
      expect(result).toMatchObject(KEY_OBJECT);
    });
    it('should not allow duplicate key IDs', async () => {
      let key_id = uuidv4();
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: key_id }))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: key_id }))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('should not allow duplicate private keys', async () => {
      let key_id1 = uuidv4();
      let key_id2 = uuidv4();
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: key_id1 }))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: key_id2 }))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyList', () => {
    it('returns an array of key objects', async () => {
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD);
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[1].private_key, TEST_PASSWORD);
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[2].private_key, TEST_PASSWORD);
      let result = await keystore.keyList(walletMock.wallet_list[0]);
      for(let i=0; i < result.length; i++) {
        expect(result[i]).toMatchObject(_.omit(KEY_OBJECT, 'wallet_id'));
      }
    });
    it('throws when the wallet does not exist', async () => {
      expect(keystore.keyList(walletMock.wallet_list[1]))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('keyPrivate', () => {
    it('returns a private key hex', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: walletMock.key_list[0].key_id });
      let pk = await keystore.keyPrivate(walletMock.wallet_list[0], walletMock.key_list[0].key_id, TEST_PASSWORD);
      expect(pk).toBe(walletMock.key_list[0].private_key);
      expect(pk).toMatch(types.PRIVATE_KEY);
    });
    it('throws with incorrect password', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, { keyId: walletMock.key_list[0].key_id });
      await expect(keystore.keyPrivate(walletMock.wallet_list[0], walletMock.key_list[0].key_id, TEST_PASSWORD_WRONG))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('sign', () => {
    let keyId;
    beforeEach(async () => {
      keyId = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], attestMock[0].private_key, TEST_PASSWORD, { keyId: keyId });
    });
    it('returns a valid and correct signature for a key', async () => {
      for(let i=0; i < attestMock[0].attestation_list.length; i++) {
        let signature = await keystore.sign(attestMock[0].attestation_list[i].message, walletMock.wallet_list[0], keyId, TEST_PASSWORD);
        expect(signature).toEqual(Uint8Array.from(attestMock[0].attestation_list[i].signature));
        expect(Buffer.from(signature).toString('hex')).toMatch(types.SIGNATURE);
      }
    });
    it('throws with incorrect password', async () => {
      for(let i=0; i < attestMock[0].attestation_list.length; i++) {
        await expect(keystore.sign(attestMock[0].attestation_list[i].message, walletMock.wallet_list[0], keyId, TEST_PASSWORD_WRONG))
          .rejects.toMatchObject(expect.any(Object));
      }
    });
  });

  let backupId;
  describe('walletBackup', () => {
    afterAll( async() => { await keystore.walletDelete(backupId); });
    it('creates a backup file for a wallet', async () => {
      backupId = await keystore.walletCreate();
      await expect(keystore.walletBackup(backupId))
        .resolves.toEqual(expect.any(String));
    });
    it('fails when using a nonexistent wallet', async() => {
      await expect(keystore.walletBackup('nonexistent'))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('walletCreate', () => {
    it('returns a random wallet id by default', async () => {
      let walletId = await keystore.walletCreate();
      walletDeleteList.push(walletId);
      await expect(walletId).toMatch(types.UUID);
    });
    it('returns the proper ID when manually set', async () => {
      let walletId = uuidv4();
      walletDeleteList.push(walletId);
      await expect(keystore.walletCreate({ wallet_id: walletId }))
        .resolves.toBe(walletId);
    });
    it('throws when using duplicate name', async () => {
      let walletId = uuidv4();
      walletDeleteList.push(walletId);
      await expect(keystore.walletCreate({ wallet_id: walletId }))
        .resolves.toBe(walletId);
      await expect(keystore.walletCreate({ wallet_id: walletId }))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('walletDelete', () => {
    it('successfully removes the wallet', async () => {
      let walletId = await keystore.walletCreate();
      await expect(keystore.walletDelete(walletId)).resolves.toBe(true);
    });
    it('throws when wallet does not exist', async () => {
      let walletId = await keystore.walletCreate();
      let fakeWalletId = uuidv4();
      await expect(keystore.walletDelete(fakeWalletId)).rejects.toMatchObject(expect.any(Error));
      //cleanup
      walletDeleteList.push(walletId);
    });
  });

  describe('walletList', () => {
    it('returns an array of wallet IDs', async () => {
      await expect(keystore.walletList())
        .resolves.toEqual(expect.arrayContaining(walletDeleteList));
    });
  });

  describe('walletMnemonic', () => {
    let walletId = uuidv4();
    beforeAll( async () => { await keystore.walletCreate({ wallet_id: walletId, type: 2, password: TEST_PASSWORD, mnemonic: TEST_MNEMONIC }); });
    afterAll( async() => { await keystore.walletDelete(walletId); });
    it('returns a wallet mnemonic phrase', async () => {
      expect(keystore.walletMnemonic(walletId, TEST_PASSWORD))
        .resolves.toEqual(TEST_MNEMONIC);
    });
    it('fails with incorrect password', () => {
      expect(keystore.walletMnemonic(walletId, TEST_PASSWORD_WRONG))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('walletRestore', () => {
    afterAll( async() => {
      await keystore.walletDelete(backupId);
      await fs.promises.unlink(keystore.store.pathGet(`${backupId}.zip`));
    });
    it('should recreate a wallet', async () => {
      await keystore.walletRestore(keystore.store.pathGet(`${backupId}.zip`));
      expect(keystore.store.indexExists(backupId)).resolves.toBe(true);
    });
    it('should fail with nonexistent file', async () => {
      await expect(keystore.walletRestore(`/home/test/fakefile.zip`))
        .rejects.toMatchObject(expect.any(Object));
    });
  });
});
