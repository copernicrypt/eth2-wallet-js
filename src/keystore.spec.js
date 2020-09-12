import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';
import Keystore from './keystore';
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
let walletDeleteList = [];

describe('Keystore', () => {
  let keystore;
  beforeAll(async () => { keystore = new Keystore(); await keystore.init(); });
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
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, keyId);
    });
    it('should return valid deposit data', async () => {
      let data = await keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD, { raw: false, withdraw_public_key: walletMock.key_list[1].public_key});
      expect(data).toEqual(walletMock.deposit_data);
    });
    it('should return valid raw data', async () => {
      let data = await keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD, { withdraw_public_key: walletMock.key_list[1].public_key});
      expect(data).toEqual(walletMock.deposit_data_raw);
    });
    it('should throw with incorrect password', async () => {
      await expect(keystore.depositData(walletMock.wallet_list[0], keyId, TEST_PASSWORD_WRONG, { withdraw_public_key: walletMock.key_list[1].public_key}))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('keyCreate', () => {
    it('should return an object with the properties wallet_id, key_id, public_key', async () => {
      let result = await keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD);
      expect(result).toMatchObject(KEY_OBJECT);
    });
    it('should not allow duplicate key IDs', async () => {
      let key_id = uuidv4();
      await expect( keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD, key_id))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyCreate(walletMock.wallet_list[0], TEST_PASSWORD, key_id))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyDelete', () => {
    let keyId = uuidv4();
    beforeEach(async () => {
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, keyId);
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

  describe('keyExists', () => {
    it('should return false when public key and key id are missing', async () => {
      let key_id = uuidv4();
      await expect(keystore.keyExists(key_id, walletMock.wallet_list[0]))
        .resolves.toBe(false);
      await expect(keystore.keyExists(walletMock.key_list[0].public_key, walletMock.wallet_list[0]))
        .resolves.toBe(false);
    })
    it('should return true when public key exists but key id is unique', async () => {
      let key_id = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD);
      await expect(keystore.keyExists(key_id, walletMock.wallet_list[0]))
        .resolves.toBe(false);
      await expect(keystore.keyExists(walletMock.key_list[0].public_key, walletMock.wallet_list[0]))
        .resolves.toBe(true);
    })
    it('should return true when key id exists but public key is unique', async() => {
      let key_id = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[1].private_key, TEST_PASSWORD, key_id);
      await expect(keystore.keyExists(key_id, walletMock.wallet_list[0]))
        .resolves.toBe(true);
      await expect(keystore.keyExists(walletMock.key_list[0].public_key, walletMock.wallet_list[0]))
        .resolves.toBe(false);
    });
    it('should return true when key id and public key both exist', async () => {
      let key_id = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, key_id);
      await expect(keystore.keyExists(key_id, walletMock.wallet_list[0]))
        .resolves.toBe(true);
      await expect(keystore.keyExists(walletMock.key_list[0].public_key, walletMock.wallet_list[0]))
        .resolves.toBe(true);
    });
  });

  describe('keyImport', () => {
    it('should return an object with the properties wallet_id, key_id, public_key', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD);
      expect(result).toMatchObject(KEY_OBJECT);
    });
    it('should not allow duplicate key IDs', async () => {
      let key_id = uuidv4();
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, key_id))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, key_id))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('should not allow duplicate private keys', async () => {
      let key_id1 = uuidv4();
      let key_id2 = uuidv4();
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, key_id1))
        .resolves.toMatchObject(KEY_OBJECT);
      await expect( keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, key_id2))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('keyPrivate', () => {
    it('returns a private key hex', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, walletMock.key_list[0].key_id);
      let pk = await keystore.keyPrivate(walletMock.wallet_list[0], walletMock.key_list[0].key_id, TEST_PASSWORD);
      expect(pk).toBe(walletMock.key_list[0].private_key);
      expect(pk).toMatch(types.PRIVATE_KEY);
    });
    it('throws with incorrect password', async () => {
      let result = await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, walletMock.key_list[0].key_id);
      await expect(keystore.keyPrivate(walletMock.wallet_list[0], walletMock.key_list[0].key_id, TEST_PASSWORD_WRONG))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

  describe('keySearch', () => {
    beforeEach(async () => {
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD, walletMock.key_list[0].key_id);
    });
    it('returns an object containing key Id, public key, and wallet id using key ID', async () => {
      expect(keystore.keySearch(walletMock.key_list[0].key_id, walletMock.wallet_list[0]))
        .resolves.toMatchObject(KEY_OBJECT);
    });
    it('returns an object containing key Id, public key, and wallet id using public key', async () => {
      expect(keystore.keySearch(walletMock.key_list[0].public_key, walletMock.wallet_list[0]))
        .resolves.toMatchObject(KEY_OBJECT);
    });
    it('returns an object containing key Id, public key, and wallet id using private key', async () => {
      expect(keystore.keySearch(walletMock.key_list[0].private_key, walletMock.wallet_list[0]))
        .resolves.toMatchObject(KEY_OBJECT);
    });
    it('throws when using invalid key ID', async () => {
      expect(keystore.keySearch(walletMock.key_list[1].key_id, walletMock.wallet_list[0]))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('throws when using invalid public key', async () => {
      expect(keystore.keySearch(walletMock.key_list[1].public_key, walletMock.wallet_list[0]))
        .rejects.toMatchObject(expect.any(Error));
    });
    it('throws when using invalid private key', async () => {
      expect(keystore.keySearch(walletMock.key_list[1].private_key, walletMock.wallet_list[0]))
        .rejects.toMatchObject(expect.any(Error));
    });
  });

  describe('sign', () => {
    let keyId;
    beforeEach(async () => {
      keyId = uuidv4();
      await keystore.keyImport(walletMock.wallet_list[0], attestMock[0].private_key, TEST_PASSWORD, keyId);
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

  describe('walletListKeys', () => {
    it('returns an array of key objects', async () => {
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[0].private_key, TEST_PASSWORD);
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[1].private_key, TEST_PASSWORD);
      await keystore.keyImport(walletMock.wallet_list[0], walletMock.key_list[2].private_key, TEST_PASSWORD);
      let result = await keystore.walletListKeys(walletMock.wallet_list[0]);
      for(let i=0; i < result.length; i++) {
        expect(result[i]).toMatchObject(_.omit(KEY_OBJECT, 'wallet_id'));
      }
    });
    it('throws when the wallet does not exist', async () => {
      expect(keystore.walletListKeys(walletMock.wallet_list[1]))
        .rejects.toMatchObject(expect.any(Object));
    });
  });

});
