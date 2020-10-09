import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import * as types from './types';
import walletMock from '../__mocks__/wallet.json';
import attestMock from '../__mocks__/attestations.json';

const exec = require('child_process').exec;
const KEY_OBJECT = {
  wallet_id: expect.stringMatching(types.ANY),
  key_id: expect.stringMatching(types.UUID),
  public_key: expect.stringMatching(types.PUBLIC_KEY)
}
const EIP2335_OBJECT = {
  key_id: expect.stringMatching(types.ANY),
  public_key: expect.stringMatching(types.PUBLIC_KEY),
  key_object: {
    pubkey: expect.stringMatching(types.PUBLIC_KEY),
    uuid: expect.stringMatching(types.UUID),
    crypto: expect.objectContaining({ kdf: expect.any(Object), checksum: expect.any(Object), cipher: expect.any(Object) })
  }
}
const DEPOSIT_OBJECT = {
  pubkey: expect.stringMatching(types.PUBLIC_KEY),
  withdrawal_credentials: expect.stringMatching(types.DATA_ROOT),
  signature: expect.stringMatching(types.SIGNATURE),
  amount: expect.any(String),
  deposit_data_root: expect.stringMatching(types.DATA_ROOT)
}

describe('CLI', () => {
  jest.setTimeout(10000);
  let testWallet = 'cliTester';
  let testWallet2 = 'cliTester2';
  let keyWallet = 'cliKeyTest';
  let testKey = uuidv4();
  let testPassword = 'test';

  beforeEach(async() => await cli(['walletCreate', `--wallet=${keyWallet}`], '.'));
  afterEach(async() => await cli(['walletDelete', `--wallet=${keyWallet}`], '.'));

  describe('depositData', () => {
    let validatorKey = uuidv4();
    let withdrawalKey = uuidv4();
    beforeEach(async() => {
      await cli(['keyImport', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${validatorKey}`, `--privatekey=${walletMock.key_list[0].private_key}`], '.')
      await cli(['keyImport', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${withdrawalKey}`, `--privatekey=${walletMock.key_list[1].private_key}`], '.')
    })
    it('fails with missing wallet', async () => {
      let result = await cli(['depositData', `--password=${testPassword}`, `--key=${validatorKey}`, `--withdrawalkey=${withdrawalKey}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails with missing password', async () => {
      let result = await cli(['depositData', `--wallet=${keyWallet}`, `--key=${validatorKey}`, `--withdrawalkey=${withdrawalKey}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails with missing key', async () => {
      let result = await cli(['depositData', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--withdrawalkey=${withdrawalKey}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails with incorrect password', async () => {
      let result = await cli(['depositData', `--password=fakepassword`, `--wallet=${keyWallet}`, `--key=${validatorKey}`, `--withdrawalkey=${withdrawalKey}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('fails if withdrawal opts are not specified', async () => {
      let result = await cli(['depositData', `--password=fakepassword`, `--wallet=${keyWallet}`, `--key=${validatorKey}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns valid deposit data', async () => {
      let result = await cli(['depositData', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${validatorKey}`, `--withdrawalkey=${withdrawalKey}`], '.');
      let deposit = parseJsonOutput(result);
      expect(deposit).toMatchObject(DEPOSIT_OBJECT);
      expect(deposit).toEqual(walletMock.deposit_data);
    });
    it('returns valid raw data', async () => {
      let result = await cli(['depositData', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${validatorKey}`, `--withdrawalkey=${withdrawalKey}`, `--raw`], '.');
      let deposit = parseString(result);
      expect(types.DEPOSIT_DATA.test(deposit)).toBe(true);
      expect(deposit).toEqual(walletMock.deposit_data_raw);
    });
  });

  describe('keyCreate', () => {
    it('fails when walletId is missing', async() => {
      let result = await cli(['keyCreate', `--password=${testPassword}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is missing', async() => {
      let result = await cli(['keyCreate', `--wallet=${keyWallet}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('returns key result when complete', async() => {
      let result = await cli(['keyCreate', `--wallet=${keyWallet}`, `--password=${testPassword}`], '.');
      let key = parseJsonOutput(result);
      expect(key).toMatchObject(KEY_OBJECT);
    });
  });

  describe('keyDelete', () => {
    let keyId = uuidv4();
    beforeEach(async() => { await cli(['keyCreate', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${keyId}`], '.') })
    it('fails when walletId is missing', async() => {
      let result = await cli(['keyDelete', `--password=${testPassword}`, `--key=${keyId}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is missing', async() => {
      let result = await cli(['keyDelete', `--wallet=${keyWallet}`, `--key=${keyId}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when keyId is missing', async() => {
      let result = await cli(['keyDelete', `--wallet=${keyWallet}`, `--password=${testPassword}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('returns delete result when complete', async() => {
      let result = await cli(['keyDelete', `--wallet=${keyWallet}`, `--password=${testPassword}`, `--key=${keyId}`], '.');
      expect(result.stdout.includes('Key Deleted')).toBe(true);
    });
  });

  describe('keyImport', () => {
    let keyId = uuidv4();
    it('fails when walletId is missing', async() => {
      let result = await cli(['keyImport', `--password=${testPassword}`, `--privatekey=${walletMock.key_list[0].private_key}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is missing', async() => {
      let result = await cli(['keyImport', `--wallet=${keyWallet}`, `--privatekey=${walletMock.key_list[0].private_key}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when privateKey is missing', async() => {
      let result = await cli(['keyImport', `--wallet=${keyWallet}`, `--password=${testPassword}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when privateKey is invalid', async() => {
      let result = await cli(['keyImport', `--wallet=${keyWallet}`, `--privatekey=badkeyhere0000`, `--password=${testPassword}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns key object when successful', async () => {
      let result = await cli(['keyImport', `--wallet=${keyWallet}`, `--privatekey=${walletMock.key_list[0].private_key}`, `--password=${testPassword}`], '.');
      let key = parseJsonOutput(result);
      expect(key).toMatchObject(KEY_OBJECT);
    });
  });

  describe('keyList', () => {
    let keyId = uuidv4();
    beforeEach(async() => { await cli(['keyCreate', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${keyId}`], '.') })
    it('fails when wallet is not provided', async () => {
      let result = await cli(['keyList'], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when non-existent wallet is provided', async() => {
      let result = await cli(['keyList', '--wallet=fakewallet'], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns an array when wallet is provided', async () => {
      let result = await cli(['keyList', `--wallet=${keyWallet}`], '.');
      let list = parseJsonOutput(result);
      expect(list).toEqual(expect.arrayContaining([expect.objectContaining({
        key_id: expect.stringMatching(types.UUID),
        public_key: expect.stringMatching(types.PUBLIC_KEY)
      })]));
    });
  });

  describe('keyPrivate', () => {
    let keyId = uuidv4();
    beforeEach(async() => { await cli(['keyCreate', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${keyId}`], '.') })
    it('fails when walletId is missing', async() => {
      let result = await cli(['keyPrivate', `--password=${testPassword}`, `--key=${keyId}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is missing', async() => {
      let result = await cli(['keyPrivate', `--wallet=${keyWallet}`, `--key=${keyId}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when keyId is missing', async() => {
      let result = await cli(['keyPrivate', `--wallet=${keyWallet}`, `--password=${testPassword}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is incorrect', async() => {
      let result = await cli(['keyPrivate', `--wallet=${keyWallet}`, `--key=${keyId}`, `--password=fakepassword`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns key result when complete', async() => {
      let result = await cli(['keyPrivate', `--wallet=${keyWallet}`, `--password=${testPassword}`, `--key=${keyId}`], '.');
      let key = parseString(result);
      expect(types.PRIVATE_KEY.test(key)).toBe(true);
    });
  });

  describe('keySearch', () => {
    let keyId = uuidv4();
    beforeEach(async() => { await cli(['keyImport', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${keyId}`, `--privatekey=${walletMock.key_list[0].private_key}`], '.') })
    it('fails when walletId is missing', async() => {
      let result = await cli(['keySearch', `--search=${keyId}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when search is missing', async() => {
      let result = await cli(['keySearch', `--wallet=${keyWallet}`], '.');
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when keyId does not exist', async() => {
      let result = await cli(['keySearch', `--wallet=${keyWallet}`, `--search=${uuidv4()}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('fails when public key does not exist', async() => {
      let result = await cli(['keySearch', `--wallet=${keyWallet}`, `--search=${walletMock.key_list[1].public_key}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('fails when wallet does not exist', async() => {
      let result = await cli(['keySearch', `--wallet=fakewallet`, `--search=${keyId}`], '.');
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns with keyId search', async () => {
      let result = await cli(['keySearch', `--wallet=${keyWallet}`, `--search=${keyId}`], '.');
      let key = parseJsonOutput(result);
      expect(key).toMatchObject(EIP2335_OBJECT);
    })
    it('returns with public key search', async () => {
      let result = await cli(['keySearch', `--wallet=${keyWallet}`, `--search=${walletMock.key_list[0].public_key}`], '.');
      let key = parseJsonOutput(result);
      expect(key).toMatchObject(EIP2335_OBJECT);
    });
  });

  describe('sign', () => {
    let keyId = uuidv4();
    beforeEach(async() => { await cli(['keyImport', `--password=${testPassword}`, `--wallet=${keyWallet}`, `--key=${keyId}`, `--privatekey=${attestMock[0].private_key}`], '.') })
    it('fails when wallet is missing', async() => {
      let result = await cli(['sign', `--password=${testPassword}`, `--search=${keyId}`, `--message=${attestMock[0].attestation_list[0].message}`]);
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when search is missing', async() => {
      let result = await cli(['sign', `--wallet=${keyWallet}`, `--password=${testPassword}`, `--message=${attestMock[0].attestation_list[0].message}`]);
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when password is missing', async() => {
      let result = await cli(['sign', `--wallet=${keyWallet}`, `--search=${keyId}`, `--message=${attestMock[0].attestation_list[0].message}`]);
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails when message is missing', async() => {
      let result = await cli(['sign', `--wallet=${keyWallet}`, `--password=${testPassword}`, `--search=${keyId}`]);
      expect(result.stderr.includes('required option')).toBe(true);
    });
    it('fails with incorrect password', async () => {
      let result = await cli(['sign', `--wallet=${keyWallet}`, `--password=fakepassword`, `--search=${keyId}`, `--message=${attestMock[0].attestation_list[0].message}`]);
      expect(result.stderr.includes('Error')).toBe(true);
    });
    it('returns a valid and correct signature for a key', async () => {
      let result = await cli(['sign', `--wallet=${keyWallet}`, `--password=${testPassword}`, `--search=${keyId}`, `--message=${attestMock[0].attestation_list[0].message}`]);
      let signature = parseString(result);
      expect(types.SIGNATURE.test(signature)).toBe(true);
      expect(signature).toEqual(Buffer.from(attestMock[0].attestation_list[0].signature).toString('hex'));
    });
  });

  let backupPath;
  describe('walletBackup', () => {
    beforeEach( async () => { await cli(['walletCreate', `--wallet=${testWallet}`], '.'); });
    afterEach(async() => {
      await cli(['walletDelete', `--wallet=${testWallet}`], '.');
    });
    it('returns a success message.', async () => {
      let result = await cli(['walletBackup', `--wallet=${testWallet}`], '.');
      expect(result.stdout.includes(`successfully backed up`)).toBe(true);
      backupPath = result.stdout.split(': ')[1].trim();
    });
    it('fails with nonexistent wallet', async () => {
      let result = await cli(['walletBackup', `--wallet=fakewallet`], '.');
      expect(result.stderr.includes(`Wallet does not exist`)).toBe(true);
    });
  });

  describe('walletRestore', () => {
    afterAll(async () => {
      await fs.promises.unlink(backupPath);
      await cli(['walletDelete', `--wallet=${testWallet}`], '.');
    });
    it('should recreate a wallet', async () => {
      let result = await cli(['walletRestore', `--source=${backupPath}`], '.');
      expect(result.stdout.includes('successfully restored')).toBe(true);
    });
    it('should fail with nonexistent file', async () => {
      let result = await cli(['walletRestore', `--source=/home/badpath/fake.zip`], '.');
      expect(result.stderr.includes('no such file')).toBe(true);
    });
  });

  describe('walletCreate', () => {
    afterEach(async() => {
      await cli(['walletDelete', `--wallet=${testWallet2}`], '.');
    });
    it('returns a successful message', async () => {
      let result = await cli(['walletCreate', `--wallet=${testWallet2}`], '.');
      expect(result.stdout.includes(`Created wallet: ${testWallet2}`)).toBe(true);
    });
    it('returns a random UUID when no wallet ID specified', async () => {
      let result = await cli(['walletCreate'], '.');
      let walletId = (result.stdout.split(': ')[1]).trim();
      expect(result.stdout.includes(`Created wallet:`)).toBe(true);
      expect(types.UUID.test(walletId)).toBe(true);
      await cli(['walletDelete', `--wallet=${walletId}`], '.');
    });
    it('returns error when creating a duplicate', async() => {
      await cli(['walletCreate', `--wallet=${testWallet2}`], '.');
      let result = await cli(['walletCreate', `--wallet=${testWallet2}`], '.');
      expect(result.stderr.includes(`Wallet already exists`)).toBe(true);
    });
    it('returns error when using an invalid type', async() => {
      let result = await cli(['walletCreate', `--type=9`], '.');
      expect(result.stderr.includes(`Wallet type '9' not supported`)).toBe(true);
    });
  })

  describe('walletDelete', () => {
    it('returns success message on completion', async () => {
      await cli(['walletCreate', `--wallet=${testWallet}`], '.');
      let result = await cli(['walletDelete', `--wallet=${testWallet}`], '.');
      expect(result.stdout.includes(`Deleted wallet: ${testWallet}`)).toBe(true);
    });
    it('returns error when wallet does not exist', async () => {
      let result = await cli(['walletDelete', `--wallet=fakeWallet`], '.');
      expect(result.stderr.includes(`Error`)).toBe(true);
    });
  });

  describe('walletList', () => {
    beforeAll(async() => {
      await cli(['walletCreate', `--wallet=${testWallet}`], '.');
      await cli(['walletCreate', `--wallet=${testWallet2}`], '.');
    });
    afterAll(async() => {
      await cli(['walletDelete', `--wallet=${testWallet}`], '.');
      await cli(['walletDelete', `--wallet=${testWallet2}`], '.');
    });
    it('returns an array of wallet names', async () => {
      let result = await cli(['walletList'], '.');
      let list = parseJsonOutput(result);
      expect(list.length).toBeGreaterThanOrEqual(2);
    });
  });
});

function cli(args, cwd) {
  return new Promise(resolve => {
    exec(`yarn run cli ${args.join(' ')}`,
    { cwd },
    (error, stdout, stderr) => { resolve({
    code: error && error.code ? error.code : 0,
    error,
    stdout,
    stderr })
  })
})}

function parseJsonOutput(output) {
  let preparse = output.stdout.split('\n').slice(1).join('\n').replace(/'/g, '"').replace(/(?:[\w]+(?=:[" ]))/g, x => `"${x}"`).replace(/\[Object\]/g, '{}').trim();
  //console.log(preparse);
  return JSON.parse(preparse);
}

function parseString(output, line=0) {
  let parsed = output.stdout.split('\n').slice(1);
  return parsed[line];
}
