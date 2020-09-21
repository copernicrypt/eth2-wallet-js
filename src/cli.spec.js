import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import * as types from './types';
const exec = require('child_process').exec;
const KEY_OBJECT = {
  wallet_id: expect.stringMatching(types.ANY),
  key_id: expect.stringMatching(types.UUID),
  public_key: expect.stringMatching(types.PUBLIC_KEY)
}

describe('CLI', () => {
  jest.setTimeout(10000);
  let testWallet = 'cliTester';
  let testWallet2 = 'cliTester2';
  let keyWallet = 'cliKeyTest';
  let testKey = uuidv4();
  let testPassword = 'test';

  beforeAll(async() => await cli(['walletCreate', `--wallet=${keyWallet}`], '.'));
  afterAll(async() => await cli(['walletDelete', `--wallet=${keyWallet}`], '.'));

  describe('depositData', () => {

  });

  describe('keyCreate', () => {
    it('fails when walletId is missing', async() => {
      let result = await cli(['keyCreate', `--password=${testPassword}`], '.');
      expect(result.stderr.includes('required option'));
    });
    it('fails when password is missing', async() => {
      let result = await cli(['keyCreate', `--wallet=${keyWallet}`], '.');
      expect(result.stderr.includes('required option'));
    });
    it('returns key result when complete', async() => {
      let result = await cli(['keyCreate', `--wallet=${keyWallet}`, `--password=${testPassword}`], '.');
      let key = parseJsonOutput(result);
      expect(key).toMatchObject(KEY_OBJECT);
    });
  });

  describe('keyDelete', () => {

  });

  describe('keyImport', () => {

  });

  describe('keyList', () => {

  });

  describe('keyPrivate', () => {

  });

  describe('keySearch', () => {

  });

  describe('sign', () => {

  });

  describe('walletCreate', () => {
    afterEach(async() => {
      await cli(['walletDelete', `--wallet=${testWallet}`], '.');
    });
    it('returns a successful message', async () => {
      let result = await cli(['walletCreate', `--wallet=${testWallet}`], '.');
      expect(result.stdout.includes(`Created wallet: ${testWallet}`)).toBe(true);
    });
    it('returns a random UUID when no wallet ID specified', async () => {
      let result = await cli(['walletCreate'], '.');
      let walletId = (result.stdout.split(': ')[1]).trim();
      expect(result.stdout.includes(`Created wallet:`)).toBe(true);
      expect(types.UUID.test(walletId)).toBe(true);
      await cli(['walletDelete', `--wallet=${walletId}`], '.');
    });
    it('returns error when creating a duplicate', async() => {
      await cli(['walletCreate', `--wallet=${testWallet}`], '.');
      let result = await cli(['walletCreate', `--wallet=${testWallet}`], '.');
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
  let preparse = output.stdout.split('\n').slice(1).join('\n').replace(/'/g, '"').replace(/(?:[\w]+(?=:[" ]))/g, x => `"${x}"`).trim();
  return JSON.parse(preparse);
}
