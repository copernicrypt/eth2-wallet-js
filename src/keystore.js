import _ from 'lodash';
import crypto from 'crypto';
import path from 'path';
import util from 'util';
import fs from 'fs';
import bls from 'bls-eth-wasm';
import { ethers } from "ethers";
import  { v4 as uuidv4 } from 'uuid';
import PQueue from 'p-queue';
import * as types from './types';
import * as utils from './utils';

const DEPOSIT_CONTRACT = require('./depositContract.json');
const init = bls.init(bls.BLS12_381);
const HOMEDIR = require('os').homedir();
const VERSION = 1;
const FORK_VERSION = Buffer.from('00000001','hex');
const BLS_WITHDRAWAL_PREFIX = Buffer.from('00', 'hex');
const DEPOSIT_AMOUNT = BigInt(32000000000);

class Keystore {
  constructor(opts={}) {
    let defaults = {
      wallet_path: `${HOMEDIR}/.eth2-wallet-js/wallet`,
      algorithm: 'aes-256-cbc',
      fork_version: FORK_VERSION
    }
    opts = { ...defaults, ...opts };
    this.version = VERSION;
    this.queue = new PQueue({ concurrency: 1 });
    this.algorithm = opts.algorithm;
    this.walletPath = opts.wallet_path;
    this.forkVersion = opts.fork_version;
  }

  /**
   * This just awaits the initialization of the BLS package.
   * @return {Null}
   */
  async init() {
    await init;
    return;
  }

  async depositData(walletId, keyId, password, opts={} ) {
    let defaults = { withdraw_key_id: keyId, withdraw_key_wallet: walletId, withdraw_public_key: null, amount: DEPOSIT_AMOUNT, raw: true };
    opts = {...defaults, ...opts };
    try {
      let validatorKey = await this.keySearch(keyId, walletId);
      let validatorPubKey = validatorKey.public_key;
      let withdrawPubKey;
      if(types.PUBLIC_KEY.test(opts.withdraw_public_key)) withdrawPubKey = opts.withdraw_public_key;
      else {
        let withdrawKey = await this.keySearch(opts.withdraw_key_id, opts.withdraw_key_wallet);
        withdrawPubKey = withdrawKey.public_key;
      }

      //deposit data with empty signature to sign
      const withdrawalPubKeyHash = crypto.createHash('sha256').update(Buffer.from(withdrawPubKey, 'hex')).digest();
      const depositData = {
          pubkey: Buffer.from(validatorPubKey, 'hex'),
          withdrawalCredentials: Buffer.concat([ BLS_WITHDRAWAL_PREFIX, withdrawalPubKeyHash.slice(1) ]),
          amount: opts.amount,
          signature: Buffer.alloc(96),
      };
      let signingRoot = utils.getSigningRoot(depositData, this.forkVersion);
      depositData.signature = await this.sign(signingRoot.toString('hex'), walletId, validatorPubKey, password);
      let depositDataRoot = utils.getDepositDataRoot(depositData);
      if(opts.raw == true) {
        let contract = new ethers.utils.Interface(DEPOSIT_CONTRACT.abi);
        let raw = contract.encodeFunctionData("deposit", [
          depositData.pubkey,
          depositData.withdrawalCredentials,
          depositData.signature,
          depositDataRoot,
        ]);
        return raw;
      }
      else return {
        pubkey: validatorPubKey,
        withdrawal_credentials: depositData.withdrawalCredentials.toString('hex'),
        signature: Buffer.from(depositData.signature).toString('hex'),
        amount: depositData.amount.toString(),
        deposit_data_root: depositDataRoot.toString('hex')
      }
    }
    catch(error) { throw error; }
  }

  async keyCreate(walletId, password, accountId=uuidv4()) {
    return this.queue.add(() => this.keyCreateAsync(walletId, password, accountId));
  }

  /**
   * Creates a new ETH2 keypair.
   * @param  {String} wallet_id The name of the wallet to create an key in.
   * @param  {String} password The password to protect the key.
   * @param  {String} keyId=UUID] The name of the key to create.
   * @return {Object} An object containing the wallet_id, key_id and public_key.
   * @throws On failure
   */
  async keyCreateAsync(walletId, password, keyId=uuidv4()) {
    try {
      const sec = new bls.SecretKey()
      sec.setByCSPRNG();
      const pub = sec.getPublicKey();
      let privateKeyHex = bls.toHexStr(sec.serialize());
      return await this.keyImportAsync(walletId, privateKeyHex, password, keyId);
    }
    catch(error) { throw error; }
  }

  /**
   * Removes a key from a wallet.
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @param  {String}  password The password protecting the key.
   * @return {Boolean}          True on successful deletion.
   * @throws On failure
   */
  async keyDelete(walletId, keyId, password) {
    try {
      let key = await this.keyPrivate(walletId, keyId, password);
      let indexFile = await this.walletIndexKey(walletId, keyId, null, true);
      let keyFile = await fs.promises.unlink(`${this.walletPath}/${walletId}/${keyId}`);
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Check whether a key already exists.
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @return {Boolean}          Whether or not the key ID already exists in the wallet.
   * @throws On failure
   */
  async keyExists(search, walletId) {
    try {
      let indexSearch = await this.keySearch(search, walletId);
      let fileSearch = await fs.promises.access(`${this.walletPath}/${walletId}/${indexSearch.key_id}`);
      return true;
    }
    catch(error) {
      //console.error(error);
      return false;
    }
  }

  async keyImport(walletId, privateKey, password, keyId=uuidv4()) {
    return this.queue.add(() => this.keyImportAsync(walletId, privateKey, password, keyId));
  }

  /**
   * Import a private key into the keystore
   * @param  {String}  walletId The wallet to import into.
   * @param  {String}  privateKey A 32byte HEX-format private key
   * @param  {String}  password A password to protect the key.
   * @param  {String}  keyId The ID reference for the key.
   * @return {Object}  An object containing the walletId <string> key ID <UUID> and public key <48-byte HEX>
   * @throws On failure
   */
  async keyImportAsync(walletId, privateKey, password, keyId=uuidv4()) {
    try {
      if(await this.keyExists(keyId, walletId))
        throw new Error('Key ID already exists.');
      if(await this.keyExists(privateKey, walletId))
          throw new Error('Private Key already exists.');

      const sec = bls.deserializeHexStrToSecretKey(privateKey);
      const pub = sec.getPublicKey();
      const pubKeyHex = bls.toHexStr(pub.serialize());
      let saveData = await this.encrypt(privateKey, password);

      let walletFile = fs.promises.writeFile( `${this.walletPath}/${walletId}/${keyId}`, JSON.stringify(saveData) );
      let indexFile = this.walletIndexKey(walletId, keyId, pubKeyHex);
      await Promise.all([walletFile, indexFile]);

      return {
        wallet_id: walletId,
        key_id: keyId,
        public_key: pubKeyHex
      }
    }
    catch(error) { throw error; }
  }

  /**
   * Get a private key
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @param  {String}  password The password protecting the key.
   * @return {String}           The 64-byte HEX formatted private key.
   * @throws On failure
   */
  async keyPrivate(walletId, keyId, password) {
    try {
      let data = await this.decrypt(walletId, keyId, password);
      return data;
    }
    catch(error) { throw error; }
  }

  /**
   * Finds key information.
   * @param  {String}  search   Either an key ID or public key.
   * @param  {String}  walletId The wallet ID to search for keys.
   * @return {Object}  Object containing key_id and public_key.
   * @throws On failure
   */
  async keySearch(search, walletId) {
    try {
      let buffer = await fs.promises.readFile(`${this.walletPath}/${walletId}/index`);
      let index = JSON.parse(buffer.toString());
      let searchField;
      // Convert private key to public key for search.
      if(types.PRIVATE_KEY.test(search)) {
        const sec = bls.deserializeHexStrToSecretKey(search);
        const pub = sec.getPublicKey();
        const pubKeyHex = bls.toHexStr(pub.serialize());
        searchField = 'public_key';
        search = pubKeyHex;
      }
      else searchField = (types.PUBLIC_KEY.test(search)) ? 'public_key' : 'key_id';
      let keyObj = _.find(index.key_list, { [searchField]: search });
      //console.log(`${keyObj} -- Field: ${searchField} -- Search: ${search} -- Wallet: ${walletId}`);
      if(_.isNil(keyObj)) throw new Error('Key not found.')
      return { key_id: keyObj.key_id, public_key: keyObj.public_key, wallet_id: walletId }
    }
    catch (error) { throw error; }
  }

  /**
  * Signs a generic message with a private key.
  * @param  {String}  message   The message to sign (32-Byte HEX)
   * @param  {String}  walletId Wallet ID where the key is stored.
   * @param  {String}  search   The key to search for. Accepts keyID, publicKey, and privateKey.
   * @param  {String}  password Password protecting the signing key.
   * @return {Array}   The 96-byte BLS signature.
   */
  async sign(message, walletId, search, password) {
    try {
      let keyObject = await this.keySearch(search, walletId);
      let secHex = await this.keyPrivate(walletId, keyObject.key_id, password);
      const sec = bls.deserializeHexStrToSecretKey(secHex);
      const pub = sec.getPublicKey();
      const msg = bls.fromHexStr(message);
      const sig = sec.sign(msg);
      let serialized = sig.serialize()
      return serialized;
    }
    catch(error) { throw error; }
  }

  /**
   * Creates a new wallet to store keys.
   * @param  {Object}  [opts={}] Optional parameters.
   * @param  {String}  [opts.wallet_id=uuidv4] Wallet identifer. If not provided, will be random.
   * @param  {String}  [opts.type=1] The type of wallet to create. 1=Simple, 2=Hierarchical deterministic.
   * @param  {String}  [opts.password=null] Password for HD wallets.
   * @param  {String}  [opts.mnemonic=null] BIP39 mnemonic for HD wallets.
   * @return {String}  The wallet identifier.
   * @throws On failure
   */
  async walletCreate(opts={}) {
    let defaults = { wallet_id: uuidv4(), type: 1 };
    opts = { ...defaults, ...opts };
    let walletExists = await this.walletExists(opts.wallet_id);
    if(walletExists) throw new Error('Wallet already exists');
    try {
      await fs.promises.mkdir(`${this.walletPath}/${opts.wallet_id}`, { recursive: true });
      const indexData = { type: opts.type, key_list: [] };
      await fs.promises.writeFile(`${this.walletPath}/${opts.wallet_id}/index`, JSON.stringify(indexData));
      return opts.wallet_id;
    }
    catch(error) { throw error; }
  }

  /**
   * Delete a wallet
   * @param  {String}  id The wallet identifier
   * @return {Boolean}    True if the delete was successful.
   * @throws On failure
   */
  async walletDelete(walletId) {
    try {
      let walletExists = await this.walletExists(walletId);
      if(!walletExists) throw new Error('Wallet does not exist');
      await fs.promises.rmdir(`${this.walletPath}/${walletId}`, { recursive: true });
      return true;
    }
    catch(error) { throw error; }
  }

  async walletExists(walletId) {
    try {
      await fs.promises.access(`${this.walletPath}/${walletId}`);
      return true;
    }
    catch(error) {
      return false;
    }
  }

  /**
   * Return a list of available wallet IDs
   * @return {Array} A list of wallet IDs.
   * @throws On failure
   */
  async walletList() {
    try {
      // get all the files and directories
      let list = await fs.promises.readdir(`${this.walletPath}`, { withFileTypes: true });
      // filter out files and hidden folders
      let dirList = list.filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name)
        .filter(item => !(/(^|\/)\.[^\/\.]/g).test(item));
      return dirList;
    }
    catch(error) { throw error; }
  }

  /**
   * List of available keys in a wallet.
   * @param  {String}  id The wallet ID to search
   * @return {Array}   An array of key objects.
   */
  async walletListKeys(walletId) {
    try {
      let buffer = await fs.promises.readFile(`${this.walletPath}/${walletId}/index`);
      let indexData = JSON.parse(buffer.toString());
      return indexData.key_list;
    }
    catch(error) { throw error; }
  }

  /**
   * Modifies a wallet index file. Either adds or removes a key.
   * @param  {String}  walletId         The wallet file to modify
   * @param  {String}  keyId            The key to modify
   * @param  {String}  [publicKey=null] 48-Byte HEX public key
   * @param  {Boolean} [remove=false]   Whether to remove the key
   * @return {Boolean}                  True on sucess
   * @throws On failure
   */
  async walletIndexKey(walletId, keyId, publicKey=null, remove=false) {
    try {
      let buffer = await fs.promises.readFile(`${this.walletPath}/${walletId}/index`);
      let indexData = JSON.parse(buffer.toString());
      // check for existing keys
      let indexSearch = (publicKey === null) ? keyId : publicKey;
      let hasKey = await this.keyExists(indexSearch, walletId);

      if(remove == true && hasKey) _.remove(indexData.key_list, function(o) { o.key_id == keyId });
      else if( remove == false && !hasKey) indexData.key_list.push({ key_id: keyId, public_key: publicKey });
      else if(remove == true && !hasKey) throw new Error(`Key not found: ${keyId}.`)
      else if(remove == false && hasKey) throw new Error(`Duplicate key found: ${publicKey}.`)

      await fs.promises.writeFile(`${this.walletPath}/${walletId}/index`, JSON.stringify(indexData));
      return true;
    }
    catch(error) { throw error; }
  }

  async encrypt(text, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest();

    let cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { algorithm: this.algorithm, iv: iv.toString('hex'), data: encrypted.toString('hex') };
  }

  async decrypt(walletId, keyId, password) {
    let buffer = await fs.promises.readFile(`${this.walletPath}/${walletId}/${keyId}`);
    let text = JSON.parse(buffer.toString());
    let iv = Buffer.from(text.iv, 'hex');
    const key = crypto.createHash('sha256').update(password).digest();

    let encryptedText = Buffer.from(text.data, 'hex');
    let decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
}

module.exports = {
  Keystore
}
