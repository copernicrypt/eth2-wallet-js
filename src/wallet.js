/**
 * @module Wallet
 */
import _ from 'lodash';
import crypto from 'crypto';
import bls from 'bls-eth-wasm';
import { ethers } from "ethers";
import  { v4 as uuidv4 } from 'uuid';
import * as types from './types';
import * as utils from './utils';
import { getKey } from './key/index';
import { getStore } from './store/index';

import DEPOSIT_CONTRACT from './depositContract.json';
const init = bls.init(bls.BLS12_381);
const HOMEDIR = require('os').homedir();
const VERSION = 1;
const FORK_VERSION = Buffer.from('00000001','hex');
const BLS_WITHDRAWAL_PREFIX = Buffer.from('00', 'hex');
const DEPOSIT_AMOUNT = BigInt(32000000000);

/**
 * An implementation of ETH2 Wallet
 * @type {Object}
 */
export class Wallet {
  constructor(opts={}) {
    let defaults = {
      wallet_path: `${HOMEDIR}/.eth2-wallet-js/wallet`,
      algorithm: 'aes-256-cbc',
      fork_version: FORK_VERSION,
      key: null,
      store: null
    }
    opts = { ...defaults, ...opts };
    this.version = VERSION;
    this.algorithm = opts.algorithm;
    this.forkVersion = opts.fork_version;
    this.key = getKey(this.algorithm);
    this.store = getStore(opts.wallet_path);
    this.key = (opts.key === null) ? getKey(this.algorithm) : opts.key;
    this.store = (opts.store === null) ? getStore(opts.wallet_path) : opts.store;
  }

  /**
   * This just awaits the initialization of the BLS package.
   * @return {Null}
   */
  async init() {
    await init;
    return;
  }

  /**
   * Gets the deposit data fields for a validator deposit on the ETH1 chain.
   * @param  {String}  walletId  The wallet ID where the validator key is stored.
   * @param  {String}  keyId     The key ID of the validator to generate data for.
   * @param  {String}  password  The password of the validator key.
   * @param  {Object} withdrawalOpts Withdrawal Parameters. Either withdrawalOpts.withdrawal_public_key, withdrawalOpts.withdrawal_key_id or withdrawalOpts.withdrawal_key_wallet must be specified.
   * @param  {String} [withdrawalOpts.withdrawal_key_id=<keyId>] The keyID of the Withdrawal key.
   * @param  {String} [withdrawalOpts.withdrawal_key_wallet=<walletId>] The wallet ID where the withdrawal key is stored.
   * @param  {String} [withdrawalOpts.withdrawal_public_key=null] The public key of the withdrawal key. Overrides withdrawal_key_wallet and withdrawal_key_id.
   * @return {Object|String}     Either an object containing the depoosit fields, or the raw TX data string.
   */
  async depositData(walletId, keyId, password, withdrawalOpts ) {
    let fields = ['withdrawal_key_wallet', 'withdrawal_key_id', 'withdrawal_public_key'];
    let hasOpt = fields.some(f => _.has(withdrawalOpts, f));
    if(!hasOpt) throw new Error(`Options must include One of: ${fields.toString()}`);
    let defaults = { withdrawal_key_id: keyId, withdrawal_key_wallet: walletId, withdrawal_public_key: null, amount: DEPOSIT_AMOUNT, raw: true };
    let opts = {...defaults, ...withdrawalOpts };
    try {
      let validatorKey = await this.store.keySearch(keyId, walletId);
      let validatorPubKey = validatorKey.public_key;
      let withdrawPubKey;
      if(types.PUBLIC_KEY.test(opts.withdrawal_public_key)) withdrawPubKey = opts.withdrawal_public_key;
      else {
        let withdrawKey = await this.store.keySearch(opts.withdrawal_key_id, opts.withdrawal_key_wallet);
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

  /**
   * Creates a new ETH2 keypair.
   * @param  {String} wallet_id The name of the wallet to create an key in.
   * @param  {String} password The password to protect the key.
   * @param  {String} keyId=UUID] The name of the key to create.
   * @return {Object} An object containing the wallet_id, key_id and public_key.
   * @throws On failure
   */
  async keyCreate(walletId, password, keyId=uuidv4()) {
    try {
      const sec = new bls.SecretKey()
      sec.setByCSPRNG();
      const pub = sec.getPublicKey();
      let privateKeyHex = bls.toHexStr(sec.serialize());
      return await this.keyImport(walletId, privateKeyHex, password, keyId);
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
      await this.store.keyDelete(keyId, walletId);
      return true;
    }
    catch(error) { throw error; }
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
  async keyImport(walletId, privateKey, password, keyId=uuidv4()) {
    try {
      const sec = bls.deserializeHexStrToSecretKey(privateKey);
      const pub = sec.getPublicKey();
      const pubKeyHex = bls.toHexStr(pub.serialize());
      let saveData = await this.key.encrypt(privateKey, password, pubKeyHex, { keyId: keyId });
      await this.store.keyWrite(saveData, { keyId: keyId, publicKey: pubKeyHex, path: walletId } );

      return {
        wallet_id: walletId,
        key_id: keyId,
        public_key: pubKeyHex
      }
    }
    catch(error) { throw error; }
  }

  /**
   * List of available keys in a wallet.
   * @param  {String}  id The wallet ID to search
   * @return {Array}   An array of key objects.
   */
  async keyList(walletId) {
    return this.store.keyList(walletId);
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
      let key = await this.store.keySearch(keyId, walletId);
      return await this.key.decrypt(key.key_object, password);
    }
    catch(error) { throw error; }
  }

  /**
   * Finds a key in the store.
   * @param  {String}  search   The keyId or public key to search for.
   * @param  {String}  walletId The wallet storing the key.
   * @return {Object}           The key object.
   */
  async keySearch(search, walletId) {
    return this.store.keySearch(search, walletId);
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
      let keyObject = await this.store.keySearch(search, walletId);
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
    let walletExists = await this.store.indexExists(opts.wallet_id);
    if(walletExists) throw new Error('Wallet already exists');
    try {
      await this.store.indexCreate(opts.wallet_id);
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
      let walletExists = await this.store.indexExists(walletId);
      if(!walletExists) throw new Error('Wallet does not exist');
      return this.store.pathDelete(walletId);
    }
    catch(error) { throw error; }
  }

  /**
   * Return a list of available wallet IDs
   * @return {Array} A list of wallet IDs.
   * @throws On failure
   */
  async walletList() {
    return this.store.pathList();
  }
}
