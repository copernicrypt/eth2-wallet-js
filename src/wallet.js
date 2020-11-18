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
import { Eip2333 } from './key/eip2333';
import { deriveKey } from './key/eip2334';
import { getStore } from './store/index';
import DEPOSIT_CONTRACT from './depositContract.json';
const bip39 = require('bip39');

const init = bls.init(bls.BLS12_381);
const HOMEDIR = require('os').homedir();
const VERSION = 1;
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
      fork_version: 'pyrmont',
      key: null,
      store: null
    }
    opts = { ...defaults, ...opts };
    this.version = VERSION;
    this.algorithm = opts.algorithm;
    this.forkVersion = types.FORKS[opts.fork_version];
    this.key = (opts.key === null) ? getKey(this.algorithm) : opts.key;
    this.store = (opts.store === null) ? getStore(opts.wallet_path) : opts.store;
    this.mnemonic = getKey(this.algorithm, 'mnemonic');
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
   * @param  {String} [forkVersion=null] Optionally override the Instance fork version.
   * @return {Object|String}     Either an object containing the depoosit fields, or the raw TX data string.
   */
  async depositData(walletId, keyId, password, withdrawalOpts, forkVersion=null ) {
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
          signature: Buffer.alloc(96)
      };
      // forkVersion Override
      let forkChoice = this.forkVersion;
      if(forkVersion !== null) {
        if(!types.FORKS.hasOwnProperty(forkVersion)) throw new Error(`Fork choice must be one of ${Object.keys(types.FORKS).toString()}`);
        else forkChoice = types.FORKS[forkVersion];
      }
      let signingRoot = utils.getSigningRoot(depositData, forkChoice);
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
        amount: depositData.amount.toString(),
        signature: Buffer.from(depositData.signature).toString('hex'),
        deposit_message_root: signingRoot.toString('hex'),
        deposit_data_root: depositDataRoot.toString('hex'),
        fork_version: forkChoice.toString('hex'),
        eth2_network_name: _.findKey(types.FORKS, forkChoice)
      }
    }
    catch(error) { throw error; }
  }

  /**
   * Creates a new ETH2 keypair.
   * @param  {String} wallet_id The name of the wallet to create an key in.
   * @param  {String} password The password to protect the key.
   * @param  {String} [opts.keyId=UUID] The name of the key to create.
   * @param  {String} [opts.walletPassword=null] Wallet password for HD wallets.
   * @return {Object} An object containing the wallet_id, key_id and public_key.
   * @throws On failure
   */
  async keyCreate(walletId, password, opts={}) {
    try {
      let defaults = { keyId: uuidv4(), walletPassword: null, path:'' };
      opts = { ...defaults, ...opts };
      const walletType = await this.store.indexType(walletId);
      let privateKeyHex;

      if(types.WALLET[walletType] === 'HD') {
        if(_.isEmpty(opts.walletPassword)) throw new Error('HD wallets require a password to unlock.')
        let nextAccount = await this.store.indexAccountNext(walletId);
        let mnemonicEncrypted = await this.store.mnemonicGet(walletId);
        let mnemonic = await this.mnemonic.decrypt(mnemonicEncrypted, opts.walletPassword);
        privateKeyHex = await this.keyDerive(mnemonic, nextAccount);
        opts.path = `m/12381/3600/${nextAccount}/0`;
      }
      else privateKeyHex =  await this.keyRandom();

      return await this.keyImport(walletId, privateKeyHex, password, { keyId: opts.keyId, path: opts.path, hdOverride: true });
    }
    catch(error) { throw error; }
  }

  async keyRandom() {
    const sec = new bls.SecretKey()
    sec.setByCSPRNG();
    const pub = sec.getPublicKey();
    return bls.toHexStr(sec.serialize());
  }

  async keyDerive(mnemonic, account, use=0, sub=null) {
    try {
      const seed = await bip39.mnemonicToSeed(mnemonic);
      let extra  = (sub !== null) ? `${sub}` : '';
      const key = deriveKey(seed, `m/12381/3600/${account}/${use}${extra}`);
      return key.toString('hex');
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
      const walletType = await this.store.indexType(walletId);
      if(types.WALLET[walletType] === 'HD') throw new Error('Cannot delete keys from HD wallets.');

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
   * @param  {String}  [opts.keyId] The ID reference for the key.
   * @param  {String}  [opts.path] Optional derivation path reference.
   * @param  {Boolean} [opts.hdOverride] Overrides the default rejection of importing into HD wallets. Only used by the create function.
   * @return {Object}  An object containing the walletId <string> key ID <UUID> and public key <48-byte HEX>
   * @throws On failure
   */
  async keyImport(walletId, privateKey, password, opts={}) {
    try {
      const walletType = await this.store.indexType(walletId);
      if(types.WALLET[walletType] === 'HD' && opts.hdOverride !== true) throw new Error('Cannot import keys into HD wallets.');

      let defaults = { keyId: uuidv4(), path: ''};
      opts = { ...defaults, ...opts };
      const sec = bls.deserializeHexStrToSecretKey(privateKey);
      const pub = sec.getPublicKey();
      const pubKeyHex = bls.toHexStr(pub.serialize());
      let saveData = await this.key.encrypt(privateKey, password, pubKeyHex, { keyId: opts.keyId, path: opts.path });
      await this.store.keyWrite(saveData, { keyId: opts.keyId, publicKey: pubKeyHex, path: walletId } );

      return {
        wallet_id: walletId,
        key_id: opts.keyId,
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
   * Parses a password file and returns the password for a key
   * @param  {String}  file   The file destination to read.
   * @param  {String}  wallet The wallet ID to search for.
   * @param  {String}  key    The key ID to get password for.
   * @return {String}         The password for this key.
   */
  async parsePasswordFile(file, wallet, key) {

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
   * Creates a wallet backup file
   * @param  {String}  walletId           The ID of the wallet to backup.
   * @param  {String}  [destination=null] The destination to write the backup file.
  * @return {Promise}                    Resolves to save destination path on success.
   */
  async walletBackup(walletId, destination=null) {
    return this.store.pathBackup(walletId, destination);
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
    if(!types.WALLET.hasOwnProperty(opts.type)) throw new Error(`Wallet type '${opts.type}' not supported`);
    // HD wallet validation
    if(opts.type == 2) {
      if(_.isEmpty(opts.password)) throw new Error('Password required for HD wallets');
      if(!_.isEmpty(opts.mnemonic) && opts.mnemonic.trim().split(/\s+/g).length < 24) throw new Error('Mnemonic must be at least 24 words long.')
    }
    try {
      await this.store.indexCreate(opts.wallet_id, opts.type);
      // Handle Mnemonic storage
      if(opts.type == 2) {
        let mnemonic = (_.isEmpty(opts.mnemonic)) ? await bip39.generateMnemonic(256) : opts.mnemonic;
        let mnemonicEncrypted = await this.mnemonic.encrypt(mnemonic, opts.password);
        await this.store.mnemonicCreate(mnemonicEncrypted, opts.wallet_id);
      }
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

  /**
   * Returns the wallet mnemonic phrase.
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  password The password protecting the mnemonic.
   * @return {String}           The mnemonic phrase.
   */
  async walletMnemonic(walletId, password) {
    try {
      const walletType = await this.store.indexType(walletId);
      if(types.WALLET[walletType] === 'Simple') throw new Error('Only HD wallets have mnemonics');

      let mnemonicJson = await this.store.mnemonicGet(walletId);
      return await this.mnemonic.decrypt(mnemonicJson, password);
    }
    catch(error) { throw error; }
  }

  /**
   * Restores a wallet from file.
   * @param  {String}  source The absolute path of the source file.
   * @param  {String}  [wallet=null] Optional wallet name to import into. Defaults to filename.
   * @return {Boolean}        Returns true on success.
   * @throws On Failure.
   */
  async walletRestore(source, wallet=null) {
    return this.store.pathRestore(source, wallet);
  }
}
