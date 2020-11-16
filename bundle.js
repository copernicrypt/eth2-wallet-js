'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var _ = require('lodash');
var crypto = require('crypto');
var bls = require('bls-eth-wasm');
var ethers = require('ethers');
var uuid = require('uuid');
var bigintBuffer = require('bigint-buffer');
var mainnet = require('@chainsafe/lodestar-types/lib/ssz/presets/mainnet');
var util = require('util');
var fs = require('fs');
var PQueue = require('p-queue');
var archiver = require('archiver');
var extract = require('extract-zip');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var ___default = /*#__PURE__*/_interopDefaultLegacy(_);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var bls__default = /*#__PURE__*/_interopDefaultLegacy(bls);
var util__default = /*#__PURE__*/_interopDefaultLegacy(util);
var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
var PQueue__default = /*#__PURE__*/_interopDefaultLegacy(PQueue);
var archiver__default = /*#__PURE__*/_interopDefaultLegacy(archiver);
var extract__default = /*#__PURE__*/_interopDefaultLegacy(extract);

const PUBLIC_KEY = new RegExp("^(0x)?[0-9a-f]{96}$");
const UUID = new RegExp("^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$", 'i');
const FORKS = { 'mainnet': Buffer.from('00000000','hex'), 'pyrmont': Buffer.from('00002009', 'hex'), 'medalla': Buffer.from('00000001','hex')};
const WALLET = { 1: 'Simple', 2: 'HD' };

/**
 * @module constants
 */
const ZERO_HASH = Buffer.alloc(32, 0);
const EMPTY_SIGNATURE = Buffer.alloc(96, 0);

// Domain Types
const DomainType = {
  BEACON_PROPOSER: 0,
  BEACON_ATTESTER: 1,
  RANDAO: 2,
  DEPOSIT: 3,
  VOLUNTARY_EXIT: 4,
  SELECTION_PROOF: 5,
  AGGREGATE_AND_PROOF: 6,
};

function getSigningRoot(depositData, forkVersion) {
  const domainWrappedObject = {
      objectRoot: mainnet.types.DepositMessage.hashTreeRoot(depositData),
      domain: getDomain(forkVersion),
  };
  return mainnet.types.SigningData.hashTreeRoot(domainWrappedObject);
}

function getDomain(forkVersion, domainType=DomainType.DEPOSIT, genesisValidatorRoot=ZERO_HASH) {
  const forkDataRoot = getForkDataRoot(forkVersion, genesisValidatorRoot);
  return Buffer.concat([intToBytes(BigInt(domainType), 4), Uint8Array.from(forkDataRoot).slice(0, 28)]);
}

function getDepositDataRoot(depositData) {
  return mainnet.types.DepositData.hashTreeRoot(depositData);
}

function getForkDataRoot(currentVersion, genesisValidatorsRoot) {
  const forkData = {
    currentVersion,
    genesisValidatorsRoot,
  };
  return mainnet.types.ForkData.hashTreeRoot(forkData);
}

function intToBytes(value, length, endian='le') {
  if (endian === "le") {
    return bigintBuffer.toBufferLE(value, length);
  } else if (endian === "be") {
    return bigintBuffer.toBufferBE(value, length);
  }
  throw new Error("endian must be either 'le' or 'be'");
}

/**
 * Keystore implementation of EIP-2335
 * @see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md
 * @type {Class}
 */

const pbkdf2 = util__default['default'].promisify(crypto__default['default'].pbkdf2);

const VERSION = 4;
const SUPPORTED_ALGOS = ['aes-256-cbc', 'aes-256-ctr', 'aes-192-cbc', 'aes-192-ctr', 'aes-128-cbc', 'aes-128-ctr'];
const INTERATIONS = 262144;
const DECRYPTION_KEY_LENGTH = 32;

class Eip2335 {

  constructor(algorithm='aes-256-cbc', version=VERSION) {
    this.algorithm = algorithm;
    this.version = version;
    if(!SUPPORTED_ALGOS.includes(algorithm)) throw new Error(`Encryption algorithm not supported. Try ${SUPPORTED_ALGOS.toString()}`);
    if(algorithm.substr(0, 7) === 'aes-128') this.keyLength = 16;
    else if(algorithm.substr(0, 7) === 'aes-192') this.keyLength = 24;
    else if(algorithm.substr(0, 7) === 'aes-256') this.keyLength = 32;
  }

  async encrypt(privateKey, password, publicKey, opts={}) {
    // key_id needs to be a valid UUID for use in this spec. If it isn't create a new one.
    if(!UUID.test(opts.keyId)) delete opts.keyId;
    let defaults = { path: "", keyId: uuid.v4(), description: 'eth2-wallet-js key' };
    opts = {...defaults, ...opts };
    const iv = crypto__default['default'].randomBytes(16);
    const salt = crypto__default['default'].randomBytes(32).toString('hex');
    const key = await this.getDecryptionKey(password, salt);
    let decryptionKey = Buffer.from(key,'hex');

    let cipher = crypto__default['default'].createCipheriv(this.algorithm, decryptionKey.slice(0, this.keyLength), iv);
    let encrypted = cipher.update(Buffer.from(privateKey, 'hex'));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    let encryptedHex = encrypted.toString('hex');
    let checksum = this.getChecksum(key, encryptedHex);

    return {
      crypto: {
        kdf: { function: 'pbkdf2', params: { dklen: DECRYPTION_KEY_LENGTH, c: INTERATIONS, prf: 'sha256', salt: salt.toString('hex') }, message: '' },
        checksum: { function: 'sha256', params: {}, message: checksum },
        cipher: { function: this.algorithm, params: { iv: iv.toString('hex') }, message: encryptedHex }
      },
      description: opts.description,
      "pubkey": publicKey,
      "path": opts.path,
      "uuid": opts.keyId,
      "version": this.version,
    }
  }

  async decrypt(jsonKey, password) {
    let ivBuf = Buffer.from(jsonKey.crypto.cipher.params.iv, 'hex');
    let key = await this.getDecryptionKey(password, jsonKey.crypto.kdf.params.salt, jsonKey.crypto.kdf.params.c, jsonKey.crypto.kdf.params.dklen);
    let decryptionKey = Buffer.from(key,'hex');
    if(!this.verifyPassword(decryptionKey, jsonKey.crypto.cipher.message, jsonKey.crypto.checksum.message)) throw new Error('Invalid Password');

    let encryptedText = Buffer.from(jsonKey.crypto.cipher.message, 'hex');
    let decipher = crypto__default['default'].createDecipheriv(this.algorithm, decryptionKey.slice(0, this.keyLength), ivBuf);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('hex');
  }

  verifyPassword(decryptionKey, cipher, checksum) {
    try {
      let keyChecksum = this.getChecksum(decryptionKey, cipher);
      return (keyChecksum == checksum);
    }
    catch(error) { throw error; }
  }

  getChecksum(key, cipher) {
    try {
      let dkSlice = Buffer.from(key, 'hex').slice(16,32);
      let preImage = Buffer.concat([dkSlice, Buffer.from(cipher, 'hex')]);
      let checksum = crypto__default['default'].createHash('sha256').update(preImage).digest();
      return checksum.toString('hex');
    }
    catch(error) { throw error; }
  }

  /**
   * Gets a decryption key from store details
   * @param  {String}  password The UTF8-encoded password.
   * @param  {String}  salt     32-Byte HEX salt
   * @return {String}           64-Byte HEX decryption key
   * @throws On failure.
   */
  async getDecryptionKey(password, salt, iterations=INTERATIONS, keylength=DECRYPTION_KEY_LENGTH) {
    try {
      password = await this.passwordFilter(password);
      let derivedKey = await pbkdf2(Buffer.from(password, 'utf8'), Buffer.from(salt, 'hex'), iterations, keylength, 'sha256');
      return derivedKey.toString('hex');
    }
    catch(error) { throw error; }
  }

  async passwordFilter(password) {
    let filtered = password.replace(/[\x00-\x1F\x7F-\x9F]/g, "");    return filtered;
  }
}

const VERSION$1 = 1;
const SUPPORTED_ALGOS$1 = ['aes-256-cbc', 'aes-256-ctr', 'aes-192-cbc', 'aes-192-ctr', 'aes-128-cbc', 'aes-128-ctr'];

class SimpleJson {
  constructor(algorithm='aes-256-cbc', version=VERSION$1) {
    this.algorithm = algorithm;
    this.version = version;
    if(!SUPPORTED_ALGOS$1.includes(algorithm)) throw new Error(`Encryption algorithm not supported. Try ${SUPPORTED_ALGOS$1.toString()}`);
    if(algorithm.substr(0, 7) === 'aes-128') this.keyLength = 16;
    else if(algorithm.substr(0, 7) === 'aes-192') this.keyLength = 24;
    else if(algorithm.substr(0, 7) === 'aes-256') this.keyLength = 32;
  }

  async encrypt(privateKey, password, publicKey, opts={}) {
    let defaults = { path: "", keyId: uuid.v4() };
    opts = {...defaults, ...opts };
    const iv = crypto__default['default'].randomBytes(16);
    const key = crypto__default['default'].createHash('sha256').update(password).digest();

    let cipher = crypto__default['default'].createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(privateKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { algorithm: this.algorithm, iv: iv.toString('hex'), data: encrypted.toString('hex'), public_key: publicKey, key_id: opts.keyId, path: opts.path };
  }

  async decrypt(jsonKey, password) {
    let iv = Buffer.from(jsonKey.iv, 'hex');
    const key = crypto__default['default'].createHash('sha256').update(password).digest();

    let encryptedText = Buffer.from(jsonKey.data, 'hex');
    let decipher = crypto__default['default'].createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
}

const VERSION$2 = 1;
const SUPPORTED_ALGOS$2 = ['aes-256-cbc', 'aes-256-ctr', 'aes-192-cbc', 'aes-192-ctr', 'aes-128-cbc', 'aes-128-ctr'];

class Mnemonic {
  constructor(algorithm='aes-256-cbc', version=VERSION$2) {
    this.algorithm = algorithm;
    this.version = version;
    if(!SUPPORTED_ALGOS$2.includes(algorithm)) throw new Error(`Encryption algorithm not supported. Try ${SUPPORTED_ALGOS$2.toString()}`);
    if(algorithm.substr(0, 7) === 'aes-128') this.keyLength = 16;
    else if(algorithm.substr(0, 7) === 'aes-192') this.keyLength = 24;
    else if(algorithm.substr(0, 7) === 'aes-256') this.keyLength = 32;
  }

  async encrypt(mnemonic, password, opts={}) {
    let defaults = { };
    opts = {...defaults, ...opts };
    const iv = crypto__default['default'].randomBytes(16);
    const key = crypto__default['default'].createHash('sha256').update(password).digest();

    let cipher = crypto__default['default'].createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(mnemonic);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { algorithm: this.algorithm, iv: iv.toString('hex'), data: encrypted.toString('hex') };
  }

  async decrypt(jsonKey, password) {
    let iv = Buffer.from(jsonKey.iv, 'hex');
    const key = crypto__default['default'].createHash('sha256').update(password).digest();

    let encryptedText = Buffer.from(jsonKey.data, 'hex');
    let decipher = crypto__default['default'].createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
}

/**
 * Returns a Key Object
 * @type {Function}
 * @param {String} algorithm The encryption algorithm used to protect the key.
 * @param {String} type The type of key [simple, eip2335].
 */
function getKey(algorithm, type) {
  switch(type) {
    case 'simple':
      return new SimpleJson(algorithm);
    case 'mnemonic':
      return new Mnemonic(algorithm);
    default:
      return new Eip2335(algorithm);
  }
}

/**
 * Converts and BigInt type to Buffer
 * @param  {BigInt} bn The number to convert
 * @return {Buffer}    The resulting buffer.
 */
function bigIntToBuffer(bn) {
  var hex = BigInt(bn).toString(16);
  if (hex.length % 2) { hex = '0' + hex; }

  var len = hex.length / 2;
  var u8 = new Uint8Array(len);

  var i = 0;
  var j = 0;
  while (i < len) {
    u8[i] = parseInt(hex.slice(j, j+2), 16);
    i += 1;
    j += 2;
  }
  return Buffer.from(u8);
}

/**
 * Key Generation implementation of EIP-2333
 * @see https://eips.ethereum.org/EIPS/eip-2333
 * @type {Class}
 */
const sha256 = require('bcrypto/lib/sha256');
const hkdf = require('bcrypto/lib/hkdf');

class Eip2333 {

  /**
   * Derives a lamport key from a secret
   * @param  {String} ikm  A secret octet string
   * @param  {String} salt An octet string
   * @return {Array<Buffer>}       An array of 255 32-octet strings

   */
  static ikmToLamportSk(ikm, salt) {
    const okm = hkdf.derive(sha256, Buffer.from(ikm), Buffer.from(salt), Buffer.alloc(0), 8160);
    let lsk = [];
    //break the buffer into 255 chunks of 32
    for(let i=0; i < 255; i++) {
      lsk.push(okm.slice(i*32, (i+1)*32));
    }
    return lsk;
  }
  /**
   * Converts a parent secret key to a compressed lamport private key
   * @param  {Buffer} parentSk The BLS Secret Key of the parent node
   * @param  {Integer} index    The index of the desired child node, an integer 0 <= index < 2^32
   * @return {Buffer}          The compressed lamport PK, a 32 octet string
   */
  static parentSkToLamportPk(parentSk, index) {
    const salt = Buffer.alloc(4);
    salt.writeUInt32BE(index, 0);
    const ikm = Buffer.from(parentSk);
    const lamport0 = Eip2333.ikmToLamportSk(ikm, salt);
    const notIkm = Buffer.from(ikm.map((value) => ~value));
    const lamport1 = Eip2333.ikmToLamportSk(notIkm, salt);
    const lamportPk = lamport0.concat(lamport1).map((value) => sha256.digest(value));
    return sha256.digest(Buffer.concat(lamportPk));
  }

  /**
   * Used to hash 32 random bytes into the subgroup of the BLS12-381 private keys.
   * @param  {String} ikm          A secret octet string >= 256 bits in length
   * @param  {String} [keyInfo=''] An optional octet string (default="", the empty string)
   * @return {BigInt}              The corresponding secret key, an integer 0 <= SK < r.
   */
  static hkdfModR(ikm, keyInfo='') {
    let salt = Buffer.from("BLS-SIG-KEYGEN-SALT-", "ascii");
    const r = BigInt("52435875175126190479447740508185965837690552500527637822603658699938581184513");
    let sk = BigInt(0);
    while (sk == 0) {
      salt = sha256.digest(salt);
      const okm = hkdf.derive(
        sha256,
        Buffer.concat([ikm, Buffer.alloc(1)]),
        salt,
        Buffer.concat([Buffer.from(keyInfo), Buffer.from([0, 48])]),
        48
      );
      sk = BigInt(`0x${okm.toString('hex')}`) % r;
    }
    return bigIntToBuffer(sk);
  }

  /**
   * Takes in the parent’s private key and the index of the child and returns the child private key.
   * @param  {Buffer} parentSk The secret key of the parent node, a big endian encoded integer
   * @param  {Integer} index   The index of the desired child node, an integer 0 <= index < 2^32
   * @return {Buffer}          The secret key of the child node, a big endian encoded integer
   */
  static deriveChildSk(parentSk, index) {
    const compressedLamportPk = Eip2333.parentSkToLamportPk(parentSk, index);
    return Eip2333.hkdfModR(compressedLamportPk);
  }

  /**
   * The seed should ideally be derived from a mnemonic, with the intention being that BIP39 mnemonics,
   * with the associated mnemonic_to_seed method be used.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
   * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
   * @param  {Buffer} seed The source entropy for the entire tree, a octet string >= 256 bits in length
   * @return {Buffer}      The secret key of master node within the tree, a big endian encoded integer.
   */
  static deriveMasterSk(seed) {
    if( (seed.byteLength * 8) < 256) throw new Error('Seed length is too short. You need at least 256-bits.')
    return Eip2333.hkdfModR(seed);
  }
}

const TYPES = { ETH1: 60, ETH2:3600 };

/**
 * Converts a derivation path to an array of indices based on the EIP334 specification. For use with EIP2333 key derivation.
 * @see https://eips.ethereum.org/EIPS/eip-2334
 * @param {String}  path The derivation path. ( m / purpose / coin_type /  account / use )
 * @param {Integer} [coinType='ETH2'] The type of coin to validate.
 * @throws When path is invalid.
 */
function pathToIndexList(path, coinType='ETH2') {
  const pathList = path.split("/");
  // Check validity of the path
  if(pathList.length < 5) throw new Error('Path must contain at least 5 levels. See https://eips.ethereum.org/EIPS/eip-2334#path.');
  if(pathList[0] !== 'm') throw new Error('Root level must be be "m". See https://eips.ethereum.org/EIPS/eip-2334#path');
  if(pathList[1] !== '12381') throw new Error('Purpose level must be be "12381". See https://eips.ethereum.org/EIPS/eip-2334#purpose');
  if(Number.parseInt(pathList[2]) !== TYPES[coinType]) throw new Error('Coin Type does not match. See https://eips.ethereum.org/EIPS/eip-2334#coin-type.')
  pathList.shift(); // Remove root level
  const indexList = pathList.map((level) => Number.parseInt(level));
  if( indexList.some(level => { return (Number.isNaN(level) || level < 0 || level >= 4294967296) }) ) throw new Error('Each level needs to be an integer in the range 0 <= i < 2**32');

  return indexList;
}

/**
 * Derive a key from a seed and path.
 * @param  {Buffer} seed The seed/entropy to derive from.
 * @param  {String} path The derivation path.
 * @return {Buffer}      The derived key.
 * @throws When path is invalid.
 */
function deriveKey(seed, path) {
  try {
    let key = Eip2333.deriveMasterSk(seed);
    const indexList = pathToIndexList(path);
    indexList.forEach(i => key = Eip2333.deriveChildSk(key, i));
    return key;
  }
  catch(error) {
    throw error;
  }
}

const HOMEDIR = require('os').homedir();

/**
 * Filesystem storage system for keys.
 * @type {Object}
 */
class Filesystem {
  constructor(opts={}) {
    let defaults = { path: `${HOMEDIR}/.eth2-wallet-js/wallet`, keyType: 1 };
    opts = {...defaults, ...opts };

    this.rootPath = opts.path;
    this.keyType = opts.keyType;
    this.indexQueue = new PQueue__default['default']({ concurrency: 1 });
  }

  /**
   * Deletes a key from the store.
   * @param  {String} search       The search term. Either keyId or publicKey.
   * @param  {String} [path=null] A subpath where the key is stored.
   * @return {Boolean}            Returns true when delete is successful.
   * @throws On failure.
   */
  async keyDelete(search, path=null) {
    try {
      let keyId = search;
      if(PUBLIC_KEY.test(search)) {
        let keyObj = await this.keySearch(search, path);
        keyId = keyObj.key_id;
      }
      let indexFile = await this.indexUpdate(keyId, null, true, path);
      let keyFile = await fs__default['default'].promises.unlink(this.pathGet(keyId, path));
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
  async keyExists(search, path=null) {
    try {
      let indexSearch = await this.keySearch(search, path);
      let fileSearch = await fs__default['default'].promises.access(this.pathGet(indexSearch.key_id, path));
      return true;
    }
    catch(error) {
      //console.error(error);
      return false;
    }
  }

  /**
   * List of available keys in a wallet.
   * @param  {String}  path The wallet ID to search
   * @return {Array}   An array of key objects.
   */
  async keyList(path=null) {
    try {
      let buffer = await fs__default['default'].promises.readFile(this.pathGet('index', path));
      let indexData = JSON.parse(buffer.toString());
      return indexData.key_list;
    }
    catch(error) { throw error; }
  }

  /**
   * Finds key information.
   * @param  {String}  search   Either an key ID or public key.
   * @param  {String}  path The subpath to search in. Either keyId or publicKey
   * @return {Object}  Object containing key_id and public_key.
   * @throws On failure
   */
  async keySearch(search, path=null) {
    try {
      let buffer = await fs__default['default'].promises.readFile(this.pathGet('index', path));
      let index = JSON.parse(buffer.toString());
      let searchField = (PUBLIC_KEY.test(search)) ? 'public_key' : 'key_id';
      let keyObj = ___default['default'].find(index.key_list, { [searchField]: search });
      //console.log(`${keyObj} -- Field: ${searchField} -- Search: ${search} -- Wallet: ${walletId}`);
      if(___default['default'].isNil(keyObj)) throw new Error('Key not found.')
      let key = await fs__default['default'].promises.readFile(this.pathGet(keyObj.key_id, path));
      keyObj.key_object = JSON.parse(key);
      return keyObj;
      //return { key_id: keyObj.key_id, public_key: keyObj.public_key, path: path || '' }
    }
    catch (error) { throw error; }
  }

  /**
   * Write a key to storage
   * @param  {Object}  keyData   The data the store. Likely in JSON.
   * @param  {Object} [opts={}]  Optional parameters
   * @param  {String}  [opts.keyId=UUID]       The key ID.
   * @param  {String}  [opts.publicKey=null]   48-Byte HEX public key
   * @param  {String}  [opts.path=null] Optional subpath.
   * @return {Boolean} True on Success.
   * @throws On failure.
   */
  async keyWrite(keyData, opts={}) {
    let defaults = { keyId: uuid.v4(), publicKey: null, path: null };
    opts = {...defaults, ...opts };
    if(await this.keyExists(opts.keyId, opts.path))
      throw new Error('Key ID already exists.');
    if(opts.publicKey !== null && await this.keyExists(opts.publicKey, opts.path))
      throw new Error('Public Key already exists.');

    try {
      await this.indexUpdate(opts.keyId, opts.publicKey, false, opts.path);
      await fs__default['default'].promises.writeFile( this.pathGet(opts.keyId, opts.path), JSON.stringify(keyData), { recursive: true } );
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Retrieve the next accound index.
   * @param  {String}  path An optional subpath where the index is stored.
   * @return {Integer}      The next sequential account index.
   */
  async indexAccountNext(path=null) {
    try {
      let indexData = await this.indexGet(path);
      if(WALLET[indexData.type] !== 'HD') throw new Error('Only HD wallets track account indexes.');
      else return (___default['default'].isNil(indexData.currentAccount)) ? 0 : indexData.currentAccount + 1;
    }
    catch(error) { throw error; }
  }

  /**
   * Creates a new index file.
   * @param  {String}  [path=null] Optional subpath to create the index.
   * @return {Object}              The Index data object.
   */
  async indexCreate(path=null, keyType=this.keyType) {
    try {
      let indexPath = this.pathGet('index', path);
      await fs__default['default'].promises.mkdir(this.pathGet(path), { recursive: true });
      const indexData = { type: keyType, key_list: [] };
      await fs__default['default'].promises.writeFile(indexPath, JSON.stringify(indexData));
      return indexData;
    }
    catch(error) { throw error; }
  }

  /**
   * Determines whether an index file already exists.
   * @param  {String}  path An optional subpath where the index is stored.
   * @return {Boolean}      True if it exists, false otherwise.
   */
  async indexExists(path=null) {
    try {
      await fs__default['default'].promises.access(this.pathGet('index', path));
      return true;
    }
    catch(error) { return false; }
  }

  async indexGet(path=null) {
    if(this.indexExists(path)) {
      let indexPath = this.pathGet('index', path);
      let buffer = await fs__default['default'].promises.readFile(indexPath);
      return JSON.parse(buffer.toString());
    }
    else throw new Error('Index does not exist.');
  }

  async indexType(path=null) {
    try {
      let indexData = await this.indexGet(path);
      return indexData.type;
    }
    catch(error) { throw error; }
  }

  async indexUpdate(keyId, publicKey=null, remove=false, path=null) {
    return this.indexQueue.add(() => this.indexUpdateAsync(keyId, publicKey, remove, path));
  }

  /**
   * Modifies a wallet index file. Either adds or removes a key. Creates new index if one doesn't exist.
   * @param  {String}  walletId         The wallet file to modify
   * @param  {String}  keyId            The key to modify
   * @param  {Boolean} [remove=false]   Whether to remove the key
   * @return {Boolean}                  True on sucess
   * @throws On failure
   */
  async indexUpdateAsync(keyId, publicKey=null, remove=false, path=null) {
    try {
      let indexExists = await this.indexExists(path);
      if(!indexExists) await this.indexCreate(path);
      let indexData = await this.indexGet(path);
      // check for existing keys
      let indexSearch = (publicKey === null) ? keyId : publicKey;
      let keyExists = await this.keyExists(indexSearch, path);
      let removed;
      if(remove == true && keyExists) removed = await ___default['default'].remove(indexData.key_list, function(o) {
        return (o.key_id == keyId || o.uuid == keyId);
      });
      else if( remove == false && !keyExists) {
        indexData.key_list.push({ key_id: keyId, public_key: publicKey });
        // Set the current account index for HD wallets.
        if(WALLET[indexData.type] === 'HD') indexData.currentAccount = indexData.key_list.length;
      }
      else if(remove == true && !keyExists) throw new Error(`Key not found: ${keyId}.`)
      else if(remove == false && keyExists) throw new Error(`Duplicate key found: ${publicKey}.`)
      await fs__default['default'].promises.writeFile(this.pathGet('index', path), JSON.stringify(indexData));
      return true;
    }
    catch(error) { throw error; }
  }

  async mnemonicCreate(mnemonic, path=null) {
    try {
      let mnemonicPath = this.pathGet('mnemonic', path);
      await fs__default['default'].promises.writeFile(mnemonicPath, JSON.stringify(mnemonic));
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Returns an encrypted mnemonic JSON object.
   * @param  {String}  [path=null] Subpath within the root wallet.
   * @return {Object|String}              The mnemonic object string
   */
  async mnemonicGet(path=null) {
    let key = await fs__default['default'].promises.readFile(this.pathGet('mnemonic', path));
    return JSON.parse(key);
  }

  /**
   * Backup a file path to ZIP
   * @param  {String}  path               The Subpath to backup within the root wallet.
   * @param  {String}  [destination=null] The destination to write the file to.
   * @return {String}                    Resolves on success, returns the save path.
   */
  async pathBackup(path, destination=null) {
    let walletExists = await this.indexExists(path);
    if(!walletExists) throw new Error('Wallet does not exist.');
    if(destination == null) destination = this.pathGet(`${path}.zip`);
    return new Promise((resolve, reject) => {
      // create a file to stream archive data to.
      const output = fs__default['default'].createWriteStream( destination );
      const archive = archiver__default['default']('zip', {
        zlib: { level: 9 } // Sets the compression level.
      });
      output.on("close", function() { resolve(destination); });
      archive.on("error", reject);
      archive.directory(`${this.pathGet(path)}/`, false);
      archive.pipe(output);
      archive.finalize();
    });
  }

  /**
   * Restore a path from file.
   * @param  {String}  source The source file absolute path.
   * @param  {String}  [wallet=null] Optional wallet name.
   * @return {Boolean}        Returns true on success.
   * @throws On Error.
   */
  async pathRestore(source, wallet=null) {
    try {
        let filename = source.replace(/^.*[\\\/]/, '').split('.')[0];
        await fs__default['default'].promises.access(source);
        let dir = ( wallet == null ) ? this.pathGet(filename) : this.pathGet(wallet);
        await extract__default['default'](source, { dir: dir });
        //console.log(`Wallet restored: ${filename}`);
        return true;
      }
      catch (err) {
        throw err;
      }
  }

  /**
   * Gets an absolute path for writing a file
   * @param  {String} filename       Filename to write
   * @param  {String} [subpath=null] Optional subpath
   * @return {String}                The absolute path for a target file.
   */
  pathGet(filename, subpath=null) {
    filename = (filename !== null) ? filename: '';
    return (subpath !== null) ? `${this.rootPath}/${subpath}/${filename}` : `${this.rootPath}/${filename}`;
  }

  /**
   * Deletes all keys/indexes in a path
   * @param  {String}  path The Path to delete
   * @return {Boolean}      True if successful
   * @throws On failure
   */
  async pathDelete(path) {
    try {
      await fs__default['default'].promises.rmdir(this.pathGet(path), { recursive: true });
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Return a list of available wallet IDs
   * @return {Array} A list of wallet IDs.
   * @throws On failure
   */
  async pathList(path=null) {
    try {
      // get all the files and directories
      let list = await fs__default['default'].promises.readdir(this.pathGet(null, path), { withFileTypes: true });
      // filter out files and hidden folders
      let dirList = list.filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name)
        .filter(item => !(/(^|\/)\.[^\/\.]/g).test(item));
      return dirList;
    }
    catch(error) { throw error; }
  }
}

/**
 * Returns a Key Object
 * @type {Function}
 * @param {String} algorithm The encryption algorithm used to protect the key.
 * @param {String} type The type of key [simple, eip2335].
 */
function getStore(rootPath, type=1) {
  switch(type) {
    default:
      return new Filesystem({ path: rootPath, keyType: type });
  }
}

var abi = [
	{
		inputs: [
		],
		stateMutability: "nonpayable",
		type: "constructor"
	},
	{
		anonymous: false,
		inputs: [
			{
				indexed: false,
				internalType: "bytes",
				name: "pubkey",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "withdrawal_credentials",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "amount",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "signature",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "index",
				type: "bytes"
			}
		],
		name: "DepositEvent",
		type: "event"
	},
	{
		inputs: [
			{
				internalType: "bytes",
				name: "pubkey",
				type: "bytes"
			},
			{
				internalType: "bytes",
				name: "withdrawal_credentials",
				type: "bytes"
			},
			{
				internalType: "bytes",
				name: "signature",
				type: "bytes"
			},
			{
				internalType: "bytes32",
				name: "deposit_data_root",
				type: "bytes32"
			}
		],
		name: "deposit",
		outputs: [
		],
		stateMutability: "payable",
		type: "function"
	},
	{
		inputs: [
		],
		name: "get_deposit_count",
		outputs: [
			{
				internalType: "bytes",
				name: "",
				type: "bytes"
			}
		],
		stateMutability: "view",
		type: "function"
	},
	{
		inputs: [
		],
		name: "get_deposit_root",
		outputs: [
			{
				internalType: "bytes32",
				name: "",
				type: "bytes32"
			}
		],
		stateMutability: "view",
		type: "function"
	},
	{
		inputs: [
			{
				internalType: "bytes4",
				name: "interfaceId",
				type: "bytes4"
			}
		],
		name: "supportsInterface",
		outputs: [
			{
				internalType: "bool",
				name: "",
				type: "bool"
			}
		],
		stateMutability: "pure",
		type: "function"
	}
];
var bytecode = "0x60806040523480156200001157600080fd5b50602180546001600160a01b0319163317905560005b601f8110156200011e576002602282602081106200004157fe5b0154602283602081106200005157fe5b015460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b60208310620000aa5780518252601f19909201916020918201910162000089565b51815160209384036101000a60001901801990921691161790526040519190930194509192505080830381855afa158015620000ea573d6000803e3d6000fd5b5050506040513d60208110156200010057600080fd5b5051602260018301602081106200011357fe5b015560010162000027565b5061194e806200012f6000396000f3fe60806040526004361061003f5760003560e01c806301ffc9a71461004457806322895118146100a4578063621fd130146101ba578063c5f2892f14610244575b600080fd5b34801561005057600080fd5b506100906004803603602081101561006757600080fd5b50357fffffffff000000000000000000000000000000000000000000000000000000001661026b565b604080519115158252519081900360200190f35b6101b8600480360360808110156100ba57600080fd5b8101906020810181356401000000008111156100d557600080fd5b8201836020820111156100e757600080fd5b8035906020019184600183028401116401000000008311171561010957600080fd5b91939092909160208101903564010000000081111561012757600080fd5b82018360208201111561013957600080fd5b8035906020019184600183028401116401000000008311171561015b57600080fd5b91939092909160208101903564010000000081111561017957600080fd5b82018360208201111561018b57600080fd5b803590602001918460018302840111640100000000831117156101ad57600080fd5b919350915035610304565b005b3480156101c657600080fd5b506101cf61112d565b6040805160208082528351818301528351919283929083019185019080838360005b838110156102095781810151838201526020016101f1565b50505050905090810190601f1680156102365780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561025057600080fd5b5061025961113f565b60408051918252519081900360200190f35b60007fffffffff0000000000000000000000000000000000000000000000000000000082167f01ffc9a70000000000000000000000000000000000000000000000000000000014806102fe57507fffffffff0000000000000000000000000000000000000000000000000000000082167f8564090700000000000000000000000000000000000000000000000000000000145b92915050565b6030861461035d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602681526020018061187d6026913960400191505060405180910390fd5b602084146103b6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260368152602001806118146036913960400191505060405180910390fd5b6060821461040f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260298152602001806118f06029913960400191505060405180910390fd5b670de0b6b3a7640000341015610470576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806118ca6026913960400191505060405180910390fd5b633b9aca003406156104cd576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252603381526020018061184a6033913960400191505060405180910390fd5b633b9aca00340467ffffffffffffffff811115610535576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260278152602001806118a36027913960400191505060405180910390fd5b606061054082611532565b90507f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c589898989858a8a610575602054611532565b6040805160a0808252810189905290819060208201908201606083016080840160c085018e8e80828437600083820152601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01690910187810386528c815260200190508c8c808284376000838201819052601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01690920188810386528c5181528c51602091820193918e019250908190849084905b83811015610648578181015183820152602001610630565b50505050905090810190601f1680156106755780820380516001836020036101000a031916815260200191505b5086810383528881526020018989808284376000838201819052601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169092018881038452895181528951602091820193918b019250908190849084905b838110156106ef5781810151838201526020016106d7565b50505050905090810190601f16801561071c5780820380516001836020036101000a031916815260200191505b509d505050505050505050505050505060405180910390a160215473ffffffffffffffffffffffffffffffffffffffff163314801561075f5750620186a0602054105b156107ac5760215460405173ffffffffffffffffffffffffffffffffffffffff909116903480156108fc02916000818181858888f193505050501580156107aa573d6000803e3d6000fd5b505b600060028a8a600060801b604051602001808484808284377fffffffffffffffffffffffffffffffff0000000000000000000000000000000090941691909301908152604080517ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0818403018152601090920190819052815191955093508392506020850191508083835b6020831061087457805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610837565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa1580156108d1573d6000803e3d6000fd5b5050506040513d60208110156108e657600080fd5b5051905060006002806108fc6040848a8c611776565b6040516020018083838082843780830192505050925050506040516020818303038152906040526040518082805190602001908083835b6020831061097057805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610933565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa1580156109cd573d6000803e3d6000fd5b5050506040513d60208110156109e257600080fd5b505160026109f3896040818d611776565b60405160009060200180848480828437919091019283525050604080518083038152602092830191829052805190945090925082918401908083835b60208310610a6c57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610a2f565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610ac9573d6000803e3d6000fd5b5050506040513d6020811015610ade57600080fd5b5051604080516020818101949094528082019290925280518083038201815260609092019081905281519192909182918401908083835b60208310610b5257805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610b15565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610baf573d6000803e3d6000fd5b5050506040513d6020811015610bc457600080fd5b50516040805160208101858152929350600092600292839287928f928f92018383808284378083019250505093505050506040516020818303038152906040526040518082805190602001908083835b60208310610c5157805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610c14565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610cae573d6000803e3d6000fd5b5050506040513d6020811015610cc357600080fd5b50516040518651600291889160009188916020918201918291908601908083835b60208310610d2157805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610ce4565b6001836020036101000a0380198251168184511680821785525050505050509050018367ffffffffffffffff191667ffffffffffffffff1916815260180182815260200193505050506040516020818303038152906040526040518082805190602001908083835b60208310610dc657805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610d89565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610e23573d6000803e3d6000fd5b5050506040513d6020811015610e3857600080fd5b5051604080516020818101949094528082019290925280518083038201815260609092019081905281519192909182918401908083835b60208310610eac57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610e6f565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610f09573d6000803e3d6000fd5b5050506040513d6020811015610f1e57600080fd5b50519050858114610f7a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260548152602001806117c06054913960600191505060405180910390fd5b60205463ffffffff11610fd8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602181526020018061179f6021913960400191505060405180910390fd5b602080546001019081905560005b602081101561112157816001166001141561101857826000826020811061100957fe5b01555061112495505050505050565b60026000826020811061102757fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b6020831061109d57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101611060565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa1580156110fa573d6000803e3d6000fd5b5050506040513d602081101561110f57600080fd5b50519250600282049150600101610fe6565b50fe5b50505050505050565b606061113a602054611532565b905090565b6020546000908190815b602081101561136857816001166001141561125e5760026000826020811061116d57fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b602083106111e357805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016111a6565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015611240573d6000803e3d6000fd5b5050506040513d602081101561125557600080fd5b5051925061135a565b6002836022836020811061126e57fe5b015460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b602083106112e357805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016112a6565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015611340573d6000803e3d6000fd5b5050506040513d602081101561135557600080fd5b505192505b600282049150600101611149565b50600282611377602054611532565b600060401b6040516020018084815260200183805190602001908083835b602083106113d257805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101611395565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790527fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000095909516920191825250604080518083037ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8018152601890920190819052815191955093508392850191508083835b602083106114b757805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0909201916020918201910161147a565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015611514573d6000803e3d6000fd5b5050506040513d602081101561152957600080fd5b50519250505090565b60408051600880825281830190925260609160208201818036833701905050905060c082901b8060071a60f81b8260008151811061156c57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060061a60f81b826001815181106115af57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060051a60f81b826002815181106115f257fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060041a60f81b8260038151811061163557fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060031a60f81b8260048151811061167857fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060021a60f81b826005815181106116bb57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060011a60f81b826006815181106116fe57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060001a60f81b8260078151811061174157fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535050919050565b60008085851115611785578182fd5b83861115611791578182fd5b505082019391909203915056fe4465706f736974436f6e74726163743a206d65726b6c6520747265652066756c6c4465706f736974436f6e74726163743a207265636f6e7374727563746564204465706f7369744461746120646f6573206e6f74206d6174636820737570706c696564206465706f7369745f646174615f726f6f744465706f736974436f6e74726163743a20696e76616c6964207769746864726177616c5f63726564656e7469616c73206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c7565206e6f74206d756c7469706c65206f6620677765694465706f736974436f6e74726163743a20696e76616c6964207075626b6579206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f20686967684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f206c6f774465706f736974436f6e74726163743a20696e76616c6964207369676e6174757265206c656e677468a26469706673582212207dbf3f4ee522272de1ffb81cc3d2f0ec22b207751cb3b79bf5abebb9050c061164736f6c634300060b0033";
var DEPOSIT_CONTRACT = {
	abi: abi,
	bytecode: bytecode
};

/**
 * @module Wallet
 */
const bip39 = require('bip39');

const init = bls__default['default'].init(bls__default['default'].BLS12_381);
const HOMEDIR$1 = require('os').homedir();
const VERSION$3 = 1;
const BLS_WITHDRAWAL_PREFIX = Buffer.from('00', 'hex');
const DEPOSIT_AMOUNT = BigInt(32000000000);

/**
 * An implementation of ETH2 Wallet
 * @type {Object}
 */
class Wallet {
  constructor(opts={}) {
    let defaults = {
      wallet_path: `${HOMEDIR$1}/.eth2-wallet-js/wallet`,
      algorithm: 'aes-256-cbc',
      fork_version: 'pyrmont',
      key: null,
      store: null
    };
    opts = { ...defaults, ...opts };
    this.version = VERSION$3;
    this.algorithm = opts.algorithm;
    this.forkVersion = FORKS[opts.fork_version];
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
    let hasOpt = fields.some(f => ___default['default'].has(withdrawalOpts, f));
    if(!hasOpt) throw new Error(`Options must include One of: ${fields.toString()}`);
    let defaults = { withdrawal_key_id: keyId, withdrawal_key_wallet: walletId, withdrawal_public_key: null, amount: DEPOSIT_AMOUNT, raw: true };
    let opts = {...defaults, ...withdrawalOpts };
    try {
      let validatorKey = await this.store.keySearch(keyId, walletId);
      let validatorPubKey = validatorKey.public_key;
      let withdrawPubKey;
      if(PUBLIC_KEY.test(opts.withdrawal_public_key)) withdrawPubKey = opts.withdrawal_public_key;
      else {
        let withdrawKey = await this.store.keySearch(opts.withdrawal_key_id, opts.withdrawal_key_wallet);
        withdrawPubKey = withdrawKey.public_key;
      }

      //deposit data with empty signature to sign
      const withdrawalPubKeyHash = crypto__default['default'].createHash('sha256').update(Buffer.from(withdrawPubKey, 'hex')).digest();
      const depositData = {
          pubkey: Buffer.from(validatorPubKey, 'hex'),
          withdrawalCredentials: Buffer.concat([ BLS_WITHDRAWAL_PREFIX, withdrawalPubKeyHash.slice(1) ]),
          amount: opts.amount,
          signature: Buffer.alloc(96),
      };
      // forkVersion Override
      let forkChoice = this.forkVersion;
      if(forkVersion !== null) {
        if(!FORKS.hasOwnProperty(forkVersion)) throw new Error(`Fork choice must be one of ${Object.keys(FORKS).toString()}`);
        else forkChoice = FORKS[forkVersion];
      }
      let signingRoot = getSigningRoot(depositData, forkChoice);
      depositData.signature = await this.sign(signingRoot.toString('hex'), walletId, validatorPubKey, password);
      let depositDataRoot = getDepositDataRoot(depositData);
      if(opts.raw == true) {
        let contract = new ethers.ethers.utils.Interface(DEPOSIT_CONTRACT.abi);
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
   * @param  {String} [opts.keyId=UUID] The name of the key to create.
   * @param  {String} [opts.walletPassword=null] Wallet password for HD wallets.
   * @return {Object} An object containing the wallet_id, key_id and public_key.
   * @throws On failure
   */
  async keyCreate(walletId, password, opts={}) {
    try {
      let defaults = { keyId: uuid.v4(), walletPassword: null, path:'' };
      opts = { ...defaults, ...opts };
      const walletType = await this.store.indexType(walletId);
      let privateKeyHex;

      if(WALLET[walletType] === 'HD') {
        if(___default['default'].isEmpty(opts.walletPassword)) throw new Error('HD wallets require a password to unlock.')
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
    const sec = new bls__default['default'].SecretKey();
    sec.setByCSPRNG();
    const pub = sec.getPublicKey();
    return bls__default['default'].toHexStr(sec.serialize());
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
      if(WALLET[walletType] === 'HD') throw new Error('Cannot delete keys from HD wallets.');

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
      if(WALLET[walletType] === 'HD' && opts.hdOverride !== true) throw new Error('Cannot import keys into HD wallets.');

      let defaults = { keyId: uuid.v4(), path: ''};
      opts = { ...defaults, ...opts };
      const sec = bls__default['default'].deserializeHexStrToSecretKey(privateKey);
      const pub = sec.getPublicKey();
      const pubKeyHex = bls__default['default'].toHexStr(pub.serialize());
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
      const sec = bls__default['default'].deserializeHexStrToSecretKey(secHex);
      const pub = sec.getPublicKey();
      const msg = bls__default['default'].fromHexStr(message);
      const sig = sec.sign(msg);
      let serialized = sig.serialize();
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
    let defaults = { wallet_id: uuid.v4(), type: 1 };
    opts = { ...defaults, ...opts };
    let walletExists = await this.store.indexExists(opts.wallet_id);
    if(walletExists) throw new Error('Wallet already exists');
    if(!WALLET.hasOwnProperty(opts.type)) throw new Error(`Wallet type '${opts.type}' not supported`);
    // HD wallet validation
    if(opts.type == 2) {
      if(___default['default'].isEmpty(opts.password)) throw new Error('Password required for HD wallets');
      if(!___default['default'].isEmpty(opts.mnemonic) && opts.mnemonic.trim().split(/\s+/g).length < 24) throw new Error('Mnemonic must be at least 24 words long.')
    }
    try {
      await this.store.indexCreate(opts.wallet_id, opts.type);
      // Handle Mnemonic storage
      if(opts.type == 2) {
        let mnemonic = (___default['default'].isEmpty(opts.mnemonic)) ? await bip39.generateMnemonic(256) : opts.mnemonic;
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
      if(WALLET[walletType] === 'Simple') throw new Error('Only HD wallets have mnemonics');

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

exports.Wallet = Wallet;
