/**
 * Keystore implementation of EIP-2335
 * @see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md
 * @type {Class}
 */
import crypto from 'crypto';
import util from 'util';
import  { v4 as uuidv4 } from 'uuid';
import * as types from '../types';

const pbkdf2 = util.promisify(crypto.pbkdf2);
const scrypt = util.promisify(crypto.scrypt);

const VERSION = 4;
const SUPPORTED_ALGOS = ['aes-256-cbc', 'aes-256-ctr', 'aes-192-cbc', 'aes-192-ctr', 'aes-128-cbc', 'aes-128-ctr'];
const COST = 262144;
const DECRYPTION_KEY_TYPE = ['pbkdf2', 'scrypt'];
const DECRYPTION_KEY_LENGTH = 32;

export class Eip2335 {

  constructor(algorithm='aes-256-cbc', version=VERSION) {
    this.algorithm = algorithm;
    this.version = version;
    if(!SUPPORTED_ALGOS.includes(algorithm)) throw new Error(`Encryption algorithm not supported. Try ${SUPPORTED_ALGOS.toString()}`);
    if(algorithm.substr(0, 7) === 'aes-128') this.keyLength = 16;
    else if(algorithm.substr(0, 7) === 'aes-192') this.keyLength = 24;
    else if(algorithm.substr(0, 7) === 'aes-256') this.keyLength = 32;
  }

  async encrypt(privateKey, password, publicKey, opts={}) {
    let defaults = {
      path: "",
      keyId: uuidv4(),
      description: 'eth2-wallet-js key',
      kdf: 'pbkdf2',
      dklen: DECRYPTION_KEY_LENGTH,
      c: COST,
      n: COST,
      prf: 'sha256',
      r: 8,
      p: 1
    }
    opts = {...defaults, ...opts };
    if(!DECRYPTION_KEY_TYPE.includes(opts.kdf)) throw new Error(`Key type must be one of ${DECRYPTION_KEY_TYPE}`);

    // key_id needs to be a valid UUID for use in this spec. If it isn't create a new one.
    if(!types.UUID.test(opts.keyId)) delete opts.keyId;

    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(32).toString('hex');
    const key = await this.getDecryptionKey(opts.kdf, password, salt, opts);
    let decryptionKey = Buffer.from(key,'hex');

    let cipher = crypto.createCipheriv(this.algorithm, decryptionKey.slice(0, this.keyLength), iv);
    let encrypted = cipher.update(Buffer.from(privateKey, 'hex'));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    let encryptedHex = encrypted.toString('hex');
    let checksum = this.getChecksum(key, encryptedHex);

    let kdfParams = { dklen: opts.dklen, salt: salt }
    if(opts.kdf === 'pbkdf2') kdfParams = { ...kdfParams, ...{ c: opts.c, prf: opts.prf } };
    else kdfParams = { ...kdfParams, ...{ n: opts.n, r: opts.r, p: opts.p } };

    return {
      crypto: {
        kdf: { function: opts.kdf, params: kdfParams, message: '' },
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
    let key = await this.getDecryptionKey(jsonKey.crypto.kdf.function, password, jsonKey.crypto.kdf.params.salt, jsonKey.crypto.kdf.params);
    let decryptionKey = Buffer.from(key,'hex');
    if(!this.verifyPassword(decryptionKey, jsonKey.crypto.cipher.message, jsonKey.crypto.checksum.message)) throw new Error('Invalid Password');

    let encryptedText = Buffer.from(jsonKey.crypto.cipher.message, 'hex');
    let decipher = crypto.createDecipheriv(this.algorithm, decryptionKey.slice(0, this.keyLength), ivBuf);
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
      let checksum = crypto.createHash('sha256').update(preImage).digest();
      return checksum.toString('hex');
    }
    catch(error) { throw error; }
  }

  /**
   * Gets a decryption key from store details
   * @param  {String}  type     Either 'pbkdf2' or 'scrypt'.
   * @param  {String}  password The UTF8-encoded password.
   * @param  {String}  salt     32-Byte HEX salt
   * @param  {Integer} [opts.dklen] The Key length.
   * @param  {Integer} [opts.prf] Digest for pbkdf2
   * @param  {Integer} [opts.c] Iterations (PBKDF2)
   * @param  {Integer} [opts.n] CPU/Memory Cost (Scrypt) / Iterations (PBKDF2)
   * @param  {Integer} [opts.r] Block size for scrypt.
   * @param  {Integer} [opts.p] Parallelization for scrypt.
   * @return {String}           64-Byte HEX decryption key
   * @throws On failure.
   */
  async getDecryptionKey(type, password, salt, opts={}) {
    try {
      let defaults = { dklen: DECRYPTION_KEY_LENGTH, c: COST, n: COST, prf: 'sha256', r: 8, p: 1 }
      opts = { ...defaults, ...opts }
      password = await this.passwordFilter(password);
      opts.prf = opts.prf.replace(/hmac-/g, "");

      let derivedKey;
      if(type === 'pbkdf2') derivedKey = await pbkdf2(Buffer.from(password, 'utf8'), Buffer.from(salt, 'hex'), opts.c, opts.dklen, opts.prf);
      else derivedKey = await scrypt(Buffer.from(password, 'utf8'), Buffer.from(salt, 'hex'), opts.dklen, { cost: opts.n, r: opts.r, p: opts.p, maxmem: (512 * 1024 * 1024) });
      return derivedKey.toString('hex');
    }
    catch(error) { throw error; }
  }

  async passwordFilter(password) {
    let filtered = password.replace(/[\x00-\x1F\x7F-\x9F]/g, "");;
    return filtered;
  }
}
