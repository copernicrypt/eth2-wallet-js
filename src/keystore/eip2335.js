/**
 * Keystore implementation of EIP-2335
 * @see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md
 * @type {Class}
 */
import crypto from 'crypto';
import util from 'util';
import  { v4 as uuidv4 } from 'uuid';

const pbkdf2 = util.promisify(crypto.pbkdf2);

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
    let defaults = { path: "", uuid: uuidv4(), description: 'eth2-wallet-js key' }
    opts = {...defaults, ...opts };
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(32).toString('hex');
    const key = await this.getDecryptionKey(password, salt);
    let decryptionKey = Buffer.from(key,'hex');

    let cipher = crypto.createCipheriv(this.algorithm, decryptionKey.slice(0, this.keyLength), iv);
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
      "uuid": opts.uuid,
      "version": this.version,
    }
  }

  async decrypt(jsonKey, password) {
    let ivBuf = Buffer.from(jsonKey.crypto.cipher.params.iv, 'hex');
    let key = await this.getDecryptionKey(password, jsonKey.crypto.kdf.params.salt, jsonKey.crypto.kdf.params.c, jsonKey.crypto.kdf.params.dklen);
    let decryptionKey = Buffer.from(key,'hex');

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
    let filtered = password.replace(/[\x00-\x1F\x7F-\x9F]/g, "");;
    return filtered;
  }
}

module.exports = {
  Eip2335
}
