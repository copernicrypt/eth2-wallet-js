import crypto from 'crypto';
import  { v4 as uuidv4 } from 'uuid';

const VERSION = 1;
const SUPPORTED_ALGOS = ['aes-256-cbc', 'aes-256-ctr', 'aes-192-cbc', 'aes-192-ctr', 'aes-128-cbc', 'aes-128-ctr'];

export class SimpleJson {
  constructor(algorithm='aes-256-cbc', version=VERSION) {
    this.algorithm = algorithm;
    this.version = version;
    if(!SUPPORTED_ALGOS.includes(algorithm)) throw new Error(`Encryption algorithm not supported. Try ${SUPPORTED_ALGOS.toString()}`);
    if(algorithm.substr(0, 7) === 'aes-128') this.keyLength = 16;
    else if(algorithm.substr(0, 7) === 'aes-192') this.keyLength = 24;
    else if(algorithm.substr(0, 7) === 'aes-256') this.keyLength = 32;
  }

  async encrypt(privateKey, password, publicKey, opts={}) {
    let defaults = { path: "", uuid: uuidv4() }
    opts = {...defaults, ...opts };
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest();

    let cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(privateKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { algorithm: this.algorithm, iv: iv.toString('hex'), data: encrypted.toString('hex'), public_key: publicKey, uuid: opts.uuid, path: opts.path };
  }

  async decrypt(jsonKey, password) {
    let iv = Buffer.from(jsonKey.iv, 'hex');
    const key = crypto.createHash('sha256').update(password).digest();

    let encryptedText = Buffer.from(jsonKey.data, 'hex');
    let decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
}
