/**
 * Key Generation implementation of EIP-2333
 * @see https://eips.ethereum.org/EIPS/eip-2333
 * @type {Class}
 */
import { bigIntToBuffer } from '../helpers';
const sha256 = require('bcrypto/lib/sha256');
const hkdf = require('bcrypto/lib/hkdf');
const VERSION = 4;

export class Eip2333 {

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
    const compressedLamportPk = Eip2333.parentSkToLamportPk(parentSk, index)
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
