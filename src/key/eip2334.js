import { Eip2333 } from './eip2333';
import bls from 'bls-eth-wasm';
const TYPES = { ETH1: 60, ETH2:3600 };

/**
 * Converts a derivation path to an array of indices based on the EIP334 specification. For use with EIP2333 key derivation.
 * @see https://eips.ethereum.org/EIPS/eip-2334
 * @param {String}  path The derivation path. ( m / purpose / coin_type /  account / use )
 * @param {Integer} [coinType='ETH2'] The type of coin to validate.
 * @throws When path is invalid.
 */
export function pathToIndexList(path, coinType='ETH2') {
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
export function deriveKey(seed, path) {
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
