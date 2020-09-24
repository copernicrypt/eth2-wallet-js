import { Eip2335 } from './eip2335';
import { SimpleJson } from './simpleJson';
/**
 * Returns a Key Object
 * @type {Function}
 * @param {String} algorithm The encryption algorithm used to protect the key.
 * @param {String} type The type of key [simple, eip2335].
 */
export function getKey(algorithm, type) {
  switch(type) {
    case 'simple':
      return new SimpleJson(algorithm);
    default:
      return new Eip2335(algorithm);
  }
}
