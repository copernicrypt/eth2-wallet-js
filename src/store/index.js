import { Filesystem } from './filesystem';
/**
 * Returns a Key Object
 * @type {Function}
 * @param {String} algorithm The encryption algorithm used to protect the key.
 * @param {String} type The type of key [simple, eip2335].
 */
export function getStore(rootPath, type=1) {
  switch(type) {
    default:
      return new Filesystem({ path: rootPath, keyType: type });
  }
}
