import { Eip2335 } from './eip2335';
import { SimpleJson } from './simpleJson';

export function getKeystore(algorithm, type) {
  switch(type) {
    case 'simple':
      return new SimpleJson(algorithm);
    default:
      return new Eip2335(algorithm);
  }
}