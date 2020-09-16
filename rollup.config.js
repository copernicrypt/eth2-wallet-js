import json from '@rollup/plugin-json';
//import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/wallet.js',
  output: {
    file: 'bundle.js',
    format: 'cjs'
  },
  plugins: [ json(), commonjs() ]
};
