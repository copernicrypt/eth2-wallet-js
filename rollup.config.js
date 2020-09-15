import json from '@rollup/plugin-json';

export default {
  input: 'src/wallet.js',
  output: {
    file: 'bundle.js',
    format: 'cjs'
  },
  plugins: [ json() ]
};
