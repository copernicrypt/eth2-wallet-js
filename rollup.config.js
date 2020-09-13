import json from '@rollup/plugin-json';

export default {
  input: 'src/keystore.js',
  output: {
    file: 'bundle.js',
    format: 'cjs'
  },
  plugins: [ json() ]
};
