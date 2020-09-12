# eth2-wallet-js
NodeJS implementation of an Ethereum 2 Wallet keystore.

## Install
```shell
git clone https://github.com/copernicrypt/eth2-wallet-js
yarn install
```

## Test

```shell
yarn test
```

## Basic Usage
```javascript
import Keystore from 'eth2-wallet-js';

let wallet = Keystore.walletCreate();
let key = Keystore.keyCreate(wallet, 'mypassword');

```

## Commands
The CLI can be invoked using yarn or npm:
```shell
yarn run cli <command> [...args]
```

### walletCreate

### walletDelete

### walletList

### walletListKeys
