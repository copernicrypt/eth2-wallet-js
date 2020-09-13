# eth2-wallet-js
NodeJS implementation of an Ethereum 2 Wallet keystore.

**\*\*UNDER ACTIVE DEVELOPMENT, NOT FOR PRODUCTION USE\*\***

-   [Dependencies](#dependencies)
-   [Install](#install)
-   [Test](#test)
-   [Basic NodeJS Usage](#basic-nodejs-usage)
-   [Instance Options](#instance-options)
-   [CLI Usage](#cli-usage)
-   [Functions](#functions)
-   [Notes/Limitations](#noteslimitations)
-   [Roadmap](#roadmap)
-   [Thanks](#thanks)

## Dependencies
-   [Nodejs](https://nodejs.org/en/download/) >= 12.0.0

## Install

### NodeJS Module
```shell
yarn add https://github.com/copernicrypt/eth2-wallet-js
yarn install
```

### CLI
```shell
git clone https://github.com/copernicrypt/eth2-wallet-js
yarn install
```

## Test

```shell
yarn test
```

## Basic NodeJS Usage
```javascript
import { Keystore } from 'eth2-wallet-js';

let ks = new Keystore();
let wallet = Keystore.walletCreate();
let key = Keystore.keyCreate(wallet, 'mypassword');
```

## Instance Options
```javascript
import { Keystore } from 'eth2-wallet-js';

let opts = {
  algorithm: 'aes-256-cbc',
  wallet_path: '~/.eth2-wallet-js/wallet',
  fork_version: Buffer.from('00000001','hex')
}

let ks = new Keystore(opts);
```

## CLI Usage
The CLI can be invoked using yarn or npm:

```shell
yarn run cli <command> [...args]
```

-   \<parameters\> are required.
-   \[options\] are optional.

### depositData \<wallet\> \<password\> \<key\> \[withdrawalwallet=\<wallet\>\] \[withdrawalkey=\<key\>\] \[withdrawalpublickey=null\] \[amount=32000000000\] \[raw=false\]
Generates deposit data for submitting to the deposit contract.  

```shell
$ yarn run cli depositData --wallet=primary --password=testpassword --key=testaccountId --withdrawalpublickey=b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9
{
  pubkey: 'b88f5ff7e293d26d24a2655a8c72c8b92d495393548f7b86a31c2fe0923fd1ba292f31c11bb740e8acd7f599fb2ae06d',
  withdrawal_credentials: '00756e0bd4defe8a84f4303f6004e7f1b6978ddbe7fc7d22e2b0bd5f1c895e4c',
  signature: '92543970b5d2ab17666c9db957252d3a46ebf47782dfd8c53fc74d3cdce99883f35468d07d48094cfb8c986569e54f4619cdc64242e3c478a3899e4264a8d6d6a872311523c60f39b788d0398da77322dd2b8922e6f7b7ce4a8696b625bb59a3',
  amount: '32000000000',
  deposit_data_root: 'ea0c696c122426c32e5d6abe3caa4334cdc22fb08caa2601a6737e842fa73554'
}

```

```shell
$ yarn run cli depositData --wallet=primary --password=testpassword --key=testaccountId --withdrawalpublickey=b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9 --raw
0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120ea0c696c122426c32e5d6abe3caa4334cdc22fb08caa2601a6737e842fa735540000000000000000000000000000000000000000000000000000000000000030b88f5ff7e293d26d24a2655a8c72c8b92d495393548f7b86a31c2fe0923fd1ba292f31c11bb740e8acd7f599fb2ae06d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000756e0bd4defe8a84f4303f6004e7f1b6978ddbe7fc7d22e2b0bd5f1c895e4c000000000000000000000000000000000000000000000000000000000000006092543970b5d2ab17666c9db957252d3a46ebf47782dfd8c53fc74d3cdce99883f35468d07d48094cfb8c986569e54f4619cdc64242e3c478a3899e4264a8d6d6a872311523c60f39b788d0398da77322dd2b8922e6f7b7ce4a8696b625bb59a3
```

### keyCreate \<wallet\> \<password\> \[key\]
Imports a private key into a wallet.

```shell
$ yarn run cli keyImport --wallet=primary --password=testpassword --key=testaccountID
{
  wallet_id: "primary",
  public_key: "b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9",
  key_id: "testaccoundID"
}
```

### keyDelete \<wallet\> \<key\> \<password\>
Deletes a key from a wallet.

```shell
$ yarn run cli keyDelete --wallet=primary --key=testaccountID --password=testpassword
Key Deleted: testaccountID ---- Wallet: primary
```

### keyImport \<wallet\> \<privatekey\> \<password\> \[key\]
Imports a private key into a wallet.

```shell
$ yarn run cli keyImport --wallet=primary --privatekey=1e16b2c1947fd9fd4045a88177313db10198ed6abd1b0f165d49cd13a72546e2 --password=testpassword --key=testaccountID
{
  wallet_id: "primary",
  public_key: "b6de3f6dd56a863f69bca81af4dc9877d04a81df361bbe555d6944b9d84fce18fdfb939d9ef3c312ead638b759b207c9",
  key_id: "testaccoundID"
}
```

### keyPrivate \<wallet\> \<key\> \<password\>
Returns a private key HEX.

```shell
$ yarn run cli keyPrivate --wallet=primary --key=testaccountID --password=testpassword
1e16b2c1947fd9fd4045a88177313db10198ed6abd1b0f165d49cd13a72546e2
```

### keySearch \<wallet\> \<search\>
Finds a key by search term. Accepts key ID, public key, or private key.

```shell
$ yarn run cli keySearch --wallet=primary --search=testaccountID
{
  wallet_id: "primary",
  public_key: "HEX",
  key_id: "testaccoundID"
}
```

### sign \<message\> \<wallet\> \<search\> \<password\>
Signs a generic message with a key.

```shell
$ yarn run cli sign --message=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --wallet=primary --search=key1 --password=test
```

### walletCreate \[wallet=UUID\]\[type=1\]
Creates a new wallet.

Available Types: `1` (Random) or `2` (HD)

```shell
$ yarn run cli walletCreate --wallet=test
Created wallet: test
```


### walletDelete \<wallet\>
Deletes a wallet.

```shell
$ yarn run cli walletDelete --wallet=test
Deleted wallet: test
```

### walletList
Lists all available wallets

```shell
$ yarn run cli walletList
[
  'test',
  'test2'
]
```

### walletListKeys \<wallet\>
Lists all keys for a given wallet.

```shell
$ yarn run cli walletListKeys --wallet=test
[
  'test',
  'test2'
]
```

## Functions

<dl>
<dt><a href="#init">init()</a> ⇒ <code>Null</code></dt>
<dd><p>This just awaits the initialization of the BLS package.</p>
</dd>
<dt><a href="#keyCreateAsync">keyCreateAsync(wallet_id, password, keyId)</a> ⇒ <code>Object</code></dt>
<dd><p>Creates a new ETH2 keypair.</p>
</dd>
<dt><a href="#keyDelete">keyDelete(walletId, keyId, password)</a> ⇒ <code>Boolean</code></dt>
<dd><p>Removes a key from a wallet.</p>
</dd>
<dt><a href="#keyExists">keyExists(walletId, keyId)</a> ⇒ <code>Boolean</code></dt>
<dd><p>Check whether a key already exists.</p>
</dd>
<dt><a href="#keyImportAsync">keyImportAsync(walletId, privateKey, password, keyId)</a> ⇒ <code>Object</code></dt>
<dd><p>Import a private key into the keystore</p>
</dd>
<dt><a href="#keyPrivate">keyPrivate(walletId, keyId, password)</a> ⇒ <code>String</code></dt>
<dd><p>Get a private key</p>
</dd>
<dt><a href="#keySearch">keySearch(search, walletId)</a> ⇒ <code>Object</code></dt>
<dd><p>Finds key information.</p>
</dd>
<dt><a href="#sign">sign(message, walletId, search, password)</a> ⇒ <code>Array</code></dt>
<dd><p>Signs a generic message with a private key.</p>
</dd>
<dt><a href="#walletCreate">walletCreate([opts])</a> ⇒ <code>String</code></dt>
<dd><p>Creates a new wallet to store keys.</p>
</dd>
<dt><a href="#walletDelete">walletDelete(id)</a> ⇒ <code>Boolean</code></dt>
<dd><p>Delete a wallet</p>
</dd>
<dt><a href="#walletList">walletList()</a> ⇒ <code>Array</code></dt>
<dd><p>Return a list of available wallet IDs</p>
</dd>
<dt><a href="#walletListKeys">walletListKeys(id)</a> ⇒ <code>Array</code></dt>
<dd><p>List of available keys in a wallet.</p>
</dd>
<dt><a href="#walletIndexKey">walletIndexKey(walletId, keyId, [publicKey], [remove])</a> ⇒ <code>Boolean</code></dt>
<dd><p>Modifies a wallet index file. Either adds or removes a key.</p>
</dd>
</dl>

<a name="init"></a>

### init() ⇒ <code>Null</code>
This just awaits the initialization of the BLS package.


<a name="keyCreateAsync"></a>

### keyCreateAsync(wallet_id, password, keyId) ⇒ <code>Object</code>
Creates a new ETH2 keypair.

**Returns**: <code>Object</code> - An object containing the wallet_id, key_id and public_key.  
**Throws**: On failure


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| wallet_id | <code>String</code> |  | The name of the wallet to create an key in. |
| password | <code>String</code> |  | The password to protect the key. |
| keyId | <code>String</code> | <code>UUID</code> | The name of the key to create. |

<a name="keyDelete"></a>

### keyDelete(walletId, keyId, password) ⇒ <code>Boolean</code>
Removes a key from a wallet.

**Returns**: <code>Boolean</code> - True on successful deletion.  
**Throws**: On failure


| Param | Type | Description |
| --- | --- | --- |
| walletId | <code>String</code> | The wallet ID. |
| keyId | <code>String</code> | The Key ID. |
| password | <code>String</code> | The password protecting the key. |

<a name="keyExists"></a>

### keyExists(walletId, keyId) ⇒ <code>Boolean</code>
Check whether a key already exists.

**Returns**: <code>Boolean</code> - Whether or not the key ID already exists in the wallet.  
**Throws**: On failure


| Param | Type | Description |
| --- | --- | --- |
| walletId | <code>String</code> | The wallet ID. |
| keyId | <code>String</code> | The Key ID. |

<a name="keyImportAsync"></a>

### keyImportAsync(walletId, privateKey, password, keyId) ⇒ <code>Object</code>
Import a private key into the keystore

**Returns**: <code>Object</code> - An object containing the walletId <string> key ID <UUID> and public key <48-byte HEX>  
**Throws**: On failure


| Param | Type | Description |
| --- | --- | --- |
| walletId | <code>String</code> | The wallet to import into. |
| privateKey | <code>String</code> | A 32byte HEX-format private key |
| password | <code>String</code> | A password to protect the key. |
| keyId | <code>String</code> | The ID reference for the key. |

<a name="keyPrivate"></a>

### keyPrivate(walletId, keyId, password) ⇒ <code>String</code>
Get a private key

**Returns**: <code>String</code> - The 64-byte HEX formatted private key.  
**Throws**: On failure


| Param | Type | Description |
| --- | --- | --- |
| walletId | <code>String</code> | The wallet ID. |
| keyId | <code>String</code> | The Key ID. |
| password | <code>String</code> | The password protecting the key. |

<a name="keySearch"></a>

### keySearch(search, walletId) ⇒ <code>Object</code>
Finds key information.

**Returns**: <code>Object</code> - Object containing key_id and public_key.  
**Throws**: On failure


| Param | Type | Description |
| --- | --- | --- |
| search | <code>String</code> | Either an key ID or public key. |
| walletId | <code>String</code> | The wallet ID to search for keys. |

<a name="sign"></a>

### sign(message, walletId, search, password) ⇒ <code>Array</code>
Signs a generic message with a private key.

**Returns**: <code>Array</code> - The 96-byte BLS signature.  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>String</code> | The message to sign (32-Byte HEX) |
| walletId | <code>String</code> | Wallet ID where the key is stored. |
| search | <code>String</code> | The key to search for. Accepts keyID, publicKey, and privateKey. |
| password | <code>String</code> | Password protecting the signing key. |

<a name="walletCreate"></a>

### walletCreate([opts]) ⇒ <code>String</code>
Creates a new wallet to store keys.

**Returns**: <code>String</code> - The wallet identifier.  
**Throws**: On failure


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [opts] | <code>Object</code> | <code>{}</code> | Optional parameters. |
| [opts.wallet_id] | <code>String</code> | <code>uuidv4</code> | Wallet identifer. If not provided, will be random. |
| [opts.type] | <code>String</code> | <code>1</code> | The type of wallet to create. 1=Simple, 2=Hierarchical deterministic. |
| [opts.password] | <code>String</code> | <code></code> | Password for HD wallets. |
| [opts.mnemonic] | <code>String</code> | <code></code> | BIP39 mnemonic for HD wallets. |

<a name="walletDelete"></a>

### walletDelete(id) ⇒ <code>Boolean</code>
Delete a wallet

**Returns**: <code>Boolean</code> - True if the delete was successful.  
**Throws**: On failure

| Param | Type | Description |
| --- | --- | --- |
| id | <code>String</code> | The wallet identifier |

<a name="walletList"></a>

### walletList() ⇒ <code>Array</code>
Return a list of available wallet IDs

**Returns**: <code>Array</code> - A list of wallet IDs.  
**Throws**: On failure

<a name="walletListKeys"></a>

### walletListKeys(id) ⇒ <code>Array</code>
List of available keys in a wallet.

**Returns**: <code>Array</code> - An array of key objects.  

| Param | Type | Description |
| --- | --- | --- |
| id | <code>String</code> | The wallet ID to search |

<a name="walletIndexKey"></a>

### walletIndexKey(walletId, keyId, [publicKey], [remove]) ⇒ <code>Boolean</code>
Modifies a wallet index file. Either adds or removes a key.

**Returns**: <code>Boolean</code> - True on sucess  
**Throws**: On failure


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| walletId | <code>String</code> |  | The wallet file to modify |
| keyId | <code>String</code> |  | The key to modify |
| [publicKey] | <code>String</code> | <code></code> | 48-Byte HEX public key |
| [remove] | <code>Boolean</code> | <code>false</code> | Whether to remove the key |

## Notes/Limitations
-   No HD wallet support (yet)
-   All core functions return promises.

## Roadmap
-   Add support for BIP-39 HD wallets
-   Add support for password files
-   Add Import/Export function
-   Implement [EIP-2335](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md)

## Thanks
Would not be possible without the work being done by [@chainsafe](https://github.com/ChainSafe/) and [@herumi](https://github.com/herumi/)
