'use strict';

var _ = require('lodash');
var crypto = require('crypto');
var fs = require('fs');
var bls = require('bls-eth-wasm');
var ethers = require('ethers');
var uuid = require('uuid');
var PQueue = require('p-queue');
var bigintBuffer = require('bigint-buffer');
var mainnet = require('@chainsafe/lodestar-types/lib/ssz/presets/mainnet');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var ___default = /*#__PURE__*/_interopDefaultLegacy(_);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
var bls__default = /*#__PURE__*/_interopDefaultLegacy(bls);
var PQueue__default = /*#__PURE__*/_interopDefaultLegacy(PQueue);

const PUBLIC_KEY = new RegExp("^(0x)?[0-9a-f]{96}$");
const PRIVATE_KEY = new RegExp("^(0x)?[0-9a-f]{64}$");

/**
 * @module constants
 */
const ZERO_HASH = Buffer.alloc(32, 0);
const EMPTY_SIGNATURE = Buffer.alloc(96, 0);

// Domain Types
const DomainType = {
  BEACON_PROPOSER: 0,
  BEACON_ATTESTER: 1,
  RANDAO: 2,
  DEPOSIT: 3,
  VOLUNTARY_EXIT: 4,
  SELECTION_PROOF: 5,
  AGGREGATE_AND_PROOF: 6,
};

function getSigningRoot(depositData, forkVersion) {
  const domainWrappedObject = {
      objectRoot: mainnet.types.DepositMessage.hashTreeRoot(depositData),
      domain: getDomain(forkVersion),
  };
  return mainnet.types.SigningData.hashTreeRoot(domainWrappedObject);
}

function getDomain(forkVersion, domainType=DomainType.DEPOSIT, genesisValidatorRoot=ZERO_HASH) {
  const forkDataRoot = getForkDataRoot(forkVersion, genesisValidatorRoot);
  return Buffer.concat([intToBytes(BigInt(domainType), 4), Uint8Array.from(forkDataRoot).slice(0, 28)]);
}

function getDepositDataRoot(depositData) {
  return mainnet.types.DepositData.hashTreeRoot(depositData);
}

function getForkDataRoot(currentVersion, genesisValidatorsRoot) {
  const forkData = {
    currentVersion,
    genesisValidatorsRoot,
  };
  return mainnet.types.ForkData.hashTreeRoot(forkData);
}

function intToBytes(value, length, endian='le') {
  if (endian === "le") {
    return bigintBuffer.toBufferLE(value, length);
  } else if (endian === "be") {
    return bigintBuffer.toBufferBE(value, length);
  }
  throw new Error("endian must be either 'le' or 'be'");
}

var abi = [
	{
		inputs: [
		],
		stateMutability: "nonpayable",
		type: "constructor"
	},
	{
		anonymous: false,
		inputs: [
			{
				indexed: false,
				internalType: "bytes",
				name: "pubkey",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "withdrawal_credentials",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "amount",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "signature",
				type: "bytes"
			},
			{
				indexed: false,
				internalType: "bytes",
				name: "index",
				type: "bytes"
			}
		],
		name: "DepositEvent",
		type: "event"
	},
	{
		inputs: [
			{
				internalType: "bytes",
				name: "pubkey",
				type: "bytes"
			},
			{
				internalType: "bytes",
				name: "withdrawal_credentials",
				type: "bytes"
			},
			{
				internalType: "bytes",
				name: "signature",
				type: "bytes"
			},
			{
				internalType: "bytes32",
				name: "deposit_data_root",
				type: "bytes32"
			}
		],
		name: "deposit",
		outputs: [
		],
		stateMutability: "payable",
		type: "function"
	},
	{
		inputs: [
		],
		name: "get_deposit_count",
		outputs: [
			{
				internalType: "bytes",
				name: "",
				type: "bytes"
			}
		],
		stateMutability: "view",
		type: "function"
	},
	{
		inputs: [
		],
		name: "get_deposit_root",
		outputs: [
			{
				internalType: "bytes32",
				name: "",
				type: "bytes32"
			}
		],
		stateMutability: "view",
		type: "function"
	},
	{
		inputs: [
			{
				internalType: "bytes4",
				name: "interfaceId",
				type: "bytes4"
			}
		],
		name: "supportsInterface",
		outputs: [
			{
				internalType: "bool",
				name: "",
				type: "bool"
			}
		],
		stateMutability: "pure",
		type: "function"
	}
];
var bytecode = "0x608060405234801561001057600080fd5b5060005b601f8110156101025760026021826020811061002c57fe5b01546021836020811061003b57fe5b015460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b602083106100925780518252601f199092019160209182019101610073565b51815160209384036101000a60001901801990921691161790526040519190930194509192505080830381855afa1580156100d1573d6000803e3d6000fd5b5050506040513d60208110156100e657600080fd5b5051602160018301602081106100f857fe5b0155600101610014565b506118d680620001136000396000f3fe60806040526004361061003f5760003560e01c806301ffc9a71461004457806322895118146100a4578063621fd130146101ba578063c5f2892f14610244575b600080fd5b34801561005057600080fd5b506100906004803603602081101561006757600080fd5b50357fffffffff000000000000000000000000000000000000000000000000000000001661026b565b604080519115158252519081900360200190f35b6101b8600480360360808110156100ba57600080fd5b8101906020810181356401000000008111156100d557600080fd5b8201836020820111156100e757600080fd5b8035906020019184600183028401116401000000008311171561010957600080fd5b91939092909160208101903564010000000081111561012757600080fd5b82018360208201111561013957600080fd5b8035906020019184600183028401116401000000008311171561015b57600080fd5b91939092909160208101903564010000000081111561017957600080fd5b82018360208201111561018b57600080fd5b803590602001918460018302840111640100000000831117156101ad57600080fd5b919350915035610304565b005b3480156101c657600080fd5b506101cf6110b5565b6040805160208082528351818301528351919283929083019185019080838360005b838110156102095781810151838201526020016101f1565b50505050905090810190601f1680156102365780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561025057600080fd5b506102596110c7565b60408051918252519081900360200190f35b60007fffffffff0000000000000000000000000000000000000000000000000000000082167f01ffc9a70000000000000000000000000000000000000000000000000000000014806102fe57507fffffffff0000000000000000000000000000000000000000000000000000000082167f8564090700000000000000000000000000000000000000000000000000000000145b92915050565b6030861461035d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806118056026913960400191505060405180910390fd5b602084146103b6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252603681526020018061179c6036913960400191505060405180910390fd5b6060821461040f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260298152602001806118786029913960400191505060405180910390fd5b670de0b6b3a7640000341015610470576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806118526026913960400191505060405180910390fd5b633b9aca003406156104cd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260338152602001806117d26033913960400191505060405180910390fd5b633b9aca00340467ffffffffffffffff811115610535576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602781526020018061182b6027913960400191505060405180910390fd5b6060610540826114ba565b90507f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c589898989858a8a6105756020546114ba565b6040805160a0808252810189905290819060208201908201606083016080840160c085018e8e80828437600083820152601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01690910187810386528c815260200190508c8c808284376000838201819052601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01690920188810386528c5181528c51602091820193918e019250908190849084905b83811015610648578181015183820152602001610630565b50505050905090810190601f1680156106755780820380516001836020036101000a031916815260200191505b5086810383528881526020018989808284376000838201819052601f9091017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169092018881038452895181528951602091820193918b019250908190849084905b838110156106ef5781810151838201526020016106d7565b50505050905090810190601f16801561071c5780820380516001836020036101000a031916815260200191505b509d505050505050505050505050505060405180910390a1600060028a8a600060801b604051602001808484808284377fffffffffffffffffffffffffffffffff0000000000000000000000000000000090941691909301908152604080517ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0818403018152601090920190819052815191955093508392506020850191508083835b602083106107fc57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016107bf565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610859573d6000803e3d6000fd5b5050506040513d602081101561086e57600080fd5b5051905060006002806108846040848a8c6116fe565b6040516020018083838082843780830192505050925050506040516020818303038152906040526040518082805190602001908083835b602083106108f857805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016108bb565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610955573d6000803e3d6000fd5b5050506040513d602081101561096a57600080fd5b5051600261097b896040818d6116fe565b60405160009060200180848480828437919091019283525050604080518083038152602092830191829052805190945090925082918401908083835b602083106109f457805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090920191602091820191016109b7565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610a51573d6000803e3d6000fd5b5050506040513d6020811015610a6657600080fd5b5051604080516020818101949094528082019290925280518083038201815260609092019081905281519192909182918401908083835b60208310610ada57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610a9d565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610b37573d6000803e3d6000fd5b5050506040513d6020811015610b4c57600080fd5b50516040805160208101858152929350600092600292839287928f928f92018383808284378083019250505093505050506040516020818303038152906040526040518082805190602001908083835b60208310610bd957805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610b9c565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610c36573d6000803e3d6000fd5b5050506040513d6020811015610c4b57600080fd5b50516040518651600291889160009188916020918201918291908601908083835b60208310610ca957805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610c6c565b6001836020036101000a0380198251168184511680821785525050505050509050018367ffffffffffffffff191667ffffffffffffffff1916815260180182815260200193505050506040516020818303038152906040526040518082805190602001908083835b60208310610d4e57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610d11565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610dab573d6000803e3d6000fd5b5050506040513d6020811015610dc057600080fd5b5051604080516020818101949094528082019290925280518083038201815260609092019081905281519192909182918401908083835b60208310610e3457805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610df7565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015610e91573d6000803e3d6000fd5b5050506040513d6020811015610ea657600080fd5b50519050858114610f02576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260548152602001806117486054913960600191505060405180910390fd5b60205463ffffffff11610f60576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260218152602001806117276021913960400191505060405180910390fd5b602080546001019081905560005b60208110156110a9578160011660011415610fa0578260008260208110610f9157fe5b0155506110ac95505050505050565b600260008260208110610faf57fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b6020831061102557805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101610fe8565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa158015611082573d6000803e3d6000fd5b5050506040513d602081101561109757600080fd5b50519250600282049150600101610f6e565b50fe5b50505050505050565b60606110c26020546114ba565b905090565b6020546000908190815b60208110156112f05781600116600114156111e6576002600082602081106110f557fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b6020831061116b57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0909201916020918201910161112e565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa1580156111c8573d6000803e3d6000fd5b5050506040513d60208110156111dd57600080fd5b505192506112e2565b600283602183602081106111f657fe5b015460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b6020831061126b57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0909201916020918201910161122e565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa1580156112c8573d6000803e3d6000fd5b5050506040513d60208110156112dd57600080fd5b505192505b6002820491506001016110d1565b506002826112ff6020546114ba565b600060401b6040516020018084815260200183805190602001908083835b6020831061135a57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0909201916020918201910161131d565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790527fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000095909516920191825250604080518083037ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8018152601890920190819052815191955093508392850191508083835b6020831061143f57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101611402565b51815160209384036101000a7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01801990921691161790526040519190930194509192505080830381855afa15801561149c573d6000803e3d6000fd5b5050506040513d60208110156114b157600080fd5b50519250505090565b60408051600880825281830190925260609160208201818036833701905050905060c082901b8060071a60f81b826000815181106114f457fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060061a60f81b8260018151811061153757fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060051a60f81b8260028151811061157a57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060041a60f81b826003815181106115bd57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060031a60f81b8260048151811061160057fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060021a60f81b8260058151811061164357fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060011a60f81b8260068151811061168657fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060001a60f81b826007815181106116c957fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535050919050565b6000808585111561170d578182fd5b83861115611719578182fd5b505082019391909203915056fe4465706f736974436f6e74726163743a206d65726b6c6520747265652066756c6c4465706f736974436f6e74726163743a207265636f6e7374727563746564204465706f7369744461746120646f6573206e6f74206d6174636820737570706c696564206465706f7369745f646174615f726f6f744465706f736974436f6e74726163743a20696e76616c6964207769746864726177616c5f63726564656e7469616c73206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c7565206e6f74206d756c7469706c65206f6620677765694465706f736974436f6e74726163743a20696e76616c6964207075626b6579206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f20686967684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f206c6f774465706f736974436f6e74726163743a20696e76616c6964207369676e6174757265206c656e677468a2646970667358221220dceca8706b29e917dacf25fceef95acac8d90d765ac926663ce4096195952b6164736f6c634300060b0033";
var DEPOSIT_CONTRACT = {
	abi: abi,
	bytecode: bytecode
};

const init = bls__default['default'].init(bls__default['default'].BLS12_381);
const HOMEDIR = require('os').homedir();
const VERSION = 1;
const FORK_VERSION = Buffer.from('00000001','hex');
const BLS_WITHDRAWAL_PREFIX = Buffer.from('00', 'hex');
const DEPOSIT_AMOUNT = BigInt(32000000000);

class Wallet {
  constructor(opts={}) {
    let defaults = {
      wallet_path: `${HOMEDIR}/.eth2-wallet-js/wallet`,
      algorithm: 'aes-256-cbc',
      fork_version: FORK_VERSION,
    };
    opts = { ...defaults, ...opts };
    this.version = VERSION;
    this.queue = new PQueue__default['default']({ concurrency: 1 });
    this.algorithm = opts.algorithm;
    this.walletPath = opts.wallet_path;
    this.forkVersion = opts.fork_version;
    //this.keystore = getKeystore(this.algorithm);
  }

  /**
   * This just awaits the initialization of the BLS package.
   * @return {Null}
   */
  async init() {
    await init;
    return;
  }

  async depositData(walletId, keyId, password, opts={} ) {
    let defaults = { withdraw_key_id: keyId, withdraw_key_wallet: walletId, withdraw_public_key: null, amount: DEPOSIT_AMOUNT, raw: true };
    opts = {...defaults, ...opts };
    try {
      let validatorKey = await this.keySearch(keyId, walletId);
      let validatorPubKey = validatorKey.public_key;
      let withdrawPubKey;
      if(PUBLIC_KEY.test(opts.withdraw_public_key)) withdrawPubKey = opts.withdraw_public_key;
      else {
        let withdrawKey = await this.keySearch(opts.withdraw_key_id, opts.withdraw_key_wallet);
        withdrawPubKey = withdrawKey.public_key;
      }

      //deposit data with empty signature to sign
      const withdrawalPubKeyHash = crypto__default['default'].createHash('sha256').update(Buffer.from(withdrawPubKey, 'hex')).digest();
      const depositData = {
          pubkey: Buffer.from(validatorPubKey, 'hex'),
          withdrawalCredentials: Buffer.concat([ BLS_WITHDRAWAL_PREFIX, withdrawalPubKeyHash.slice(1) ]),
          amount: opts.amount,
          signature: Buffer.alloc(96),
      };
      let signingRoot = getSigningRoot(depositData, this.forkVersion);
      depositData.signature = await this.sign(signingRoot.toString('hex'), walletId, validatorPubKey, password);
      let depositDataRoot = getDepositDataRoot(depositData);
      if(opts.raw == true) {
        let contract = new ethers.ethers.utils.Interface(DEPOSIT_CONTRACT.abi);
        let raw = contract.encodeFunctionData("deposit", [
          depositData.pubkey,
          depositData.withdrawalCredentials,
          depositData.signature,
          depositDataRoot,
        ]);
        return raw;
      }
      else return {
        pubkey: validatorPubKey,
        withdrawal_credentials: depositData.withdrawalCredentials.toString('hex'),
        signature: Buffer.from(depositData.signature).toString('hex'),
        amount: depositData.amount.toString(),
        deposit_data_root: depositDataRoot.toString('hex')
      }
    }
    catch(error) { throw error; }
  }

  async keyCreate(walletId, password, accountId=uuid.v4()) {
    return this.queue.add(() => this.keyCreateAsync(walletId, password, accountId));
  }

  /**
   * Creates a new ETH2 keypair.
   * @param  {String} wallet_id The name of the wallet to create an key in.
   * @param  {String} password The password to protect the key.
   * @param  {String} keyId=UUID] The name of the key to create.
   * @return {Object} An object containing the wallet_id, key_id and public_key.
   * @throws On failure
   */
  async keyCreateAsync(walletId, password, keyId=uuid.v4()) {
    try {
      const sec = new bls__default['default'].SecretKey();
      sec.setByCSPRNG();
      const pub = sec.getPublicKey();
      let privateKeyHex = bls__default['default'].toHexStr(sec.serialize());
      return await this.keyImportAsync(walletId, privateKeyHex, password, keyId);
    }
    catch(error) { throw error; }
  }

  /**
   * Removes a key from a wallet.
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @param  {String}  password The password protecting the key.
   * @return {Boolean}          True on successful deletion.
   * @throws On failure
   */
  async keyDelete(walletId, keyId, password) {
    try {
      let key = await this.keyPrivate(walletId, keyId, password);
      let indexFile = await this.walletIndexKey(walletId, keyId, null, true);
      let keyFile = await fs__default['default'].promises.unlink(`${this.walletPath}/${walletId}/${keyId}`);
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Check whether a key already exists.
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @return {Boolean}          Whether or not the key ID already exists in the wallet.
   * @throws On failure
   */
  async keyExists(search, walletId) {
    try {
      let indexSearch = await this.keySearch(search, walletId);
      let fileSearch = await fs__default['default'].promises.access(`${this.walletPath}/${walletId}/${indexSearch.key_id}`);
      return true;
    }
    catch(error) {
      //console.error(error);
      return false;
    }
  }

  async keyImport(walletId, privateKey, password, keyId=uuid.v4()) {
    return this.queue.add(() => this.keyImportAsync(walletId, privateKey, password, keyId));
  }

  /**
   * Import a private key into the keystore
   * @param  {String}  walletId The wallet to import into.
   * @param  {String}  privateKey A 32byte HEX-format private key
   * @param  {String}  password A password to protect the key.
   * @param  {String}  keyId The ID reference for the key.
   * @return {Object}  An object containing the walletId <string> key ID <UUID> and public key <48-byte HEX>
   * @throws On failure
   */
  async keyImportAsync(walletId, privateKey, password, keyId=uuid.v4()) {
    try {
      if(await this.keyExists(keyId, walletId))
        throw new Error('Key ID already exists.');
      if(await this.keyExists(privateKey, walletId))
          throw new Error('Private Key already exists.');

      const sec = bls__default['default'].deserializeHexStrToSecretKey(privateKey);
      const pub = sec.getPublicKey();
      const pubKeyHex = bls__default['default'].toHexStr(pub.serialize());
      let saveData = await this.keystore.encrypt(privateKey, password, pubKeyHex);

      let walletFile = fs__default['default'].promises.writeFile( `${this.walletPath}/${walletId}/${keyId}`, JSON.stringify(saveData) );
      let indexFile = this.walletIndexKey(walletId, keyId, pubKeyHex);
      await Promise.all([walletFile, indexFile]);

      return {
        wallet_id: walletId,
        key_id: keyId,
        public_key: pubKeyHex
      }
    }
    catch(error) { throw error; }
  }

  /**
   * Get a private key
   * @param  {String}  walletId The wallet ID.
   * @param  {String}  keyId    The Key ID.
   * @param  {String}  password The password protecting the key.
   * @return {String}           The 64-byte HEX formatted private key.
   * @throws On failure
   */
  async keyPrivate(walletId, keyId, password) {
    try {
      let data = await this.decrypt(walletId, keyId, password);
      return data;
    }
    catch(error) { throw error; }
  }

  /**
   * Finds key information.
   * @param  {String}  search   Either an key ID or public key.
   * @param  {String}  walletId The wallet ID to search for keys.
   * @return {Object}  Object containing key_id and public_key.
   * @throws On failure
   */
  async keySearch(search, walletId) {
    try {
      let buffer = await fs__default['default'].promises.readFile(`${this.walletPath}/${walletId}/index`);
      let index = JSON.parse(buffer.toString());
      let searchField;
      // Convert private key to public key for search.
      if(PRIVATE_KEY.test(search)) {
        const sec = bls__default['default'].deserializeHexStrToSecretKey(search);
        const pub = sec.getPublicKey();
        const pubKeyHex = bls__default['default'].toHexStr(pub.serialize());
        searchField = 'public_key';
        search = pubKeyHex;
      }
      else searchField = (PUBLIC_KEY.test(search)) ? 'public_key' : 'key_id';
      let keyObj = ___default['default'].find(index.key_list, { [searchField]: search });
      //console.log(`${keyObj} -- Field: ${searchField} -- Search: ${search} -- Wallet: ${walletId}`);
      if(___default['default'].isNil(keyObj)) throw new Error('Key not found.')
      return { key_id: keyObj.key_id, public_key: keyObj.public_key, wallet_id: walletId }
    }
    catch (error) { throw error; }
  }

  /**
  * Signs a generic message with a private key.
  * @param  {String}  message   The message to sign (32-Byte HEX)
   * @param  {String}  walletId Wallet ID where the key is stored.
   * @param  {String}  search   The key to search for. Accepts keyID, publicKey, and privateKey.
   * @param  {String}  password Password protecting the signing key.
   * @return {Array}   The 96-byte BLS signature.
   */
  async sign(message, walletId, search, password) {
    try {
      let keyObject = await this.keySearch(search, walletId);
      let secHex = await this.keyPrivate(walletId, keyObject.key_id, password);
      const sec = bls__default['default'].deserializeHexStrToSecretKey(secHex);
      const pub = sec.getPublicKey();
      const msg = bls__default['default'].fromHexStr(message);
      const sig = sec.sign(msg);
      let serialized = sig.serialize();
      return serialized;
    }
    catch(error) { throw error; }
  }

  /**
   * Creates a new wallet to store keys.
   * @param  {Object}  [opts={}] Optional parameters.
   * @param  {String}  [opts.wallet_id=uuidv4] Wallet identifer. If not provided, will be random.
   * @param  {String}  [opts.type=1] The type of wallet to create. 1=Simple, 2=Hierarchical deterministic.
   * @param  {String}  [opts.password=null] Password for HD wallets.
   * @param  {String}  [opts.mnemonic=null] BIP39 mnemonic for HD wallets.
   * @return {String}  The wallet identifier.
   * @throws On failure
   */
  async walletCreate(opts={}) {
    let defaults = { wallet_id: uuid.v4(), type: 1 };
    opts = { ...defaults, ...opts };
    let walletExists = await this.walletExists(opts.wallet_id);
    if(walletExists) throw new Error('Wallet already exists');
    try {
      await fs__default['default'].promises.mkdir(`${this.walletPath}/${opts.wallet_id}`, { recursive: true });
      const indexData = { type: opts.type, key_list: [] };
      await fs__default['default'].promises.writeFile(`${this.walletPath}/${opts.wallet_id}/index`, JSON.stringify(indexData));
      return opts.wallet_id;
    }
    catch(error) { throw error; }
  }

  /**
   * Delete a wallet
   * @param  {String}  id The wallet identifier
   * @return {Boolean}    True if the delete was successful.
   * @throws On failure
   */
  async walletDelete(walletId) {
    try {
      let walletExists = await this.walletExists(walletId);
      if(!walletExists) throw new Error('Wallet does not exist');
      await fs__default['default'].promises.rmdir(`${this.walletPath}/${walletId}`, { recursive: true });
      return true;
    }
    catch(error) { throw error; }
  }

  async walletExists(walletId) {
    try {
      await fs__default['default'].promises.access(`${this.walletPath}/${walletId}`);
      return true;
    }
    catch(error) {
      return false;
    }
  }

  /**
   * Return a list of available wallet IDs
   * @return {Array} A list of wallet IDs.
   * @throws On failure
   */
  async walletList() {
    try {
      // get all the files and directories
      let list = await fs__default['default'].promises.readdir(`${this.walletPath}`, { withFileTypes: true });
      // filter out files and hidden folders
      let dirList = list.filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name)
        .filter(item => !(/(^|\/)\.[^\/\.]/g).test(item));
      return dirList;
    }
    catch(error) { throw error; }
  }

  /**
   * List of available keys in a wallet.
   * @param  {String}  id The wallet ID to search
   * @return {Array}   An array of key objects.
   */
  async walletListKeys(walletId) {
    try {
      let buffer = await fs__default['default'].promises.readFile(`${this.walletPath}/${walletId}/index`);
      let indexData = JSON.parse(buffer.toString());
      return indexData.key_list;
    }
    catch(error) { throw error; }
  }

  /**
   * Modifies a wallet index file. Either adds or removes a key.
   * @param  {String}  walletId         The wallet file to modify
   * @param  {String}  keyId            The key to modify
   * @param  {String}  [publicKey=null] 48-Byte HEX public key
   * @param  {Boolean} [remove=false]   Whether to remove the key
   * @return {Boolean}                  True on sucess
   * @throws On failure
   */
  async walletIndexKey(walletId, keyId, publicKey=null, remove=false) {
    try {
      let buffer = await fs__default['default'].promises.readFile(`${this.walletPath}/${walletId}/index`);
      let indexData = JSON.parse(buffer.toString());
      // check for existing keys
      let indexSearch = (publicKey === null) ? keyId : publicKey;
      let hasKey = await this.keyExists(indexSearch, walletId);

      if(remove == true && hasKey) ___default['default'].remove(indexData.key_list, function(o) { o.key_id == keyId; });
      else if( remove == false && !hasKey) indexData.key_list.push({ key_id: keyId, public_key: publicKey });
      else if(remove == true && !hasKey) throw new Error(`Key not found: ${keyId}.`)
      else if(remove == false && hasKey) throw new Error(`Duplicate key found: ${publicKey}.`)

      await fs__default['default'].promises.writeFile(`${this.walletPath}/${walletId}/index`, JSON.stringify(indexData));
      return true;
    }
    catch(error) { throw error; }
  }

  async encrypt(privateKey, password) {
    const iv = crypto__default['default'].randomBytes(16);
    const key = crypto__default['default'].createHash('sha256').update(password).digest();

    let cipher = crypto__default['default'].createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(privateKey);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { algorithm: this.algorithm, iv: iv.toString('hex'), data: encrypted.toString('hex') };
  }

  async decrypt(walletId, keyId, password) {
    let buffer = await fs__default['default'].promises.readFile(`${this.walletPath}/${walletId}/${keyId}`);
    let text = JSON.parse(buffer.toString());
    return await this.keystore.decrypt(text, password);
  }
}

module.exports = {
  Wallet
};
