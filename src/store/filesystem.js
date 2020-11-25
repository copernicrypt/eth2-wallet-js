import _ from 'lodash';
import fs from 'fs';
import  { v4 as uuidv4 } from 'uuid';
import PQueue from 'p-queue';
import archiver from 'archiver';
import extract from 'extract-zip';
import * as types from '../types';
const HOMEDIR = require('os').homedir();

/**
 * Filesystem storage system for keys.
 * @type {Object}
 */
export class Filesystem {
  constructor(opts={}) {
    let defaults = { path: `${HOMEDIR}/.eth2-wallet-js/wallet`, keyType: 1 }
    opts = {...defaults, ...opts }

    this.rootPath = opts.path;
    this.keyType = opts.keyType;
    this.indexQueue = new PQueue({ concurrency: 1 });
  }

  /**
   * Deletes a key from the store.
   * @param  {String} search       The search term. Either keyId or publicKey.
   * @param  {String} [path=null] A subpath where the key is stored.
   * @return {Boolean}            Returns true when delete is successful.
   * @throws On failure.
   */
  async keyDelete(search, path=null) {
    try {
      let keyId = search;
      if(types.PUBLIC_KEY.test(search)) {
        let keyObj = await this.keySearch(search, path);
        keyId = keyObj.key_id;
      }
      let indexFile = await this.indexUpdate(keyId, null, true, path);
      let keyFile = await fs.promises.unlink(this.pathGet(keyId, path));
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
  async keyExists(search, path=null) {
    try {
      let indexSearch = await this.keySearch(search, path);
      let fileSearch = await fs.promises.access(this.pathGet(indexSearch.key_id, path));
      return true;
    }
    catch(error) {
      //console.error(error);
      return false;
    }
  }

  /**
   * List of available keys in a wallet.
   * @param  {String}  path The wallet ID to search
   * @return {Array}   An array of key objects.
   */
  async keyList(path=null) {
    try {
      let buffer = await fs.promises.readFile(this.pathGet('index', path));
      let indexData = JSON.parse(buffer.toString());
      return indexData.key_list;
    }
    catch(error) { throw error; }
  }

  /**
   * Finds key information.
   * @param  {String}  search   Either an key ID or public key.
   * @param  {String}  path The subpath to search in. Either keyId or publicKey
   * @return {Object}  Object containing key_id and public_key.
   * @throws On failure
   */
  async keySearch(search, path=null) {
    try {
      let indexBuf = await fs.promises.readFile(this.pathGet('index', path));
      let index = JSON.parse(indexBuf.toString());
      let searchField = (types.PUBLIC_KEY.test(search)) ? 'public_key' : 'key_id';
      let keyObj = _.find(index.key_list, { [searchField]: search });
      //console.log(`${keyObj} -- Field: ${searchField} -- Search: ${search} -- Wallet: ${walletId}`);
      if(_.isNil(keyObj)) throw new Error('Key not found.')
      let key = await fs.promises.readFile(this.pathGet(keyObj.key_id, path));
      keyObj.key_object = JSON.parse(key);
      return keyObj;
      //return { key_id: keyObj.key_id, public_key: keyObj.public_key, path: path || '' }
    }
    catch (error) { throw error; }
  }

  /**
   * Write a key to storage
   * @param  {Object}  keyData   The data the store. Likely in JSON.
   * @param  {Object} [opts={}]  Optional parameters
   * @param  {String}  [opts.keyId=UUID]       The key ID.
   * @param  {String}  [opts.publicKey=null]   48-Byte HEX public key
   * @param  {String}  [opts.path=null] Optional subpath.
   * @return {Boolean} True on Success.
   * @throws On failure.
   */
  async keyWrite(keyData, opts={}) {
    let defaults = { keyId: uuidv4(), publicKey: null, path: null };
    opts = {...defaults, ...opts }
    if(await this.keyExists(opts.keyId, opts.path))
      throw new Error('Key ID already exists.');
    if(opts.publicKey !== null && await this.keyExists(opts.publicKey, opts.path))
      throw new Error('Public Key already exists.');

    try {
      await this.indexUpdate(opts.keyId, opts.publicKey, false, opts.path);
      await fs.promises.writeFile( this.pathGet(opts.keyId, opts.path), JSON.stringify(keyData), { recursive: true } );
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Retrieve the next accound index.
   * @param  {String}  path An optional subpath where the index is stored.
   * @return {Integer}      The next sequential account index.
   */
  async indexAccountNext(path=null) {
    try {
      let indexData = await this.indexGet(path);
      if(types.WALLET[indexData.type] !== 'HD') throw new Error('Only HD wallets track account indexes.');
      else return (_.isNil(indexData.currentAccount)) ? 0 : indexData.currentAccount + 1;
    }
    catch(error) { throw error; }
  }

  /**
   * Creates a new index file.
   * @param  {String}  [path=null] Optional subpath to create the index.
   * @return {Object}              The Index data object.
   */
  async indexCreate(path=null, keyType=this.keyType) {
    try {
      let indexPath = this.pathGet('index', path);
      await fs.promises.mkdir(this.pathGet(path), { recursive: true });
      const indexData = { type: keyType, key_list: [] };
      await fs.promises.writeFile(indexPath, JSON.stringify(indexData));
      return indexData;
    }
    catch(error) { throw error; }
  }

  /**
   * Determines whether an index file already exists.
   * @param  {String}  path An optional subpath where the index is stored.
   * @return {Boolean}      True if it exists, false otherwise.
   */
  async indexExists(path=null) {
    try {
      await fs.promises.access(this.pathGet('index', path));
      return true;
    }
    catch(error) { return false; }
  }

  async indexGet(path=null) {
    if(this.indexExists(path)) {
      let indexPath = this.pathGet('index', path)
      let buffer = await fs.promises.readFile(indexPath);
      return JSON.parse(buffer.toString());
    }
    else throw new Error('Index does not exist.');
  }

  /**
   * Rebuilds the index file of a folder
   * @param  {String}  [path=null] [description]
   * @param  {String}  [opts.pattern='default']   The pattern to search for key files (default, eth2_cli)
   * @return {Boolean} True on success
   * @throws On failure.
   */
  async indexRebuild(path=null, opts={}) {
    let defaults = { pattern: 'default' }
    opts = { ...defaults, ...opts };
    try {
      // Get a list of JSON files
      let fileList = await fs.promises.readdir(this.pathGet(path));
      const keyList = fileList.filter(e => e.match(types.WALLET_FILE[opts.pattern]));
      if(keyList.length > 0) {
        // Delete old Index file
        await fs.promises.unlink(this.pathGet('index', path));
        // Convert files to JSON
        let filesParsed = keyList.map(async(file) => {
          let filePath = this.pathGet(file, path);
          let fileBuf = await fs.promises.readFile(filePath);
          let fileJson = JSON.parse(fileBuf.toString('utf8'));
          if(fileJson.hasOwnProperty('uuid') && fileJson.hasOwnProperty('pubkey')) {
            // Use the UUID to rename the file.
            await fs.promises.rename(filePath, this.pathGet(`${fileJson.uuid}.json`, path));
            // Use the uuid and pubkey to add new items to the index file's key_list array
            await this.indexUpdate(fileJson.uuid, fileJson.pubkey, false, path);
            return filePath;
          }
          else return null;
        })
        return await Promise.all(filesParsed); // pass array of promises
      }
      else throw new Error('No valid JSON files found.')
    }
    catch(error) { throw error; }
  }

  async indexType(path=null) {
    try {
      let indexData = await this.indexGet(path);
      return indexData.type;
    }
    catch(error) { throw error; }
  }

  async indexUpdate(keyId, publicKey=null, remove=false, path=null) {
    return this.indexQueue.add(() => this.indexUpdateAsync(keyId, publicKey, remove, path));
  }

  /**
   * Modifies a wallet index file. Either adds or removes a key. Creates new index if one doesn't exist.
   * @param  {String}  walletId         The wallet file to modify
   * @param  {String}  keyId            The key to modify
   * @param  {Boolean} [remove=false]   Whether to remove the key
   * @return {Boolean}                  True on sucess
   * @throws On failure
   */
  async indexUpdateAsync(keyId, publicKey=null, remove=false, path=null) {
    try {
      let indexExists = await this.indexExists(path);
      if(!indexExists) await this.indexCreate(path);
      let indexData = await this.indexGet(path);
      // check for existing keys
      let indexSearch = (publicKey === null) ? keyId : publicKey;
      let keyExists = await this.keyExists(indexSearch, path);
      let removed;
      if(remove == true && keyExists) removed = await _.remove(indexData.key_list, function(o) {
        return (o.key_id == keyId || o.uuid == keyId);
      });
      else if( remove == false && !keyExists) {
        indexData.key_list.push({ key_id: keyId, public_key: publicKey });
        // Set the current account index for HD wallets.
        if(types.WALLET[indexData.type] === 'HD') indexData.currentAccount = indexData.key_list.length;
      }
      else if(remove == true && !keyExists) throw new Error(`Key not found: ${keyId}.`)
      else if(remove == false && keyExists) throw new Error(`Duplicate key found: ${publicKey}.`)
      await fs.promises.writeFile(this.pathGet('index', path), JSON.stringify(indexData));
      return true;
    }
    catch(error) { throw error; }
  }

  async mnemonicCreate(mnemonic, path=null) {
    try {
      let mnemonicPath = this.pathGet('mnemonic', path);
      await fs.promises.writeFile(mnemonicPath, JSON.stringify(mnemonic));
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Returns an encrypted mnemonic JSON object.
   * @param  {String}  [path=null] Subpath within the root wallet.
   * @return {Object|String}              The mnemonic object string
   */
  async mnemonicGet(path=null) {
    let key = await fs.promises.readFile(this.pathGet('mnemonic', path));
    return JSON.parse(key);
  }

  /**
   * Backup a file path to ZIP
   * @param  {String}  path               The Subpath to backup within the root wallet.
   * @param  {String}  [destination=null] The destination to write the file to.
   * @return {String}                    Resolves on success, returns the save path.
   */
  async pathBackup(path, destination=null) {
    let walletExists = await this.indexExists(path);
    if(!walletExists) throw new Error('Wallet does not exist.');
    if(destination == null) destination = this.pathGet(`${path}.zip`)
    return new Promise((resolve, reject) => {
      // create a file to stream archive data to.
      const output = fs.createWriteStream( destination );
      const archive = archiver('zip', {
        zlib: { level: 9 } // Sets the compression level.
      });
      output.on("close", function() { resolve(destination) });
      archive.on("error", reject);
      archive.directory(`${this.pathGet(path)}/`, false);
      archive.pipe(output);
      archive.finalize();
    });
  }

  /**
   * Restore a path from file.
   * @param  {String}  source The source file absolute path.
   * @param  {String}  [wallet=null] Optional wallet name.
   * @return {Boolean}        Returns true on success.
   * @throws On Error.
   */
  async pathRestore(source, opts={}) {
    try {
        let defaults = { wallet: null, rebuild: false }
        opts = { ...defaults, ...opts };
        let filename = source.replace(/^.*[\\\/]/, '').split('.')[0];
        await fs.promises.access(source);
        let walletName = ( opts.wallet == null ) ? filename : opts.wallet;
        let dir = this.pathGet(walletName);
        await extract(source, { dir: dir });
        if(opts.rebuild === true) await this.indexRebuild(walletName);
        //console.log(`Wallet restored: ${filename}`);
        return true;
      }
      catch (err) {
        throw err;
      }
  }

  /**
   * Gets an absolute path for writing a file
   * @param  {String} filename       Filename to write
   * @param  {String} [subpath=null] Optional subpath
   * @return {String}                The absolute path for a target file.
   */
  pathGet(filename, subpath=null) {
    filename = (filename !== null) ? filename: '';
    return (subpath !== null) ? `${this.rootPath}/${subpath}/${filename}` : `${this.rootPath}/${filename}`;
  }

  /**
   * Deletes all keys/indexes in a path
   * @param  {String}  path The Path to delete
   * @return {Boolean}      True if successful
   * @throws On failure
   */
  async pathDelete(path) {
    try {
      await fs.promises.rmdir(this.pathGet(path), { recursive: true });
      return true;
    }
    catch(error) { throw error; }
  }

  /**
   * Return a list of available wallet IDs
   * @return {Array} A list of wallet IDs.
   * @throws On failure
   */
  async pathList(path=null) {
    try {
      // get all the files and directories
      let list = await fs.promises.readdir(this.pathGet(null, path), { withFileTypes: true });
      // filter out files and hidden folders
      let dirList = list.filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name)
        .filter(item => !(/(^|\/)\.[^\/\.]/g).test(item));
      return dirList;
    }
    catch(error) { throw error; }
  }
}
