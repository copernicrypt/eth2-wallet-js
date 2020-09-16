import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';
import { Command } from 'commander';
import { Wallet } from './wallet';

const WALLET = new Wallet();

const program = new Command();
program.version('0.1.0', '-v, --version', 'output the current version');

program
  .command('depositData')
  .description('generates deposit data for a validator/withdrawal keypair')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID where the validator key is stored')
  .requiredOption('-k, --key <key>', 'The validator key ID')
  .requiredOption('-p, --password <password>', 'The password protecting the validator key')
  .option('-wkw, --withdrawalwallet <withdrawalwallet>', 'The wallet where the withdrawal key is stored. Defaults to same as <wallet>', null)
  .option('-wk, --withdrawalkey <withdrawalkey>', 'The ID of the withdrawal key. Defaults to <key>', null)
  .option('-wpk, --withdrawalpublickey <withdrawalpublickey>', 'The Public Key of the Withdrawal key. Optionally replaces <withdrawalwallet> and <withdrawalkey>', null)
  .option('-a, --amount <amount>', 'The amount of the deposit in gwei.', BigInt(32000000000))
  .option('-r, --raw', 'Whether to return the raw data HEX.', false)
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let opts = { withdraw_key_id: cmdObj.key, withdraw_key_wallet: cmdObj.wallet, withdraw_public_key: cmdObj.withdrawalpublickey, raw: cmdObj.raw, amount: cmdObj.amount };
      if(_.isNil(cmdObj.withdrawalpublickey)) {
        if(!_.isNil(cmdObj.withdrawalwallet)) opts.withdraw_key_wallet = cmdObj.withdrawalwallet;
        if(!_.isNil(cmdObj.withdrawalkey)) opts.withdraw_key_id = cmdObj.withdrawalkey;
      }
      console.log(await WALLET.depositData(cmdObj.wallet, cmdObj.key, cmdObj.password, opts));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
  });

program
  .command('keyCreate')
  .description('creates a new key in a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID to create a new key in')
  .requiredOption('-p, --password <password>', 'The password protecting the key')
  .option('-k, --key <key>', 'The key ID', uuidv4())
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      console.log(await WALLET.keyCreate(cmdObj.wallet, cmdObj.password, cmdObj.key));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('keyDelete')
  .description('deletes a key from a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID to import into')
  .requiredOption('-k, --key <key>', 'The key ID')
  .requiredOption('-p, --password <password>', 'The password protecting the key')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      await WALLET.keyDelete(cmdObj.wallet, cmdObj.key, cmdObj.password);
      console.log(`Key Deleted: ${cmdObj.key} --- Wallet: ${cmdObj.wallet}`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
  });

program
  .command('keyImport')
  .description('imports a private key into a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID to import into')
  .requiredOption('-pk, --privatekey <privatekey>', 'The private key to import in hex format')
  .requiredOption('-p, --password <password>', 'The password to protect the imported private key')
  .option('-k, --key <key>', 'A key id for the imported key', uuidv4())
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      console.log(await WALLET.keyImport(cmdObj.wallet, cmdObj.privatekey, cmdObj.password, cmdObj.key));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('keyPrivate')
  .description('returns a private key HEX')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .requiredOption('-k, --key <key>', 'The key ID')
  .requiredOption('-p, --password <password>', 'The password protecting the key')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      console.log(await WALLET.keyPrivate(cmdObj.wallet, cmdObj.key, cmdObj.password));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});


program
  .command('keySearch')
  .description('finds a key in a wallet based on keyId, publicKey or privateKey')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .requiredOption('-s, --search <search>', 'The key to search for. KeyId, publicKey or privateKey')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      console.log(await WALLET.keySearch(cmdObj.search, cmdObj.wallet));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});


program
  .command('sign')
  .description('signs a generic message')
  .requiredOption('-m, --message <message>', 'The message to sign (32-byte HEX)')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .requiredOption('-s, --search <search>', 'The key to search for. Accepts keyId, publicKey and privateKey')
  .requiredOption('-p, --password <password>', 'The password protecting the key.')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let result = WALLET.sign(cmdObj.message, cmdObj.wallet, cmdObj.search, cmdObj.password);
      console.log(result);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletCreate')
  .description('creates a new wallet')
  .option('-w, --wallet <wallet>', 'The wallet ID', null)
  .option('-t, --type <type>', 'The wallet type (1=Basic, 2=HD (not implemented))', 1)
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let params = { type: cmdObj.type }
      if(params.type !== 1 || params.type !== 2) console.error(`Wallet type '${params.type}' not supported`);
      if(!_.isNil(cmdObj.wallet)) params.wallet_id = cmdObj.wallet;
      let walletId = await WALLET.walletCreate( params );
      console.log(`Created wallet: ${walletId}`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletDelete')
  .description('deletes a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      await WALLET.walletDelete( cmdObj.wallet );
      console.log(`Deleted wallet: ${cmdObj.wallet}`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletList')
  .description('lists all available wallets')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let list = await WALLET.walletList();
      console.log(list);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletListKeys')
  .description('lists all available keys for a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let list = await WALLET.walletListKeys(cmdObj.wallet);
      console.log(list);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program.parse(process.argv);
