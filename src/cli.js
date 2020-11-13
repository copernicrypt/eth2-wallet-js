#!/usr/bin/env node
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
      let opts = { withdrawal_key_id: cmdObj.key, withdrawal_key_wallet: cmdObj.wallet, withdrawal_public_key: cmdObj.withdrawalpublickey, raw: cmdObj.raw, amount: cmdObj.amount };
      if(_.isNil(cmdObj.withdrawalpublickey)) {
        if(!_.isNil(cmdObj.withdrawalwallet)) opts.withdrawal_key_wallet = cmdObj.withdrawalwallet;
        if(!_.isNil(cmdObj.withdrawalkey)) opts.withdrawal_key_id = cmdObj.withdrawalkey;
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
  .command('keyList')
  .description('lists all available keys for a wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let list = await WALLET.keyList(cmdObj.wallet);
      console.log(list);
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
  .description('finds a key in a wallet based on keyId, publicKey')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .requiredOption('-s, --search <search>', 'The key to search for. KeyId, publicKey')
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
  .requiredOption('-s, --search <search>', 'The key to search for. Accepts keyId, publicKey')
  .requiredOption('-p, --password <password>', 'The password protecting the key.')
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let result = await WALLET.sign(cmdObj.message, cmdObj.wallet, cmdObj.search, cmdObj.password);
      console.log(Buffer.from(result).toString('hex'));
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletBackup')
  .description('creates a wallet backup file')
  .requiredOption('-w, --wallet <wallet>', 'The wallet ID')
  .option('-d, --destination <destination>', 'The destination to save the file.', null)
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let destination = await WALLET.walletBackup(cmdObj.wallet, cmdObj.destination);
      console.log(`Wallet "${cmdObj.wallet}" successfully backed up to: ${destination}`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
  });

program
  .command('walletCreate')
  .description('creates a new wallet')
  .option('-w, --wallet <wallet>', 'The wallet ID', null)
  .option('-t, --type <type>', 'The wallet type (1=Basic, 2=HD)', 1)
  .option('-p, --password <password>', 'The HD wallet password.', null)
  .option('-m, --mnemonic <mnemonic>', 'The BIP39 mnemonic phrase', null)
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      let params = { type: cmdObj.type, password: cmdObj.password, mnemonic: cmdObj.mnemonic }
      if(params.type == 1 && params.type == 2) console.error(`Wallet type '${params.type}' not supported`);
      else {
        if(!_.isNil(cmdObj.wallet)) params.wallet_id = cmdObj.wallet;
        let walletId = await WALLET.walletCreate( params );
        console.log(`Created wallet: ${walletId}`);
      }
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
  .command('walletMnemonic')
  .description('returns the mnemonic for an HD wallet')
  .requiredOption('-w, --wallet <wallet>', 'The wallet to search for.')
  .requiredOption('-p, --password <password>', 'The password protecting the wallet.')
  .action( async(cmdObj) => {
    try {
      await WALLET.init();
      let mnemonic = await WALLET.walletMnemonic(cmdObj.wallet, cmdObj.password);
      console.log(mnemonic);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
  });

program
  .command('walletRestore')
  .description('restores a wallet from file.')
  .requiredOption('-s, --source <source>', 'The absolute path to the backup file.')
  .option('-w, --wallet <wallet>', 'Optional wallet name to import into. Defaults to filename.', null)
  .action(async(cmdObj) => {
    try {
      await WALLET.init();
      await WALLET.walletRestore(cmdObj.source, cmdObj.wallet);
      console.log(`Wallet "${cmdObj.wallet}" successfully restored.`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
  });

program.parse(process.argv);
