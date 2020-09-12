import _ from 'lodash';
import { Command } from 'commander';
import Keystore from './keystore';

const KEYSTORE = new Keystore();

const program = new Command();
program.version('0.1.0', '-v, --version', 'output the current version');

program
  .command('walletCreate')
  .description('creates a new wallet')
  .option('-w, --wallet <wallet>', 'The wallet ID', null)
  .option('-t, --type <filepath>', 'The wallet type (1=Basic, 2=HD (not implemented))', 1)
  .action(async(cmdObj) => {
    try {
      await KEYSTORE.init();
      let params = { type: cmdObj.type }
      if(!_.isNil(cmdObj.wallet)) params.wallet_id = cmdObj.wallet;
      let walletId = await KEYSTORE.walletCreate( params );
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
      await KEYSTORE.init();
      await KEYSTORE.walletDelete( cmdObj.wallet );
      console.log(`Deleted wallet: ${cmdObj.wallet}`);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program
  .command('walletList')
  .description('lists all available wallets')
  .action(async(cmdObj) => {
    try {
      await KEYSTORE.init();
      let list = await KEYSTORE.walletList();
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
      await KEYSTORE.init();
      let list = await KEYSTORE.walletListKeys(cmdObj.wallet);
      console.log(list);
    }
    catch(error) { console.error(`Error: ${error.message}`); }
});

program.parse(process.argv);
