import { Eip2333 } from './eip2333';
import { bigIntToBuffer } from '../helpers';

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE = "TREZOR";

const CASE0 = {
  seed: Buffer.from('c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04', 'hex'),
  master_sk:  BigInt('6083874454709270928345386274498605044986640685124978867557563392430687146096'),
  child_index: 0,
  child_sk: BigInt('20397789859736650942317412262472558107875392172444076792671091975210932703118')
}

const CASE1 = {
  seed: Buffer.from('3141592653589793238462643383279502884197169399375105820974944592', 'hex'),
  master_sk:  BigInt('29757020647961307431480504535336562678282505419141012933316116377660817309383'),
  child_index: 3141592653,
  child_sk: BigInt('25457201688850691947727629385191704516744796114925897962676248250929345014287')
}

const CASE2 = {
  seed: Buffer.from('0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00', 'hex'),
  master_sk:  BigInt('27580842291869792442942448775674722299803720648445448686099262467207037398656'),
  child_index: 4294967295,
  child_sk: BigInt('29358610794459428860402234341874281240803786294062035874021252734817515685787')
}

const CASE3 = {
  seed: Buffer.from('d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'hex'),
  master_sk:  BigInt('19022158461524446591288038168518313374041767046816487870552872741050760015818'),
  child_index: 42,
  child_sk: BigInt('31372231650479070279774297061823572166496564838472787488249775572789064611981')
}


describe('EIP2333 Key Generation', () => {
  jest.setTimeout(10000);
  describe('deriveMasterSk', () => {
    it('produces the correct master key for case 0', async () => {
      let result = Eip2333.deriveMasterSk(CASE0.seed);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE0.master_sk);
    });
    it('produces the correct master key for case 1', async () => {
      let result = Eip2333.deriveMasterSk(CASE1.seed);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE1.master_sk);
    });
    it('produces the correct master key for case 2', async () => {
      let result = Eip2333.deriveMasterSk(CASE2.seed);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE2.master_sk);
    });
    it('produces the correct master key for case 3', async () => {
      let result = Eip2333.deriveMasterSk(CASE3.seed);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE3.master_sk);
    });
    it('fails with insufficient seed size', async () => {
      let seed = Buffer.from('31415926535897932384626433832795028841971693993751058209', 'hex')
      expect(() => { Eip2333.deriveMasterSk(seed); }).toThrow();
    });
  });

  describe('deriveChildSk', () => {
    it('produces the correct child key for case 0', async () => {
      let result = Eip2333.deriveChildSk(bigIntToBuffer(CASE0.master_sk), CASE0.child_index);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE0.child_sk);
    });
    it('produces the correct child key for case 1', async () => {
      let result = Eip2333.deriveChildSk(bigIntToBuffer(CASE1.master_sk), CASE1.child_index);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE1.child_sk);
    });
    it('produces the correct child key for case 2', async () => {
      let result = Eip2333.deriveChildSk(bigIntToBuffer(CASE2.master_sk), CASE2.child_index);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE2.child_sk);
    });
    it('produces the correct child key for case 3', async () => {
      let result = Eip2333.deriveChildSk(bigIntToBuffer(CASE3.master_sk), CASE3.child_index);
      expect(BigInt(`0x${result.toString('hex')}`)).toEqual(CASE3.child_sk);
    });
  });

})
