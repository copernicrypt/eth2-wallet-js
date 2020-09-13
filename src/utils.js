import crypto from 'crypto';
import { toBufferLE, toBufferBE } from "bigint-buffer";
import { types as SSZ_TYPES} from "@chainsafe/lodestar-types/lib/ssz/presets/mainnet";
import * as CONSTANTS from './constants';

export function getSigningRoot(depositData, forkVersion) {
  const domainWrappedObject = {
      objectRoot: SSZ_TYPES.DepositMessage.hashTreeRoot(depositData),
      domain: getDomain(forkVersion),
  };
  return SSZ_TYPES.SigningData.hashTreeRoot(domainWrappedObject);
}

export function getDomain(forkVersion, domainType=CONSTANTS.DomainType.DEPOSIT, genesisValidatorRoot=CONSTANTS.ZERO_HASH) {
  const forkDataRoot = getForkDataRoot(forkVersion, genesisValidatorRoot);
  return Buffer.concat([intToBytes(BigInt(domainType), 4), Uint8Array.from(forkDataRoot).slice(0, 28)]);
}

export function getDepositDataRoot(depositData) {
  return SSZ_TYPES.DepositData.hashTreeRoot(depositData);
}

function getForkDataRoot(currentVersion, genesisValidatorsRoot) {
  const forkData = {
    currentVersion,
    genesisValidatorsRoot,
  };
  return SSZ_TYPES.ForkData.hashTreeRoot(forkData);
}

export function intToBytes(value, length, endian='le') {
  if (endian === "le") {
    return toBufferLE(value, length);
  } else if (endian === "be") {
    return toBufferBE(value, length);
  }
  throw new Error("endian must be either 'le' or 'be'");
}
