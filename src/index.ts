import EthCrypto, { Encrypted } from "eth-crypto";
import { hexToBytes } from "web3-utils"

export type IdentityType = {
  privateKey: string,
  publicKey: string,
  address: string
}

/// @dev Used for Premium Content's encryption/decryption
export class IdenityService {

  private identity: IdentityType;

  constructor(identity: IdentityType | null = null) {
    if(identity) {
      this.identity = identity
    } else {
      this.identity = createIdentity()
    }
  }

  public async encryptData(data: string): Promise<Encrypted> {
    return encryptData(
      this.identity.publicKey,
      data
    );
  }

  public async decryptEncryptedData(encryptedData: Encrypted): Promise<string> {
    return decryptData(this.identity.privateKey, encryptedData);
  }

  public getCompressedPublicKey(): string {
    return compressPublicKey(this.identity.publicKey);
  }

  public getDecompressedPublicKey(): string {
    return this.identity.publicKey;
  }
}

// PUBLIC FUNCTIONS

export function createIdentity(): IdentityType {
  return EthCrypto.createIdentity();
}

export function encryptData(pubKey: string, data: string): Promise<Encrypted> {
  return EthCrypto.encryptWithPublicKey(
    pubKey,
    data // message
  );
}

export function decryptData(privKey: string, encryptedData: Encrypted): Promise<string> {
  return EthCrypto.decryptWithPrivateKey(privKey, encryptedData);
}

export function compressPublicKey(pubKey: string): string {
  return EthCrypto.publicKey.compress(pubKey);
}

/// @dev Gives back the user's compressed public key first two characters in a boolean,
/// because it only can be "02" or "03"
/// returns true if "03"
export function compressPublicKeyPrefix(pubKey: string): boolean {
  const firstTwoChars: string = pubKey.substr(0, 2)
  if(firstTwoChars === "03") {
    return true
  }
  if(firstTwoChars === "02") {
    return false
  }
  // else
  throw new Error(`The first two characters of the ${pubKey}`
    + ` compressed public key are not 02 or 03`)
}

export function decompressPublicKeyPrefix(prefix: boolean): string {
  return prefix ? "03" : "02";
}

/// @dev at "subscribe" action the user can upload his key.
export function serializePublicKey(
  pubKey: string
): { pubKeyPrefix: boolean, pubKey: Array<number> } {
  let userPubKeyPart1: boolean = compressPublicKeyPrefix(pubKey);
  let userPubKeyPart2: string = pubKey.substr(2, pubKey.length);
  const userPubKey2 = hexToBytes("0x" + userPubKeyPart2);
  return {
    pubKeyPrefix: userPubKeyPart1,
    pubKey: userPubKey2
  }
}

/// @dev get compressed public key string from contract store
export function unserializePublicKey(
  pubKeyPrefix: boolean,
  pubKey: string
): string {
  return decompressPublicKeyPrefix(pubKeyPrefix) + pubKey.substr(2, pubKey.length);
}
