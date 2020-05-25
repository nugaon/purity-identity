import EthCrypto, { Encrypted } from "eth-crypto";
import { hexToBytes } from "web3-utils"

export type IdentityType = {
  privateKey: string,
  publicKey: string,
  address: string
}

export type SerializedPublicKey = {
  pubKeyPrefix: boolean,
  pubKey: Array<number>
}

/**
 * Used for Premium Content's encryption/decryption and contract store for pubkeys
**/
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

  public getSerializedPublicKey(): serializedPublicKey {
    return serializePublicKey(
      this.identity.publicKey
    )
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

/**
 * For contract store, the public key has to be serialized and compressed
 * as much as possible
**/
export function serializePublicKey(
  pubKey: string
): serializedPublicKey {
  const compressedPubKey = compressPublicKey(pubKey)
  const userPubKeyPart1: boolean = serializeCompressedPublicKeyPrefix(
    compressedPubKey
  );
  const userPubKeyPart2: Array<number> = serializeCompressedPublicKey(
    compressedPubKey
  )
  return {
    pubKeyPrefix: userPubKeyPart1,
    pubKey: userPubKeyPart2
  }
}

/**
 * Get decompressed public key string from contract store
**/
export function unserializePublicKey(
  pubKeyPrefix: boolean,
  pubKey: string
): string {
  return EthCrypto.publicKey.decompress(
    decompressPublicKeyPrefix(pubKeyPrefix) + pubKey.substr(2, pubKey.length)
  )
}

/**
 * Gives back the compressed public key's first two characters in a boolean,
 * because it only can be "02" or "03"
 * returns true if "03"
**/
function serializeCompressedPublicKeyPrefix(compressedPubKey: string): boolean {
  const firstTwoChars: string = compressedPubKey.substr(0, 2)
  if(firstTwoChars === "03") {
    return true
  }
  if(firstTwoChars === "02") {
    return false
  }
  // else
  throw new Error(`The first two characters of the ${compressedPubKey}`
    + ` compressed public key are not 02 or 03`)
}

/**
 * Serializes the public key's bigger part (without prefix)
**/
function serializeCompressedPublicKey(
  compressedPubKey: string
): Array<number> {
  let userPubKeyPart2: string = compressedPubKey.substr(
    2,
    compressedPubKey.length
  );
  return hexToBytes("0x" + userPubKeyPart2);
}

function decompressPublicKeyPrefix(prefix: boolean): string {
  return prefix ? "03" : "02";
}
