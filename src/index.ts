import EthCrypto, { Encrypted } from "eth-crypto";

export type IdentityType = {
  privateKey: string,
  publicKey: string,
  address: string
}

/// @dev Used for Premium Content's encryption/decription
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

export function encryptData(publicKey: string, data: string): Promise<Encrypted> {
  return EthCrypto.encryptWithPublicKey(
    publicKey,
    data // message
  );
}

export function decryptData(privateKey: string, encryptedData: Encrypted): Promise<string> {
  return EthCrypto.decryptWithPrivateKey(privateKey, encryptedData);
}

export function compressPublicKey(publicKey: string): string {
  return EthCrypto.publicKey.compress(publicKey);
}
