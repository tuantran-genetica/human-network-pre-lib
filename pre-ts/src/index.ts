import { PreClient } from "./pre";
import {
  KeyPair,
  SecretKey,
  FirstLevelSymmetricKey,
  SecondLevelEncryptionResponse,
  PublicKey,
} from "./types";
import { G2Point, GTElement, BN254CurveWrapper } from "./crypto/bn254";
import { SecondLevelSymmetricKey } from "./types";
import { bytesToBase64 } from "./utils";
import { splitSecret } from "./shamir";
import { generateRandomScalar } from "./utils/keypair";
export interface IPreClient {
  // Generate a random secret key, then split it into n shares
  generateKeys(): Promise<Array<Uint8Array>>;
  encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse>;
  decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array>;
  storeShare(): void;
}

export interface IKeySplitter {
  generateShares(): Promise<Array<Uint8Array>>;
}

export class PreSdk implements IPreClient, IKeySplitter {
  preClient: PreClient;

  /// Paramteter for KeySplitter
  shareCount: number = 3; // number of shares
  threshold: number = 2; // minimum number of shares needed to reconstruct the secret

  constructor() {
    this.preClient = new PreClient();
  }

  generateRandomKeyPair(): KeyPair {
    const keyPair = this.preClient.generateRandomKeyPair();
    return keyPair;
  }

  /**
   * @deprecated This method is deprecated and will be removed in future versions. Use generateShares instead
   * Generate a random secret key, then split it into n shares
   * @returns {Promise<Array<Uint8Array>>} An array of Uint8Array shares
   * @throws {Error} If the key generation fails
   */
  async generateKeys(): Promise<Array<Uint8Array>> {
    const secretKey = this.preClient.generateRandomKeyPair().secretKey;
    const bytes = secretKey.toBytes();
    const shares = await splitSecret(bytes, 2, 3);
    return shares;
  }
  /**
   * Generate a random secret key, then split it into n shares
   * @returns {Promise<Array<Uint8Array>>} An array of Uint8Array shares
   * @throws {Error} If the key generation fails
   */
  async generateShares(): Promise<Array<Uint8Array>> {
    const secretKey = this.preClient.generateRandomKeyPair().secretKey;
    const bytes = secretKey.toBytes();
    const shares = await splitSecret(bytes, this.threshold, this.shareCount);
    return shares;
  }

  /** 
   * Encrypts the data using the secret key.
     Each time this method is called, a new random scalar(for symmetrical encryption) is generated to ensure that the encryption is unique.
   * @param secret The secret key to encrypt the data with
   * @param data The data to encrypt - should be serialized form of sensitive data
   * @returns {Promise<SecondLevelEncryptionResponse>} The encrypted data, which
      consists of the encrypted symmetric key and the encrypted data
   */
  async encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse> {
    const randomScalar = generateRandomScalar();
    const encryptedData = await this.preClient.secondLevelEncryption(
      secret,
      data,
      randomScalar
    );
    return encryptedData;
  }

  /**
   *
   * @param encryptedKey
   * @param encryptedData
   * @param secret
   * @returns
   */
  async decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array> {
    const decryptedData = await this.preClient.decryptFirstLevel(
      {
        encryptedKey,
        encryptedMessage: encryptedData,
      },
      secret
    );
    return decryptedData;
  }

  storeShare(): void {
    console.log("Storing share in PreSdk...");
    // super.storeShare();
    console.log("Share stored.");
  }
}

// Types for the PRE server interactions
export interface StoredData {
  reencryption_key: string; // Base64 encoded G2Affine point
  encrypted_key: {
    ephemeral_public_key: string;
    encrypted_key: string;
    nonce: string;
  };
  encrypted_data: Uint8Array;
}

export interface StoreRequest {
  reencryption_key: string; // Base64 encoded G2Point
  encrypted_key: {
    first: string; // Base64 encoded G1Point
    second: string; // Base64 encoded GTElement
  };
  encrypted_data: Array<number>;
  user_id: string;
}

export interface ProxyRequest {
  request_id: string;
}

export interface StoreResponse {
  status: string;
  id: string;
}

export interface RequestResponse {
  first_level_key: {
    first: GTElement; // Serialized GTElement
    second: GTElement; // Serialized GTElement
  };
  encrypted_data: Uint8Array;
}

export interface StoreShareRequest {
  shared_key: string; // Base64 encoded share
  public_key: string; // Base64 encoded public key
}

export interface GetShareResponse {
  data: {
    shared_key: string; // Base64 encoded share
    updated_at: string; // Timestamp of the last update
  };
}

export interface UploadFileRequest {
  file_content: string; // Base64 encoded file content
  file_type: string; // MIME type of the file
  file_name: string; // Name of the file
  file_size: number; // Size of the file in bytes
}

export interface UploadFileResponse {
  data: {
    errors: Array<string>;
    id: string;
    message: string;
    mime_type: string;
    name: string;
    size: number;
    status_code: number;
  };
}

export interface GetStoredFileResponse {
  id: string;
  name: string;
  size: number;
  mime_type: string;
  object_url: string;
  // owner_id: string;
  // crypto_info: {
  //   id: string;
  //   type: string;
  //   algorithm: string;
  //   timestamp: string;
  //   capsule: string;
  //   metadata: string;
  //   created_at: string;
  //   updated_at: string;
  // };
  created_at: string;
  updated_at: string;
}

export interface GetStoredFilesResponse {
  payload: {
    data: Array<GetStoredFileResponse>;
    next_page: number;
    page: number;
    size: number;
  };
  success: boolean;
}

export class ProxyClient {
  private baseUrl: string;

  private endpoints = {
    uploadKeys: "/upload-keys",
    uploadFile: "/upload-file",
    request: "/request",
    getSharedKey: "/shared-key",
    getUploadedFiles: "/uploaded-files",
    getUploadedFile: (fileID: string) => `/file-object/${fileID}`,
  };

  private headers = {
    "X-Organization-Id": "",
    Authorization: "",
  };

  constructor(
    baseUrl: string = "http://localhost:8080",
    organizationId: string = "",
    authToken: string = ""
  ) {
    this.baseUrl = baseUrl;
    this.headers["X-Organization-Id"] = organizationId;
    if (authToken) {
      this.headers["Authorization"] = `Bearer ${authToken}`;
    }
  }

  /// Store key share on the proxy server
  async uploadKey(share: Uint8Array, pubkey: PublicKey): Promise<void> {
    const request: StoreShareRequest = {
      shared_key: bytesToBase64(share),
      public_key: bytesToBase64(pubkey.toBytes()),
    };

    const response = await fetch(
      `${this.baseUrl}${this.endpoints.uploadKeys}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
        },
        body: JSON.stringify(request),
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store share request failed: ${error.error}`);
    }
  }

  async getKeyShare(): Promise<Uint8Array> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getSharedKey}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
        },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get key share request failed: ${error.error}`);
    }

    const result: GetShareResponse = await response.json();
    // Convert the base64 encoded string back to Uint8Array
    return Uint8Array.from(atob(result.data.shared_key), (c) =>
      c.charCodeAt(0)
    );
  }

  /**
   * Store encrypted data and re-encryption key on the proxy server
   * @param reencryptionKey The re-encryption key (G2Point)
   * @param encryptedKey The encrypted symmetric key
   * @param encryptedData The encrypted data
   * @param userId The user ID
   * @returns Promise with the store response
   */
  async store(
    reencryptionKey: G2Point,
    encryptedKey: SecondLevelSymmetricKey,
    encryptedData: Uint8Array,
    userId: string
  ): Promise<StoreResponse> {
    // Use btoa for base64 encoding of byte arrays
    const request: StoreRequest = {
      reencryption_key: btoa(
        String.fromCharCode(...BN254CurveWrapper.G2ToBytes(reencryptionKey))
      ),
      encrypted_key: {
        first: btoa(
          String.fromCharCode(
            ...BN254CurveWrapper.G1ToBytes(encryptedKey.first)
          )
        ),
        second: btoa(
          String.fromCharCode(
            ...BN254CurveWrapper.GTToBytes(encryptedKey.second)
          )
        ),
      },
      encrypted_data: Array.from(encryptedData),
      user_id: userId,
    };

    const response = await fetch(`${this.baseUrl}/store`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store request failed: ${error.error}`);
    }

    return response.json();
  }

  /**
   * Store encrypted data and re-encryption key on the proxy server
   * @param reencryptionKey The re-encryption key (G2Point)
   * @param encryptedKey The encrypted symmetric key
   * @param encryptedData The encrypted data
   * @param userId The user ID
   * @returns Promise with the store response
   */
  async storeFile(
    encryptedData: Uint8Array,
    filename?: string,
    customHeader: HeadersInit = {}
  ): Promise<StoreResponse> {
    const formDataRequest: FormData = new FormData();
    // Use btoa for base64 encoding of byte arrays
    // formDataRequest.append("file", new Blob([encryptedData]), "file");

    formDataRequest.append(
      "file",
      new Blob([encryptedData]),
      filename || Date.now().toString() + "_encrypted_file" + ".enc"
    );

    const response = await fetch(
      `${this.baseUrl}${this.endpoints.uploadFile}`,
      {
        method: "POST",
        headers: {
          ...this.headers,
          ...customHeader,
        },
        body: formDataRequest,
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store request failed: ${error.error}`);
    }

    const result: UploadFileResponse = await response.json();

    return {
      status: "success",
      id: result.data.id,
    };
  }

  async getStoredFile(
    fileID: string,
    customHeader: HeadersInit = {}
  ): Promise<GetStoredFileResponse> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getUploadedFile(fileID)}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
          ...customHeader,
        },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get stored file request failed: ${error.error}`);
    }

    const result: GetStoredFileResponse = await response.json();
    return {
      id: result.id,
      name: result.name,
      size: result.size,
      mime_type: result.mime_type,
      object_url: result.object_url,
      created_at: result.created_at,
      updated_at: result.updated_at,
    };
  }

  async getStoredFiles(
    page?: number,
    size?: number,
    customHeader: HeadersInit = {}
  ): Promise<GetStoredFilesResponse> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getUploadedFiles}?page=${page}&size=${size}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
          ...customHeader,
        },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get stored files request failed: ${error.error}`);
    }

    const result: GetStoredFilesResponse = await response.json();
    if (!result.success) {
      throw new Error("Failed to fetch stored files");
    }

    return result;
  }
}

export type {
  KeyPair,
  PublicKey,
  FirstLevelSymmetricKey,
  SecondLevelSymmetricKey,
  FirstLevelEncryptionResponse,
  SecondLevelEncryptionResponse,
} from "./types";
export * from "./crypto";
export * from "./shamir";
export * from "./utils";
