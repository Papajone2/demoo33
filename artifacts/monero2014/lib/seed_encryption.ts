
const AES_KEY_BYTES = 32;
const AES_NONCE_BYTES = 12;
const AES_TAG_BYTES = 16;

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwvpksYCXg1bTTmj/0f9D
+XYvcaFDXaq5x58cHZCdAkQ5TgjDcikvQFE4cqCsKqWyetCk1SYb2JuNaMkdOY5i
0kSztnQxSNP1Jdgeby8T9m+5+pyzYZEML8Gi4tDbPD0aDIXxBSWhLQJG0+5KaAGO
QHvsqaC3uwV0b8CB9Worgg6KUEHAWe0Rr3rTJjIDmu+/gZlftNObmqqq6ywbA7rA
m+wZLztRPttCwLzlLo+AlUN2G8FpGPc/l4c0I8UEwUr1qX9m1IqBZ7Orr9OtK79h
4NqBYA7McSS70cIM3/zjhiXvWPog9gW0vi99ZzDYQR4NoPxV59Eh7QP/jmBwsEdV
TlkmRQU43QdAkp27lOurHwLbN6fBjso0/sEHjV5yr+OC606pEys3O9tQYV2aWdo6
UyEKEalU/DLvnHt3j0alzsf/7zFdNes9nk0NLeFi8kPilSfsIi9iH/aglBrjexcZ
5z/eELEeWewXBx8mYX44XCD3G851XLJSYQSMbuIiGnvLAgMBAAE=
-----END PUBLIC KEY-----`;

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function toBase64(data: Uint8Array): string {
  let binary = "";

  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }

  return btoa(binary);
}

async function importPublicKey(): Promise<CryptoKey> {
  const keyData = pemToArrayBuffer(PUBLIC_KEY_PEM);

  return await crypto.subtle.importKey(
    "spki",
    keyData,
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" }
    },
    false,
    ["encrypt"]
  );
}

export async function encryptWalletBackup(walletBackup: string) {
  // Generate a fresh random AES-256 key.
  const aesKeyBytes = crypto.getRandomValues(
    new Uint8Array(AES_KEY_BYTES)
  );

  // Import the raw AES key for AES-GCM encryption.
  const aesCryptoKey = await crypto.subtle.importKey(
    "raw",
    aesKeyBytes,
    {
      name: "AES-GCM"
    },
    false,
    ["encrypt"]
  );

  // Generate a fresh 12-byte nonce.
  const nonce = crypto.getRandomValues(
    new Uint8Array(AES_NONCE_BYTES)
  );

  const plaintext = new TextEncoder().encode(walletBackup);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      tagLength: AES_TAG_BYTES * 8
    },
    aesCryptoKey,
    plaintext
  );

  // Encrypt the AES key using RSA-OAEP with SHA-256.
  const publicKey = await importPublicKey();

  const encryptedAesKey = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    aesKeyBytes
  );

  // C++ compatible layout:
  // [ nonce ][ ciphertext ][ authentication tag ]
  const encryptedBackup = new Uint8Array(
    nonce.length + encrypted.byteLength
  );

  encryptedBackup.set(nonce, 0);
  encryptedBackup.set(
    new Uint8Array(encrypted),
    nonce.length
  );

  return {
    encrypted_backup: toBase64(encryptedBackup),
    encrypted_aes_key: toBase64(
      new Uint8Array(encryptedAesKey)
    )
  };
}
