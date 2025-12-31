const encoder = new TextEncoder();

export type HybridEncryptedPayload = {
  encryptedPayload: string;
  encryptedKey: string;
  iv: string;
  signature: string;
};

export type SecureEnvelope = HybridEncryptedPayload & {
  kid: string;
  nonce: string;
  timestamp: number;
};

/* ---------- Helpers ---------- */

function base64Encode(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(b64: string): ArrayBuffer {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

function generateNonce(bytes = 16) {
  return base64Encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/* ---------- Key Import ---------- */

export async function importRsaPublicKey(pem: string, usage: KeyUsage[]) {
  const pemBody = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  return crypto.subtle.importKey(
    'spki',
    base64Decode(pemBody),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    usage
  );
}

export async function importRsaPublicKeyForVerify(pem: string) {
  const pemBody = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  return crypto.subtle.importKey(
    'spki',
    base64Decode(pemBody),
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

export async function importRsaPrivateKey(pem: string, usage: KeyUsage[]) {
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');

  return crypto.subtle.importKey(
    'pkcs8',
    base64Decode(pemBody),
    {
      name: 'RSA-PSS',
      hash: 'SHA-256'
    },
    false,
    usage
  );
}

/* ---------- Core Encryption ---------- */

export async function encryptHybrid(
  payload: unknown,
  serverPublicKeyPem: string,
  clientPrivateKeyPem: string
): Promise<HybridEncryptedPayload> {
  // 1. Generate AES key for the payload
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );

  // 2. Encrypt payload with AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedPayload = encoder.encode(JSON.stringify(payload));

  const encryptedPayload = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encodedPayload
  );

  // 3. Encrypt AES key with server public key
  const serverPublicKey = await importRsaPublicKey(serverPublicKeyPem, [
    'encrypt'
  ]);

  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);

  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    serverPublicKey,
    rawAesKey
  );

  // 4. Sign hash of encrypted payload
  const payloadHash = await crypto.subtle.digest(
    'SHA-256',
    encryptedPayload
  );

  const clientPrivateKey = await importRsaPrivateKey(
    clientPrivateKeyPem,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    clientPrivateKey,
    payloadHash
  );

  // 5. Return transport-safe payload
  return {
    encryptedPayload: base64Encode(encryptedPayload),
    encryptedKey: base64Encode(encryptedKey),
    iv: base64Encode(iv),
    signature: base64Encode(signature)
  };
}

export async function encryptHybridWithNonce(
  payload: unknown,
  serverPublicKeyPem: string,
  clientPrivateKeyPem: string,
  kid: string
): Promise<SecureEnvelope> {
  if (!kid) {
    throw new Error('kid is required for the secure envelope');
  }

  const encrypted = await encryptHybrid(
    payload,
    serverPublicKeyPem,
    clientPrivateKeyPem
  );

  return {
    ...encrypted,
    kid,
    nonce: generateNonce(),
    timestamp: Date.now()
  };
}

export async function verifyResponseSignature(
  body: Record<string, unknown>,
  signatureB64: string,
  serverPublicKeyPem: string
): Promise<boolean> {
  const serverKey = await importRsaPublicKeyForVerify(serverPublicKeyPem);
  const canonical = {
    status: body.status,
    request_id: body.request_id,
    responded_at: body.responded_at
  };
  const encoded = encoder.encode(JSON.stringify(canonical));
  const signature = base64Decode(signatureB64);

  return crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    serverKey,
    signature,
    encoded
  );
}
