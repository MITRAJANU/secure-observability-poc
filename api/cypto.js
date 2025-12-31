import crypto from "crypto";

/* ================================
   Helpers
   ================================ */

function base64ToBuffer(b64) {
  return Buffer.from(b64, "base64");
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

/* ================================
   Signature verification
   ================================ */

function verifySignature(
  {
    encryptedPayload,
    signature
  },
  keyMaterial
) {
  const publicKey = keyMaterial.clientPublicKey;
  if (!publicKey) {
    throw new Error("MISSING_CLIENT_PUBLIC_KEY");
  }

  const payloadBuffer = base64ToBuffer(encryptedPayload);
  const payloadHash = sha256(payloadBuffer);

  const isValid = crypto.verify(
    "sha256",
    payloadHash,
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    },
    base64ToBuffer(signature)
  );

  if (!isValid) {
    throw new Error("INVALID_SIGNATURE");
  }
}

/* ================================
   Hybrid decryption
   ================================ */

function decryptPayload(
  {
    encryptedPayload,
    encryptedKey,
    iv
  },
  keyMaterial
) {
  const privateKey = keyMaterial.privateKey;
  if (!privateKey) {
    throw new Error("MISSING_SERVER_PRIVATE_KEY");
  }

  /* 1Л,?ГЯЬ Decrypt AES key using RSA-OAEP */
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    base64ToBuffer(encryptedKey)
  );

  /* 2Л,?ГЯЬ Decrypt payload using AES-GCM */
  const payloadBuffer = base64ToBuffer(encryptedPayload);
  const tagLength = 16;
  if (payloadBuffer.length < tagLength) {
    throw new Error("INVALID_PAYLOAD");
  }

  const authTag = payloadBuffer.subarray(payloadBuffer.length - tagLength);
  const ciphertext = payloadBuffer.subarray(0, payloadBuffer.length - tagLength);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    aesKey,
    base64ToBuffer(iv)
  );
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]).toString("utf8");

  return JSON.parse(decrypted);
}

/* ================================
   Full verification pipeline
   ================================ */

export function verifyAndDecrypt(body, keyMaterial = {}) {
  /*
    Validation order is CRITICAL:
    1. Signature
    2. Decryption
  */

  verifySignature(body, keyMaterial);

  const decryptedPayload = decryptPayload(body, keyMaterial);

  return decryptedPayload;
}

export function signResponse(body, keyMaterial = {}) {
  const privateKey = keyMaterial.privateKey;
  if (!privateKey) {
    throw new Error("MISSING_SERVER_PRIVATE_KEY");
  }

  const payload = Buffer.from(JSON.stringify(body));
  const signature = crypto.sign(
    "sha256",
    payload,
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    }
  );

  return signature.toString("base64");
}

/* ================================
   Hashes for observability
   ================================ */

export function computeAuditHashes(body) {
  return {
    payload_hash: sha256(base64ToBuffer(body.encryptedPayload)).toString("hex"),
    key_hash: sha256(base64ToBuffer(body.encryptedKey)).toString("hex"),
    signature_hash: sha256(base64ToBuffer(body.signature)).toString("hex")
  };
}
