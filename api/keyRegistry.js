import fs from "fs";
import path from "path";
import crypto from "crypto";

const KEYS_DIR = path.join(process.cwd(), "keys");
const KEY_PATHS = {
  serverPublic: path.join(KEYS_DIR, "server_public.pem"),
  serverPrivate: path.join(KEYS_DIR, "server_private.pem"),
  clientPublic: path.join(KEYS_DIR, "client_public.pem"),
  clientPrivate: path.join(KEYS_DIR, "client_private.pem")
};

function ensureKeyFiles() {
  const allExist = Object.values(KEY_PATHS).every(p => fs.existsSync(p));
  if (allExist) {
    return;
  }

  fs.mkdirSync(KEYS_DIR, { recursive: true });

  // Server key pair (RSA-OAEP decryption)
  const serverPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  // Client key pair (RSA-PSS signing)
  const clientPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  fs.writeFileSync(KEY_PATHS.serverPublic, serverPair.publicKey);
  fs.writeFileSync(KEY_PATHS.serverPrivate, serverPair.privateKey);
  fs.writeFileSync(KEY_PATHS.clientPublic, clientPair.publicKey);
  fs.writeFileSync(KEY_PATHS.clientPrivate, clientPair.privateKey);

  console.warn("[keyRegistry] Generated demo keys in ./keys. Use kid=server-key-1.");
  console.warn("[keyRegistry] Client private key (use in frontend):\n", clientPair.privateKey);
}

function loadKeys() {
  ensureKeyFiles();

  return {
    serverPublicKey: fs.readFileSync(KEY_PATHS.serverPublic, "utf8"),
    serverPrivateKey: fs.readFileSync(KEY_PATHS.serverPrivate, "utf8"),
    clientPublicKey: fs.readFileSync(KEY_PATHS.clientPublic, "utf8"),
    clientPrivateKey: fs.readFileSync(KEY_PATHS.clientPrivate, "utf8")
  };
}

const keys = loadKeys();

// In-memory registry keyed by kid. Adjust/add entries for rotation or multiple keys.
const registry = {
  "server-key-1": {
    kid: "server-key-1",
    publicKey: keys.serverPublicKey,
    privateKey: keys.serverPrivateKey,
    clientPublicKey: keys.clientPublicKey
  }
};

export function getKeyById(kid) {
  const key = registry[kid];
  if (!key) {
    throw new Error("UNKNOWN_KID");
  }
  return key;
}
