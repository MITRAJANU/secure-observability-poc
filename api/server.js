import express from "express";
import crypto from "crypto";
import cors from "cors";
import { emitAudit } from "./auditEmitter.js";
// import { checkNonce } from "./nonceStore.js";
import { getKeyById } from "./keyRegistry.js";
import { computeAuditHashes, verifyAndDecrypt, signResponse } from "./cypto.js";
import { listRequests, listResponses, replayRequest } from "./persistence.js";

const app = express();
app.use(express.json());
app.use(cors());

const MAX_SKEW_MS = 5 * 60 * 1000;

app.post("/secure", async (req, res) => {
  const request_id = crypto.randomUUID(); // SERVER GENERATED
  const received_at = Date.now();

  const { nonce, timestamp, kid } = req.body;

  /* ============================
     1Л,?ГЯЬ Envelope validation
     ============================ */

  if (!nonce || !timestamp || !kid) {
    return res.status(400).json({ error: "INVALID_ENVELOPE" });
  }

  if (Math.abs(received_at - timestamp) > MAX_SKEW_MS) {
    return res.status(401).json({ error: "REQUEST_EXPIRED" });
  }

  /* ============================
     2Л,?ГЯЬ Replay protection
     ============================ */

//   try {
//     await checkNonce("default-client", nonce);
//   } catch {
//     return res.status(409).json({ error: "REPLAY_DETECTED" });
//   }

  /* ============================
     3Л,?ГЯЬ Audit request (NO decrypt)
     ============================ */

  const auditHashes = computeAuditHashes(req.body);

  await emitAudit({
    type: "REQUEST",
    request_id,
    kid,
    nonce,
    timestamp,
    received_at,
    ...auditHashes
  });

  /* ============================
     4Л,?ГЯЬ Crypto verify + decrypt
     ============================ */

  let decrypted;
  try {
    const key = getKeyById(kid);
    decrypted = verifyAndDecrypt(req.body, key);
  } catch (err) {
    await emitAudit({
      type: "PERSIST_REQUEST",
      request_id,
      kid,
      nonce,
      timestamp,
      received_at,
      status: "CRYPTO_ERROR",
      error_code: err.message,
      audit: auditHashes,
      body: req.body
    });

    await emitAudit({
      type: "ERROR",
      request_id,
      error_code: err.message
    });

    return res.status(401).json({
      error: "CRYPTO_VALIDATION_FAILED",
      request_id
    });
  }

  /* ============================
     5Л,?ГЯЬ Business logic
     ============================ */

  const responded_at = Date.now();
  const responsePayload = {
    status: "OK",
    request_id,
    responded_at
  };

  const key = getKeyById(kid);
  const signature = signResponse(responsePayload, key);

  const response = {
    ...responsePayload,
    signature
  };

  await emitAudit({
    type: "PERSIST_REQUEST",
    request_id,
    kid,
    nonce,
    timestamp,
    received_at,
    status: "OK",
    audit: auditHashes,
    body: req.body,
    decrypted_payload: decrypted
  });

  /* ============================
     6Л,?ГЯЬ Audit response
     ============================ */

  const response_hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(response))
    .digest("hex");

  const latency_ms = responded_at - received_at;

  await emitAudit({
    type: "RESPONSE",
    request_id,
    response_hash,
    status: 200,
    responded_at
  });

  await emitAudit({
    type: "PERSIST_RESPONSE",
    request_id,
    kid,
    responded_at,
    status: 200,
    response_hash,
    latency_ms,
    signature
  });

  res.json(response);
});

/* ============================
   Admin Debug API
   ============================ */

app.get("/admin/requests", async (_req, res) => {
  const docs = await listRequests(100);
  res.json(docs);
});

app.get("/admin/responses", async (_req, res) => {
  const docs = await listResponses(100);
  res.json(docs);
});

app.post("/admin/replay/:requestId", async (req, res) => {
  try {
    const result = await replayRequest(
      req.params.requestId,
      req.body?.targetUrl
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(3000, () => {
  console.log("Secure API running on port 3000");
});
