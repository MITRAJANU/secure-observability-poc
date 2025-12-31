import amqp from "amqplib";
import crypto from "crypto";
import { gzipSync } from "zlib";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import dotenv from "dotenv";
import { storeRequest, storeResponse } from "./persistence.js";
dotenv.config();

const s3 = new S3Client({ region: process.env.AWS_REGION });
const BUCKET = process.env.AUDIT_BUCKET || "test-audit-1768";

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);

  const sorted = Object.keys(value)
    .sort()
    .reduce((acc, key) => {
      acc[key] = canonicalize(value[key]);
      return acc;
    }, {});

  return sorted;
}

(async () => {
  const conn = await amqp.connect(process.env.RABBIT_URL);
  const ch = await conn.createChannel();
  await ch.assertQueue("audit_logs", { durable: true });

  ch.consume("audit_logs", async msg => {
    const event = JSON.parse(msg.content.toString());

    try {
      // 1) Canonicalize JSON for stable hashing
      const canonicalEvent = canonicalize(event);
      const canonicalString = JSON.stringify(canonicalEvent);

      // 2) Compute hashes
      const base = {
        ...event,
        canonical_hash: sha256Hex(Buffer.from(canonicalString))
      };

      if (event.body?.encryptedPayload) {
        base.payload_hash = sha256Hex(
          Buffer.from(event.body.encryptedPayload, "base64")
        );
      }
      if (event.signature) {
        base.signature_hash = sha256Hex(
          Buffer.from(event.signature, "base64")
        );
      }

      // 3) Route persistence to Mongo
      if (event.type === "PERSIST_REQUEST") {
        await storeRequest(base);
      } else if (event.type === "PERSIST_RESPONSE") {
        await storeResponse(base);
      }

      // 4) Compress and store audit to S3
      const requestId = event.request_id || event.requestId || "unknown";
      console.log("Storing audit event to S3:", event.type, requestId);
      const key = `audit/${event.type}/${requestId}.json.gz`;
      const gzBody = gzipSync(Buffer.from(JSON.stringify(base)));

      await s3.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: key,
        Body: gzBody,
        ContentType: "application/json",
        ContentEncoding: "gzip"
      }));
    } catch (err) {
      console.error("[worker] Failed to handle event", err, event);
    } finally {
      ch.ack(msg);
    }
  });
})();
