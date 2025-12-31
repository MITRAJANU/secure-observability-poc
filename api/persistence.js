import crypto from "crypto";
import { MongoClient } from "mongodb";

const {
  MONGO_URI,
  MONGO_DB = "secure_observability",
  REPLAY_TARGET_URL = "http://localhost:3000/secure"
} = process.env;

let mongoClient;
let mongoDb;
let initialized = false;

async function ensureInit() {
  if (initialized) return;

  if (MONGO_URI) {
    mongoClient = new MongoClient(MONGO_URI);
    await mongoClient.connect();
    mongoDb = mongoClient.db(MONGO_DB);
    await mongoDb
      .collection("secure_requests")
      .createIndex({ received_at: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 7 });
    await mongoDb
      .collection("secure_responses")
      .createIndex({ responded_at: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 7 });
    await mongoDb.collection("replay_runs").createIndex({ replayed_at: 1 });
  }

  initialized = true;
}

export async function recordRequest(doc) {
  try {
    await ensureInit();
    if (mongoDb) {
      await mongoDb.collection("secure_requests").insertOne(doc);
    }
  } catch (err) {
    console.error("[observability] Failed to record request", err);
  }
}

export async function recordResponse(doc) {
  try {
    await ensureInit();
    if (mongoDb) {
      await mongoDb.collection("secure_responses").insertOne(doc);
    }
  } catch (err) {
    console.error("[observability] Failed to record response", err);
  }
}

export async function listRequests(limit = 50) {
  await ensureInit();
  if (!mongoDb) return [];
  return mongoDb
    .collection("secure_requests")
    .find({})
    .sort({ received_at: -1 })
    .limit(limit)
    .toArray();
}

export async function listResponses(limit = 50) {
  await ensureInit();
  if (!mongoDb) return [];
  return mongoDb
    .collection("secure_responses")
    .find({})
    .sort({ responded_at: -1 })
    .limit(limit)
    .toArray();
}

export async function replayRequest(request_id, targetUrl = REPLAY_TARGET_URL) {
  await ensureInit();
  if (!mongoDb) {
    throw new Error("MONGO_REQUIRED_FOR_REPLAY");
  }

  const doc = await mongoDb
    .collection("secure_requests")
    .findOne({ request_id });
  if (!doc) {
    throw new Error("REQUEST_NOT_FOUND");
  }

  const envelope = {
    ...doc.body,
    nonce: crypto.randomUUID(),
    timestamp: Date.now()
  };

  const res = await fetch(targetUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope)
  });

  const responseBody = await res.json().catch(() => null);

  await mongoDb.collection("replay_runs").insertOne({
    original_request_id: request_id,
    replay_request_id: envelope.request_id || crypto.randomUUID(),
    targetUrl,
    response_status: res.status,
    response_body: responseBody,
    replayed_at: new Date()
  });

  return { status: res.status, body: responseBody };
}
