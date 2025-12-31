import { MongoClient } from "mongodb";
import dotenv from "dotenv";
dotenv.config();
const {
  MONGO_URI,
  MONGO_DB = "secure_observability"
} = process.env;

let mongoClient;
let mongoDb;
let initialized = false;

async function ensureInit() {
  if (initialized) return;
  if (!MONGO_URI) {
    throw new Error("MONGO_URI not set");
  }

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

  initialized = true;
}

export async function storeRequest(doc) {
  await ensureInit();
  await mongoDb.collection("secure_requests").insertOne(doc);
}

export async function storeResponse(doc) {
  await ensureInit();
  await mongoDb.collection("secure_responses").insertOne(doc);
}
