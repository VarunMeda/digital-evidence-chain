import crypto from "node:crypto";
import { MongoClient } from "mongodb";
import pool from "../db/mysql";
import { ARTIFACT_TYPES, EXTRACTION_STATUSES, validateArtifactInput, type ArtifactInput } from "./artifactValidation";

const mongoUri = process.env.MONGO_URI;
const mongoDb = process.env.MONGO_DB || "digital_evidence_chain";
const artifactCollection = "forensic_artifacts";

export class ArtifactPersistenceError extends Error { constructor(public readonly status: number, message: string) { super(message); } }

async function withMongo<T>(operation: (collection: ReturnType<import("mongodb").Db["collection"]>) => Promise<T>): Promise<T> {
  if (!mongoUri) throw new ArtifactPersistenceError(503, "MongoDB artifact storage is not configured");
  const client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 1500, connectTimeoutMS: 1500 });
  try {
    await client.connect();
    const db = client.db(mongoDb);
    const validator = { $jsonSchema: { bsonType: "object", required: ["artifact_id", "evidence_id", "artifact_type", "fields", "parser", "observed_at", "extraction_status", "provenance", "idempotency_key"], properties: { artifact_id: { bsonType: "string" }, evidence_id: { bsonType: "int" }, artifact_type: { enum: [...ARTIFACT_TYPES] }, fields: { bsonType: "object" }, parser: { bsonType: "object", required: ["name", "version"] }, observed_at: { bsonType: "date" }, extraction_status: { enum: [...EXTRACTION_STATUSES] }, provenance: { bsonType: "object", required: ["source", "input_sha256", "method"] }, idempotency_key: { bsonType: "string" } } } };
    const collectionExists = await db.listCollections({ name: artifactCollection }, { nameOnly: true }).hasNext();
    if (!collectionExists) await db.createCollection(artifactCollection, { validator, validationLevel: "strict", validationAction: "error" });
    else await db.command({ collMod: artifactCollection, validator, validationLevel: "strict", validationAction: "error" }).catch((error) => console.warn("MongoDB collection validator was not updated; application validation remains active", error instanceof Error ? error.message : "unknown error"));
    const collection = db.collection(artifactCollection);
    await Promise.all([collection.createIndex({ evidence_id: 1, observed_at: -1, artifact_id: 1 }), collection.createIndex({ artifact_type: 1, extraction_status: 1, observed_at: -1 }), collection.createIndex({ idempotency_key: 1 }, { unique: true })]);
    return await operation(collection);
  } catch (error) {
    if (error instanceof ArtifactPersistenceError) throw error;
    throw new ArtifactPersistenceError(503, "MongoDB artifact storage is unavailable");
  } finally { await client.close().catch(() => undefined); }
}

export async function persistArtifact(body: unknown, createdBy: number) {
  let artifact: ArtifactInput;
  try { artifact = validateArtifactInput(body); } catch (error) { throw new ArtifactPersistenceError(400, error instanceof Error ? error.message : "Invalid artifact payload"); }
  const [evidenceRows] = await pool.execute<any[]>("SELECT evidence_id, evidence_code, original_sha256, original_filename FROM evidence WHERE evidence_id=? LIMIT 1", [artifact.evidence_id]);
  if (!evidenceRows.length) throw new ArtifactPersistenceError(404, "Referenced evidence record not found");
  if (evidenceRows[0].original_sha256.toLowerCase() !== artifact.provenance.input_sha256) throw new ArtifactPersistenceError(409, "Artifact provenance hash does not match the registered evidence");
  const document = { artifact_id: crypto.randomUUID(), evidence_id: artifact.evidence_id, evidence_code: evidenceRows[0].evidence_code, artifact_type: artifact.artifact_type, source_filename: artifact.source_filename || evidenceRows[0].original_filename, fields: artifact.fields, parser: artifact.parser, observed_at: artifact.observed_at, extraction_status: artifact.extraction_status, error: artifact.error, provenance: { ...artifact.provenance, evidence_sha256: evidenceRows[0].original_sha256.toLowerCase() }, idempotency_key: artifact.idempotency_key, created_by: createdBy, created_at: new Date() };
  return withMongo(async (collection) => {
    try { await collection.insertOne(document); return { document, created: true }; }
    catch (error: any) {
      if (error?.code !== 11000) throw error;
      const existing = await collection.findOne({ idempotency_key: artifact.idempotency_key }, { projection: { _id: 0 } });
      if (!existing) throw error;
      return { document: existing, created: false };
    }
  });
}
