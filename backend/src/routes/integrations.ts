import { Router } from "express";
import { MongoClient } from "mongodb";
import pool from "../db/mysql";
import { requireAuth, requireRoles } from "../middleware/auth";
import { ARTIFACT_TYPES, EXTRACTION_STATUSES } from "../services/artifactValidation";
import { getNeo4jSettings, verifyNeo4jConnection } from "../services/neo4j";
import { getLastNeo4jSync, Neo4jGraphNotFoundError, readGraph, syncNeo4jGraph } from "../services/neo4jGraph";
import { ArtifactPersistenceError, persistArtifact } from "../services/artifactPersistence";

const router = Router();
router.use(requireAuth);
const mongoUri = process.env.MONGO_URI;
const mongoDb = process.env.MONGO_DB || "digital_evidence_chain";
const artifactCollection = "forensic_artifacts";

function neo4jFailure(error: unknown): { status: "authentication_failed" | "connectivity_failed" | "query_failed"; error: string } {
  const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code) : "";
  if (code.startsWith("Neo.ClientError.Security") || /authentication|unauthorized|credentials/i.test(error instanceof Error ? error.message : "")) return { status: "authentication_failed", error: "Neo4j rejected the configured credentials" };
  if (/ServiceUnavailable|SessionExpired|Network|Connection|ECONNREFUSED|connectivity/i.test(code) || /ServiceUnavailable|SessionExpired|ECONNREFUSED|connectivity|connection/i.test(error instanceof Error ? error.message : "")) return { status: "connectivity_failed", error: "Neo4j could not be reached at the configured URI" };
  return { status: "query_failed", error: "Neo4j health query failed" };
}

router.get("/neo4j-health", async (_req, res) => {
  const configured = getNeo4jSettings();
  if (!configured.settings) return res.status(503).json({ service: "neo4j", status: "configuration_incomplete", missing: configured.missing });
  try { return res.json(await verifyNeo4jConnection()); }
  catch (error) { const failure = neo4jFailure(error); console.error("Neo4j health check failed", { name: error instanceof Error ? error.name : "UnknownError", status: failure.status }); return res.status(503).json({ service: "neo4j", ...failure }); }
});

router.get("/neo4j-status", async (_req, res) => {
  const configured = getNeo4jSettings();
  if (!configured.settings) return res.status(503).json({ service: "neo4j", status: "configuration_incomplete", missing: configured.missing, last_sync: getLastNeo4jSync() });
  try { return res.json({ ...(await verifyNeo4jConnection()), last_sync: getLastNeo4jSync() }); }
  catch (error) { const failure = neo4jFailure(error); console.error("Neo4j status check failed", { name: error instanceof Error ? error.name : "UnknownError", status: failure.status }); return res.status(503).json({ service: "neo4j", ...failure, last_sync: getLastNeo4jSync() }); }
});

router.post("/neo4j/sync", requireRoles("ADMIN"), async (_req, res) => {
  try { return res.json({ status: "completed", sync: await syncNeo4jGraph() }); }
  catch (error) { console.error("Neo4j graph synchronization failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(503).json({ service: "neo4j", status: "unavailable", error: "Neo4j graph synchronization failed; no source data was modified" }); }
});

async function withMongo<T>(operation: (collection: ReturnType<import("mongodb").Db["collection"]>) => Promise<T>): Promise<T> {
  if (!mongoUri) throw new Error("MongoDB is not configured");
  const client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 1500, connectTimeoutMS: 1500 });
  try {
    await client.connect();
    const db = client.db(mongoDb);
    const validator = { $jsonSchema: { bsonType: "object", required: ["artifact_id", "evidence_id", "artifact_type", "fields", "parser", "observed_at", "extraction_status", "provenance", "idempotency_key"], properties: { artifact_id: { bsonType: "string" }, evidence_id: { bsonType: "int" }, artifact_type: { enum: [...ARTIFACT_TYPES] }, fields: { bsonType: "object" }, parser: { bsonType: "object", required: ["name", "version"] }, observed_at: { bsonType: "date" }, extraction_status: { enum: [...EXTRACTION_STATUSES] }, provenance: { bsonType: "object", required: ["source", "input_sha256", "method"] }, idempotency_key: { bsonType: "string" } } } };
    const collectionExists = await db.listCollections({ name: artifactCollection }, { nameOnly: true }).hasNext();
    if (!collectionExists) await db.createCollection(artifactCollection, { validator, validationLevel: "strict", validationAction: "error" });
    else await db.command({ collMod: artifactCollection, validator, validationLevel: "strict", validationAction: "error" }).catch((error) => console.warn("MongoDB collection validator was not updated; application validation remains active", error instanceof Error ? error.message : "unknown error"));
    const collection = db.collection(artifactCollection);
    await Promise.all([
      collection.createIndex({ evidence_id: 1, observed_at: -1, artifact_id: 1 }),
      collection.createIndex({ artifact_type: 1, extraction_status: 1, observed_at: -1 }),
      collection.createIndex({ idempotency_key: 1 }, { unique: true }),
    ]);
    return await operation(collection);
  } finally { await client.close().catch(() => undefined); }
}

function safePage(value: unknown, fallback: number, maximum: number): number { const parsed = Number(value); return Number.isSafeInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback; }

router.get("/artifacts", async (req, res) => {
  const evidenceId = req.query.evidence_id == null ? undefined : Number(req.query.evidence_id);
  if (evidenceId !== undefined && (!Number.isSafeInteger(evidenceId) || evidenceId < 1)) return res.status(400).json({ error: "Invalid evidence_id" });
  const page = safePage(req.query.page, 1, 1000000); const pageSize = safePage(req.query.page_size, 25, 50);
  const artifactType = req.query.artifact_type == null ? undefined : String(req.query.artifact_type);
  const extractionStatus = req.query.extraction_status == null ? undefined : String(req.query.extraction_status);
  if (artifactType && !ARTIFACT_TYPES.includes(artifactType as any)) return res.status(400).json({ error: "Unsupported artifact_type" });
  if (extractionStatus && !EXTRACTION_STATUSES.includes(extractionStatus as any)) return res.status(400).json({ error: "Invalid extraction_status" });
  try {
    const result = await withMongo(async (collection) => {
      const filter: Record<string, unknown> = {};
      if (evidenceId !== undefined) filter.evidence_id = evidenceId;
      if (artifactType) filter.artifact_type = artifactType;
      if (extractionStatus) filter.extraction_status = extractionStatus;
      const [documents, total] = await Promise.all([
        collection.find(filter, { projection: { _id: 0 } }).sort({ observed_at: -1, artifact_id: 1 }).skip((page - 1) * pageSize).limit(pageSize).toArray(),
        collection.countDocuments(filter),
      ]);
      return { documents, page, page_size: pageSize, total };
    });
    return res.json(result);
  } catch (error) { console.error("MongoDB artifact lookup failed", error); return res.status(503).json({ service: "mongodb", status: "unavailable", error: "MongoDB artifact storage is unavailable" }); }
});

router.get("/artifacts/:artifactId", async (req, res) => {
  if (!/^[0-9a-f-]{36}$/i.test(req.params.artifactId)) return res.status(400).json({ error: "Invalid artifact identifier" });
  try {
    const document = await withMongo((collection) => collection.findOne({ artifact_id: req.params.artifactId }, { projection: { _id: 0 } }));
    if (!document) return res.status(404).json({ error: "Artifact not found" });
    return res.json(document);
  } catch (error) { console.error("MongoDB artifact lookup failed", error); return res.status(503).json({ service: "mongodb", status: "unavailable", error: "MongoDB artifact storage is unavailable" }); }
});

router.post("/artifacts", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  try { const result = await persistArtifact(req.body, req.user!.userId); return res.status(result.created ? 201 : 200).json(result); }
  catch (error) { if (error instanceof ArtifactPersistenceError) return res.status(error.status).json({ error: error.message }); console.error("MongoDB artifact persistence failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(503).json({ service: "mongodb", status: "unavailable", error: "MongoDB artifact storage is unavailable" }); }
});

async function graphResponse(rootLabel: "Case" | "Evidence", req: any, res: any) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: `Invalid ${rootLabel.toLowerCase()} ID` });
  const configured = getNeo4jSettings();
  if (!configured.settings) return res.status(503).json({ service: "neo4j", status: "configuration_incomplete", missing: configured.missing });
  try { return res.json(await readGraph(rootLabel, id, req.query.depth, req.query.limit)); }
  catch (error) {
    if (error instanceof Neo4jGraphNotFoundError) return res.status(404).json({ service: "neo4j", status: "not_found", error: "Graph record not found" });
    const failure = neo4jFailure(error);
    console.error("Neo4j graph lookup failed", { name: error instanceof Error ? error.name : "UnknownError", status: failure.status });
    return res.status(503).json({ service: "neo4j", ...failure });
  }
}

router.get("/graph/evidence/:id", (req, res) => graphResponse("Evidence", req, res));
router.get("/graph/case/:id", (req, res) => graphResponse("Case", req, res));
export default router;
