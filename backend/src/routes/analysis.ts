import { Router } from "express";
import pool from "../db/mysql";
import { requireAuth, requireRoles } from "../middleware/auth";
import { writeAudit } from "../services/audit";
import { hashStoredFile } from "../services/hashing";
import { runMetadataExtractor } from "../services/metadataExtractor";
import { ArtifactPersistenceError, persistArtifact } from "../services/artifactPersistence";

const router = Router();
router.use(requireAuth);

const idOf = (value: unknown) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
const safeFailure = (error: unknown) => error instanceof ArtifactPersistenceError ? error.message : error instanceof Error && /hash|storage|parser|metadata|format|unsupported|dependency|archive|JSON|XML|image/i.test(error.message) ? error.message.slice(0, 240) : "Metadata extraction failed";

router.get("/", async (req, res) => {
  const evidenceId = req.query.evidence_id == null ? null : idOf(req.query.evidence_id);
  if (req.query.evidence_id != null && !evidenceId) return res.status(400).json({ error: "Invalid evidence_id" });
  try { const [rows] = await pool.execute("SELECT * FROM analysis_records WHERE (? IS NULL OR evidence_id=?) ORDER BY created_at DESC", [evidenceId, evidenceId]); return res.json(rows); }
  catch (error) { console.error("Analysis lookup failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(500).json({ error: "Failed to retrieve analysis records" }); }
});

router.post("/", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  const evidenceId = idOf(req.body?.evidence_id); const type = req.body?.analysis_type;
  if (!evidenceId || typeof type !== "string" || !type.trim()) return res.status(400).json({ error: "evidence_id and analysis_type are required" });
  const connection = await pool.getConnection();
  try {
    const [evidence] = await connection.execute<any[]>("SELECT evidence_id FROM evidence WHERE evidence_id=? LIMIT 1", [evidenceId]);
    if (!evidence.length) return res.status(404).json({ error: "Evidence not found" });
    await connection.beginTransaction();
    const [result] = await connection.execute<any>("INSERT INTO analysis_records (evidence_id, analyst_id, analysis_type, description, status, started_at) VALUES (?, ?, ?, ?, 'PENDING', NULL)", [evidenceId, req.user!.userId, type.trim(), typeof req.body.description === "string" ? req.body.description.trim() || null : null]);
    await writeAudit(req.user!.userId, "ANALYSIS_CREATED", "ANALYSIS", result.insertId, { evidence_id: evidenceId, analysis_type: type.trim() }, connection);
    await connection.commit(); return res.status(201).json({ analysis_id: result.insertId, status: "PENDING" });
  } catch (error) { await connection.rollback().catch(() => undefined); console.error("Analysis creation failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(500).json({ error: "Failed to create analysis record" }); }
  finally { connection.release(); }
});

router.post("/:id/run", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  const id = idOf(req.params.id); if (!id) return res.status(400).json({ error: "Invalid analysis ID" });
  const [rows] = await pool.execute<any[]>("SELECT a.analysis_id, a.evidence_id, a.analyst_id, a.analysis_type, a.status, e.original_filename, e.storage_path, e.original_sha256, e.evidence_type FROM analysis_records a JOIN evidence e ON e.evidence_id=a.evidence_id WHERE a.analysis_id=? LIMIT 1", [id]);
  if (!rows.length) return res.status(404).json({ error: "Analysis record not found" });
  const analysis = rows[0];
  if (req.user!.role !== "ADMIN" && analysis.analyst_id !== req.user!.userId) return res.status(403).json({ error: "Analysis is assigned to another analyst" });
  if (analysis.status === "IN_PROGRESS") return res.status(409).json({ error: "Analysis is already in progress" });
  if (analysis.status === "COMPLETED") return res.json({ analysis_id: id, evidence_id: analysis.evidence_id, status: "COMPLETED", message: "Analysis is already completed" });

  const startConnection = await pool.getConnection();
  try {
    await startConnection.beginTransaction();
    await startConnection.execute("UPDATE analysis_records SET status='IN_PROGRESS', started_at=COALESCE(started_at, CURRENT_TIMESTAMP), completed_at=NULL, result_summary=NULL WHERE analysis_id=?", [id]);
    await writeAudit(req.user!.userId, "ANALYSIS_STARTED", "ANALYSIS", id, { evidence_id: analysis.evidence_id, analysis_type: analysis.analysis_type }, startConnection);
    await startConnection.commit();
  } catch (error) { await startConnection.rollback().catch(() => undefined); console.error("Analysis start failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(500).json({ error: "Could not start analysis" }); }
  finally { if (startConnection) startConnection.release(); }

  try {
    const actualHash = await hashStoredFile(analysis.storage_path);
    if (actualHash !== String(analysis.original_sha256).toLowerCase()) throw new Error("Stored evidence hash does not match the registered original SHA-256");
    const extraction = await runMetadataExtractor(analysis.storage_path, analysis.original_filename, undefined);
    const persisted = await persistArtifact({ evidence_id: analysis.evidence_id, artifact_type: extraction.artifact_type, source_filename: analysis.original_filename, fields: extraction.fields, parser: extraction.parser, observed_at: new Date().toISOString(), extraction_status: "COMPLETED", error: null, provenance: { source: extraction.provenance.source, input_sha256: actualHash, method: extraction.provenance.method }, idempotency_key: `analysis-${id}-${actualHash.slice(0, 16)}` }, req.user!.userId);
    const summary = `Metadata extraction completed (${extraction.artifact_type}) using ${extraction.parser.name} ${extraction.parser.version}`;
    const connection = await pool.getConnection();
    try { await connection.beginTransaction(); await connection.execute("UPDATE analysis_records SET status='COMPLETED', result_summary=?, completed_at=CURRENT_TIMESTAMP WHERE analysis_id=?", [summary, id]); await writeAudit(req.user!.userId, "ANALYSIS_COMPLETED", "ANALYSIS", id, { evidence_id: analysis.evidence_id, artifact_id: persisted.document.artifact_id, artifact_type: extraction.artifact_type, input_sha256: actualHash }, connection); await connection.commit(); } catch (error) { await connection.rollback().catch(() => undefined); throw error; } finally { connection.release(); }
    return res.json({ analysis_id: id, evidence_id: analysis.evidence_id, status: "COMPLETED", artifact: persisted.document });
  } catch (error) {
    const message = safeFailure(error);
    const connection = await pool.getConnection();
    try { await connection.beginTransaction(); await connection.execute("UPDATE analysis_records SET status='FAILED', result_summary=?, completed_at=CURRENT_TIMESTAMP WHERE analysis_id=?", [message, id]); await writeAudit(req.user!.userId, "ANALYSIS_FAILED", "ANALYSIS", id, { evidence_id: analysis.evidence_id, reason: message }, connection); await connection.commit(); } catch (updateError) { await connection.rollback().catch(() => undefined); console.error("Analysis failure status update failed", { name: updateError instanceof Error ? updateError.name : "UnknownError" }); } finally { connection.release(); }
    if (error instanceof ArtifactPersistenceError) return res.status(error.status).json({ error: error.message, analysis_id: id, status: "FAILED" });
    const status = /hash/i.test(message) ? 409 : /MongoDB|storage/i.test(message) ? 503 : 422;
    return res.status(status).json({ error: message, analysis_id: id, status: "FAILED" });
  }
});

router.patch("/:id", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  const id = idOf(req.params.id); const status = req.body?.status;
  if (!id || !["PENDING", "IN_PROGRESS", "COMPLETED", "FAILED"].includes(status)) return res.status(400).json({ error: "Invalid analysis status" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction(); const isAdmin = req.user!.role === "ADMIN";
    const [result] = await connection.execute<any>("UPDATE analysis_records SET status=?, result_summary=?, started_at=CASE WHEN ?='IN_PROGRESS' AND started_at IS NULL THEN CURRENT_TIMESTAMP ELSE started_at END, completed_at=CASE WHEN ? IN ('COMPLETED','FAILED') THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE analysis_id=? AND (? = 1 OR analyst_id=?)", [status, typeof req.body.result_summary === "string" ? req.body.result_summary.trim() || null : null, status, status, id, isAdmin ? 1 : 0, req.user!.userId]);
    if (!result.affectedRows) { await connection.rollback(); return res.status(404).json({ error: "Analysis record not found or not assigned to current analyst" }); }
    await writeAudit(req.user!.userId, "ANALYSIS_STATUS_CHANGED", "ANALYSIS", id, { status }, connection); await connection.commit(); return res.json({ analysis_id: id, status });
  } catch (error) { await connection.rollback().catch(() => undefined); console.error("Analysis update failed", { name: error instanceof Error ? error.name : "UnknownError" }); return res.status(500).json({ error: "Failed to update analysis record" }); }
  finally { connection.release(); }
});

export default router;
