import { Router } from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import multer from "multer";
import pool from "../db/mysql";
import { config } from "../config";
import { requireAuth, requireRoles } from "../middleware/auth";
import { hashStoredFile } from "../services/hashing";
import { writeAudit } from "../services/audit";
import { validateEvidenceFile } from "../services/evidenceValidation";

const router = Router();
router.use(requireAuth);

const stagingRoot = path.join(config.storageRoot, ".staging");
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => {
      fs.mkdir(stagingRoot, { recursive: true }).then(() => callback(null, stagingRoot)).catch((error) => callback(error, ""));
    },
    filename: (_req, _file, callback) => callback(null, crypto.randomUUID()),
  }),
  limits: { fileSize: config.maxUploadBytes },
  fileFilter: (_req, file, callback) => {
    if (!file.originalname || file.originalname.includes("..")) callback(new Error("Invalid filename"));
    else callback(null, true);
  },
});

const idOf = (value: string) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;

class RequestError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

async function removeOwnedFile(filePath: string | undefined): Promise<void> {
  if (!filePath) return;
  const root = path.resolve(config.storageRoot);
  const resolved = path.resolve(filePath);
  if (resolved === root || !resolved.startsWith(`${root}${path.sep}`)) {
    console.error("Refusing to clean up a file outside evidence storage", resolved);
    return;
  }
  await fs.rm(resolved, { force: true }).catch((error) => console.error("Evidence cleanup failed", error));
}

router.post("/", requireRoles("INVESTIGATOR", "ADMIN"), upload.single("evidence"), async (req, res) => {
  const file = req.file;
  const caseId = idOf(req.body?.case_id);
  let connection: Awaited<ReturnType<typeof pool.getConnection>> | undefined;
  let transactionStarted = false;
  let commitAttempted = false;
  let promotedPath: string | undefined;

  try {
    if (!file || !caseId || typeof req.body?.evidence_name !== "string" || !req.body.evidence_name.trim() || typeof req.body?.evidence_type !== "string") {
      throw new RequestError(400, "case_id, evidence_name, evidence_type, and a file are required");
    }
    if (req.body.evidence_name.trim().length > 255) throw new RequestError(400, "Evidence name is too long");

    const detectedType = await validateEvidenceFile(file.path, file.originalname, config.maxUploadBytes).catch((error) => {
      throw new RequestError(400, error instanceof Error ? error.message : "Unsupported evidence file");
    });
    const requestedType = String(req.body.evidence_type).trim().toUpperCase();
    const matchesCategory = requestedType === "AUTO"
      || requestedType === detectedType
      || (requestedType === "IMAGE" && ["JPG", "JPEG", "PNG", "TIFF", "BMP"].includes(detectedType))
      || (requestedType === "VIDEO" && ["MP4", "MOV", "AVI", "MKV"].includes(detectedType))
      || (requestedType === "AUDIO" && ["MP3", "WAV"].includes(detectedType))
      || (requestedType === "DOCUMENT" && ["PDF", "DOC", "DOCX", "TXT"].includes(detectedType))
      || (requestedType === "FORENSIC" && ["E01", "RAW", "LOG", "CSV", "JSON", "XML"].includes(detectedType));
    if (!matchesCategory) throw new RequestError(400, `Selected evidence type does not match detected file format (${detectedType})`);

    const digest = await hashStoredFile(file.path);
    connection = await pool.getConnection();
    const [cases] = await connection.execute<any[]>("SELECT case_id FROM cases WHERE case_id = ?", [caseId]);
    if (!cases.length) throw new RequestError(404, "Case not found");

    const code = `EV-${new Date().getFullYear()}-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
    promotedPath = path.join(config.storageRoot, `evidence-${crypto.randomUUID()}`);
    await connection.beginTransaction();
    transactionStarted = true;
    const [result] = await connection.execute<any>(
      "INSERT INTO evidence (evidence_code, case_id, evidence_name, evidence_type, description, original_filename, storage_path, file_size_bytes, original_sha256, current_custodian, status, registered_by, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REGISTERED', ?, NOW())",
      [code, caseId, req.body.evidence_name.trim(), detectedType, req.body.description?.trim() || null, path.basename(file.originalname), promotedPath, file.size, digest, req.user!.userId, req.user!.userId],
    );
    await connection.execute(
      "INSERT INTO custody_records (evidence_id, event_type, from_user, to_user, performed_by, reason, location) VALUES (?, 'COLLECTED', NULL, ?, ?, ?, ?)",
      [result.insertId, req.user!.userId, req.user!.userId, "Initial registration", req.body.location?.trim() || null],
    );
    await writeAudit(req.user!.userId, "EVIDENCE_REGISTERED", "EVIDENCE", result.insertId, { evidence_code: code, case_id: caseId, sha256: digest, detected_type: detectedType }, connection);

    // Promote only after all SQL work is ready. If SQL fails, the staged bytes
    // are removed; if promotion fails, the transaction is rolled back.
    await fs.rename(file.path, promotedPath);
    commitAttempted = true;
    await connection.commit();
    transactionStarted = false;
    return res.status(201).json({ evidence_id: result.insertId, evidence_code: code, original_filename: path.basename(file.originalname), file_size_bytes: file.size, original_sha256: digest, evidence_type: detectedType, status: "REGISTERED" });
  } catch (error) {
    if (transactionStarted && connection) await connection.rollback().catch((rollbackError) => console.error("Evidence rollback failed", rollbackError));
    if (commitAttempted) {
      // A commit error has an uncertain outcome. Preserve the promoted bytes
      // and log them for reconciliation instead of deleting a valid record.
      console.error("Evidence registration commit outcome is uncertain; preserved promoted file", promotedPath);
    } else {
      await removeOwnedFile(promotedPath);
      await removeOwnedFile(file?.path);
    }
    console.error("Evidence registration failed", error);
    if (error instanceof RequestError) return res.status(error.status).json({ error: error.message });
    return res.status(500).json({ error: "Evidence registration failed" });
  } finally {
    connection?.release();
  }
});

router.get("/", async (req, res) => {
  const caseId = req.query.case_id ? idOf(String(req.query.case_id)) : null;
  const [rows] = await pool.execute("SELECT evidence_id, evidence_code, case_id, evidence_name, evidence_type, original_filename, file_size_bytes, original_sha256, current_custodian, status, registered_by, registered_at FROM evidence WHERE (? IS NULL OR case_id = ?) ORDER BY registered_at DESC", [caseId, caseId]);
  res.json(rows);
});

router.get("/:id", async (req, res) => {
  const id = idOf(String(req.params.id));
  if (!id) return res.status(400).json({ error: "Invalid evidence ID" });
  const [rows] = await pool.execute<any[]>("SELECT evidence_id, evidence_code, case_id, evidence_name, evidence_type, description, original_filename, file_size_bytes, original_sha256, current_custodian, status, registered_by, registered_at FROM evidence WHERE evidence_id = ?", [id]);
  if (!rows.length) return res.status(404).json({ error: "Evidence not found" });
  const [custody] = await pool.execute("SELECT * FROM custody_records WHERE evidence_id = ? ORDER BY event_time DESC", [id]);
  const [analysis] = await pool.execute("SELECT * FROM analysis_records WHERE evidence_id = ? ORDER BY created_at DESC", [id]);
  const [alerts] = await pool.execute("SELECT * FROM integrity_alerts WHERE evidence_id = ? ORDER BY detected_at DESC", [id]);
  return res.json({ ...rows[0], custody, analysis, integrity_alerts: alerts });
});

router.post("/:id/transfer", requireRoles("CUSTODIAN", "INVESTIGATOR", "ADMIN"), async (req, res) => {
  const id = idOf(String(req.params.id));
  const toUser = idOf(req.body?.to_user_id);
  if (!id || !toUser || toUser === req.user!.userId) return res.status(400).json({ error: "Valid different destination custodian is required" });
  try {
    await pool.query("CALL sp_transfer_custody(?, ?, ?, ?, ?, ?)", [id, req.user!.userId, toUser, req.user!.userId, req.body.reason?.trim() || null, req.body.location?.trim() || null]);
    return res.json({ evidence_id: id, current_custodian: toUser, status: "IN_CUSTODY" });
  } catch (error: any) {
    const message = String(error?.sqlMessage || error?.message || "");
    if (message.includes("not found")) return res.status(404).json({ error: message });
    if (message.includes("custodian") || message.includes("Custody") || message.includes("state") || message.includes("different")) return res.status(409).json({ error: message });
    console.error("Custody transfer failed", error);
    return res.status(500).json({ error: "Custody transfer failed" });
  }
});

router.post("/:id/verify", requireRoles("ANALYST", "ADMIN", "CUSTODIAN"), async (req, res) => {
  const id = idOf(String(req.params.id));
  if (!id) return res.status(400).json({ error: "Invalid evidence ID" });
  const [rows] = await pool.execute<any[]>("SELECT storage_path, original_sha256 FROM evidence WHERE evidence_id = ?", [id]);
  if (!rows.length) return res.status(404).json({ error: "Evidence not found" });
  let actual: string;
  try {
    actual = await hashStoredFile(rows[0].storage_path);
  } catch (error) {
    console.error("Integrity hashing failed", error);
    return res.status(500).json({ error: "Integrity verification failed" });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [locked] = await connection.execute<any[]>("SELECT storage_path, original_sha256 FROM evidence WHERE evidence_id = ? FOR UPDATE", [id]);
    if (!locked.length) { await connection.rollback(); return res.status(404).json({ error: "Evidence not found" }); }
    if (locked[0].storage_path !== rows[0].storage_path || locked[0].original_sha256 !== rows[0].original_sha256) {
      await connection.rollback();
      return res.status(409).json({ error: "Evidence changed during integrity verification; retry" });
    }
    const matches = actual === locked[0].original_sha256;
    if (!matches) {
      const [alert] = await connection.execute<any>("INSERT INTO integrity_alerts (evidence_id, expected_sha256, actual_sha256, detected_by, severity) VALUES (?, ?, ?, ?, 'CRITICAL')", [id, locked[0].original_sha256, actual, req.user!.userId]);
      await connection.execute("UPDATE evidence SET status='FLAGGED' WHERE evidence_id=?", [id]);
      await writeAudit(req.user!.userId, "INTEGRITY_MISMATCH", "EVIDENCE", id, { alert_id: alert.insertId, expected_sha256: locked[0].original_sha256, actual_sha256: actual }, connection);
    } else {
      await writeAudit(req.user!.userId, "INTEGRITY_VERIFIED", "EVIDENCE", id, { sha256: actual }, connection);
    }
    await connection.commit();
    return res.json({ evidence_id: id, matches, expected_sha256: locked[0].original_sha256, actual_sha256: actual });
  } catch (error) {
    await connection.rollback().catch((rollbackError) => console.error("Integrity rollback failed", rollbackError));
    console.error("Integrity verification failed", error);
    return res.status(500).json({ error: "Integrity verification failed" });
  } finally {
    connection.release();
  }
});

export default router;
