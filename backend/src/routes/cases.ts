import { Router } from "express";
import pool from "../db/mysql";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import { requireAuth, requireRoles } from "../middleware/auth";
import { writeAudit } from "../services/audit";
const router = Router();
router.use(requireAuth);
interface CaseRow extends RowDataPacket { case_id: number; case_number: string; title: string; description: string | null; created_by: number; status: string; created_at: Date; closed_at: Date | null; }
router.post("/", requireRoles("INVESTIGATOR", "ADMIN"), async (req, res) => {
  const { case_number, title, description } = req.body ?? {};
  if (typeof case_number !== "string" || !/^[A-Z0-9-]{4,50}$/i.test(case_number.trim()) || typeof title !== "string" || title.trim().length < 3) return res.status(400).json({ error: "A valid case number and title are required" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute<ResultSetHeader>("INSERT INTO cases (case_number, title, description, created_by) VALUES (?, ?, ?, ?)", [case_number.trim(), title.trim(), typeof description === "string" ? description.trim() || null : null, req.user!.userId]);
    await writeAudit(req.user!.userId, "CASE_CREATED", "CASE", result.insertId, { case_number: case_number.trim() }, connection);
    await connection.commit();
    return res.status(201).json({ case_id: result.insertId, case_number: case_number.trim(), status: "OPEN" });
  } catch (error: any) {
    await connection.rollback().catch((rollbackError) => console.error("Case creation rollback failed", rollbackError));
    if (error.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "A case with this case number already exists" });
    console.error(error);
    return res.status(500).json({ error: "Failed to create case" });
  } finally { connection.release(); }
});
router.get("/", async (_req, res) => { try { const [rows] = await pool.query<CaseRow[]>("SELECT case_id, case_number, title, description, created_by, status, created_at, closed_at FROM cases ORDER BY created_at DESC"); return res.json(rows); } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to retrieve cases" }); } });
router.get("/:id", async (req, res) => {
  const id = Number(req.params.id); if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid case ID" });
  try { const [cases] = await pool.execute<CaseRow[]>("SELECT case_id, case_number, title, description, created_by, status, created_at, closed_at FROM cases WHERE case_id = ?", [id]); if (!cases.length) return res.status(404).json({ error: "Case not found" }); const [evidence] = await pool.execute("SELECT evidence_id, evidence_code, evidence_name, evidence_type, original_filename, file_size_bytes, original_sha256, current_custodian, status, registered_at FROM evidence WHERE case_id = ? ORDER BY registered_at DESC", [id]); const [analysis] = await pool.execute("SELECT a.* FROM analysis_records a JOIN evidence e ON e.evidence_id = a.evidence_id WHERE e.case_id = ? ORDER BY a.created_at DESC", [id]); const [alerts] = await pool.execute("SELECT i.* FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id WHERE e.case_id = ? ORDER BY i.detected_at DESC", [id]); return res.json({ ...cases[0], evidence, analysis, integrity_alerts: alerts }); } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to retrieve case" }); }
});
router.patch("/:id/status", requireRoles("INVESTIGATOR", "ADMIN"), async (req, res) => {
  const id = Number(req.params.id); const status = req.body?.status; if (!Number.isSafeInteger(id) || !["OPEN", "UNDER_INVESTIGATION", "CLOSED"].includes(status)) return res.status(400).json({ error: "Invalid case or status" });
  if (status === "CLOSED") {
    try {
      await pool.query("CALL sp_close_case(?, ?)", [id, req.user!.userId]);
      return res.json({ case_id: id, status });
    } catch (error: any) {
      const message = String(error?.sqlMessage || error?.message || "");
      if (message.includes("not found")) return res.status(404).json({ error: message });
      if (message.includes("Case")) return res.status(409).json({ error: message });
      console.error("Case closure failed", error);
      return res.status(500).json({ error: "Failed to close case" });
    }
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute<any[]>("SELECT status FROM cases WHERE case_id = ? FOR UPDATE", [id]);
    if (!rows.length) { await connection.rollback(); return res.status(404).json({ error: "Case not found" }); }
    await connection.execute("UPDATE cases SET status = ?, closed_at = NULL WHERE case_id = ?", [status, id]);
    await writeAudit(req.user!.userId, "CASE_STATUS_CHANGED", "CASE", id, { status }, connection);
    await connection.commit();
    return res.json({ case_id: id, status });
  } catch (error) {
    await connection.rollback().catch((rollbackError) => console.error("Case status rollback failed", rollbackError));
    console.error(error);
    return res.status(500).json({ error: "Failed to update case status" });
  } finally { connection.release(); }
});
export default router;
