import { Router } from "express";
import pool from "../db/mysql";
import { requireAuth, requireRoles } from "../middleware/auth";
import { writeAudit } from "../services/audit";

const router = Router();
router.use(requireAuth);

router.get("/summary", async (_req, res) => {
  try {
    const [[cases]] = await pool.query<any[]>("SELECT COUNT(*) AS total, SUM(status <> 'CLOSED') AS active FROM cases");
    const [[evidence]] = await pool.query<any[]>("SELECT COUNT(*) AS total FROM evidence");
    const [[alerts]] = await pool.query<any[]>("SELECT COUNT(*) AS open FROM integrity_alerts WHERE status <> 'RESOLVED'");
    return res.json({ active_cases: Number(cases.active || 0), total_cases: Number(cases.total || 0), evidence_items: Number(evidence.total || 0), open_alerts: Number(alerts.open || 0) });
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load dashboard summary" }); }
});

router.get("/custody", async (req, res) => {
  try { const [rows] = await pool.query("SELECT * FROM v_custody_history ORDER BY event_time DESC LIMIT 200"); return res.json(rows); }
  catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load custody history" }); }
});

router.get("/alerts", async (_req, res) => {
  try { const [rows] = await pool.query("SELECT i.*, e.evidence_code, e.evidence_name FROM integrity_alerts i JOIN evidence e ON e.evidence_id=i.evidence_id ORDER BY i.detected_at DESC"); return res.json(rows); }
  catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load integrity alerts" }); }
});

router.patch("/alerts/:id", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  const id = Number(req.params.id); const status = req.body?.status; const notes = typeof req.body?.resolution_notes === "string" ? req.body.resolution_notes.trim() : null;
  if (!Number.isSafeInteger(id) || !["OPEN", "INVESTIGATING", "RESOLVED"].includes(status)) return res.status(400).json({ error: "Invalid alert or status" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute<any>("UPDATE integrity_alerts SET status=?, resolution_notes=? WHERE alert_id=?", [status, notes, id]);
    if (!result.affectedRows) { await connection.rollback(); return res.status(404).json({ error: "Alert not found" }); }
    await writeAudit(req.user!.userId, "INTEGRITY_ALERT_UPDATED", "INTEGRITY_ALERT", id, { status }, connection);
    await connection.commit();
    return res.json({ alert_id: id, status });
  } catch (error) {
    await connection.rollback().catch((rollbackError) => console.error("Alert update rollback failed", rollbackError));
    console.error(error);
    return res.status(500).json({ error: "Failed to update integrity alert" });
  } finally { connection.release(); }
});

export default router;
