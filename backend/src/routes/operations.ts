import { Router } from "express";
import pool from "../db/mysql";
import { requireAuth, requireRoles } from "../middleware/auth";
import { writeAudit } from "../services/audit";
import { requireCaseAccess } from "../services/caseAccess";

const router = Router();
router.use(requireAuth);

router.get("/summary", async (req, res) => {
  try {
    const isAdmin = req.user!.role === "ADMIN";
    const [caseRows] = await pool.execute<any[]>("SELECT COUNT(*) AS total, SUM(status <> 'CLOSED') AS active FROM cases WHERE (? = 1 OR case_id IN (SELECT case_id FROM case_members WHERE user_id = ?))", [isAdmin ? 1 : 0, req.user!.userId]);
    const [evidenceRows] = await pool.execute<any[]>("SELECT COUNT(*) AS total FROM evidence e WHERE (? = 1 OR e.case_id IN (SELECT case_id FROM case_members WHERE user_id = ?))", [isAdmin ? 1 : 0, req.user!.userId]);
    const [alertRows] = await pool.execute<any[]>("SELECT COUNT(*) AS open FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id WHERE i.status <> 'RESOLVED' AND (? = 1 OR e.case_id IN (SELECT case_id FROM case_members WHERE user_id = ?))", [isAdmin ? 1 : 0, req.user!.userId]);
    const cases = caseRows[0]; const evidence = evidenceRows[0]; const alerts = alertRows[0];
    return res.json({ active_cases: Number(cases.active || 0), total_cases: Number(cases.total || 0), evidence_items: Number(evidence.total || 0), open_alerts: Number(alerts.open || 0) });
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load dashboard summary" }); }
});

router.get("/custody", async (req, res) => {
  try {
    const isAdmin = req.user!.role === "ADMIN";
    const [rows] = await pool.execute("SELECT v.* FROM v_custody_history v JOIN evidence e ON e.evidence_id = v.evidence_id WHERE (? = 1 OR e.case_id IN (SELECT case_id FROM case_members WHERE user_id = ?)) ORDER BY v.event_time DESC LIMIT 200", [isAdmin ? 1 : 0, req.user!.userId]);
    return res.json(rows);
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load custody history" }); }
});

router.get("/alerts", async (req, res) => {
  try {
    const isAdmin = req.user!.role === "ADMIN";
    const [rows] = await pool.execute("SELECT i.*, e.evidence_code, e.evidence_name FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id WHERE (? = 1 OR e.case_id IN (SELECT case_id FROM case_members WHERE user_id = ?)) ORDER BY i.detected_at DESC", [isAdmin ? 1 : 0, req.user!.userId]);
    return res.json(rows);
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to load integrity alerts" }); }
});

router.patch("/alerts/:id", requireRoles("ANALYST", "ADMIN"), async (req, res) => {
  const id = Number(req.params.id); const status = req.body?.status; const notes = typeof req.body?.resolution_notes === "string" ? req.body.resolution_notes.trim() : null;
  if (!Number.isSafeInteger(id) || !["OPEN", "INVESTIGATING", "RESOLVED"].includes(status)) return res.status(400).json({ error: "Invalid alert or status" });
  const [accessRows] = await pool.execute<any[]>("SELECT e.case_id FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id WHERE i.alert_id = ?", [id]);
  if (!accessRows.length) return res.status(404).json({ error: "Alert not found" });
  if (!(await requireCaseAccess(req.user!, Number(accessRows[0].case_id), res))) return;
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
