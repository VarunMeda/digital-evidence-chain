import { Router } from "express";
import pool from "../db/mysql";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import { requireAuth, requireRoles } from "../middleware/auth";
import { writeAudit } from "../services/audit";
import { caseAccessLevel, requireCaseAccess, requireCaseManage } from "../services/caseAccess";
const router = Router();
router.use(requireAuth);
interface CaseRow extends RowDataPacket { case_id: number; case_number: string; title: string; description: string | null; created_by: number; status: string; created_at: Date; closed_at: Date | null; }
const idOf = (value: unknown) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;

router.post("/", requireRoles("INVESTIGATOR", "ADMIN"), async (req, res) => {
  const { case_number, title, description } = req.body ?? {};
  if (typeof case_number !== "string" || !/^[A-Z0-9-]{4,50}$/i.test(case_number.trim()) || typeof title !== "string" || title.trim().length < 3) return res.status(400).json({ error: "A valid case number and title are required" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute<ResultSetHeader>("INSERT INTO cases (case_number, title, description, created_by) VALUES (?, ?, ?, ?)", [case_number.trim(), title.trim(), typeof description === "string" ? description.trim() || null : null, req.user!.userId]);
    await connection.execute("INSERT INTO case_members (case_id, user_id, access_level, added_by) VALUES (?, ?, 'MANAGE', ?) ON DUPLICATE KEY UPDATE access_level = 'MANAGE', added_by = VALUES(added_by)", [result.insertId, req.user!.userId, req.user!.userId]);
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

router.get("/", async (req, res) => {
  try {
    const isAdmin = req.user!.role === "ADMIN";
    const [rows] = await pool.execute<CaseRow[]>(
      `SELECT c.case_id, c.case_number, c.title, c.description, c.created_by, c.status, c.created_at, c.closed_at
       FROM cases c
       WHERE (? = 1 OR c.case_id IN (SELECT m.case_id FROM case_members m WHERE m.user_id = ?))
       ORDER BY c.created_at DESC`,
      [isAdmin ? 1 : 0, req.user!.userId],
    );
    return res.json(rows);
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to retrieve cases" }); }
});

router.get("/:id", async (req, res) => {
  const id = idOf(req.params.id); if (!id) return res.status(400).json({ error: "Invalid case ID" });
  try {
    const [cases] = await pool.execute<CaseRow[]>("SELECT case_id, case_number, title, description, created_by, status, created_at, closed_at FROM cases WHERE case_id = ?", [id]);
    if (!cases.length) return res.status(404).json({ error: "Case not found" });
    if (!(await requireCaseAccess(req.user!, id, res))) return;
    const accessLevel = await caseAccessLevel(req.user!, id);
    const [evidence] = await pool.execute("SELECT evidence_id, evidence_code, evidence_name, evidence_type, original_filename, file_size_bytes, original_sha256, current_custodian, status, registered_at FROM evidence WHERE case_id = ? ORDER BY registered_at DESC", [id]);
    const [analysis] = await pool.execute("SELECT a.* FROM analysis_records a JOIN evidence e ON e.evidence_id = a.evidence_id WHERE e.case_id = ? ORDER BY a.created_at DESC", [id]);
    const [alerts] = await pool.execute("SELECT i.* FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id WHERE e.case_id = ? ORDER BY i.detected_at DESC", [id]);
    return res.json({ ...cases[0], access_level: accessLevel, evidence, analysis, integrity_alerts: alerts });
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to retrieve case" }); }
});

router.get("/:id/members", async (req, res) => {
  const id = idOf(req.params.id); if (!id) return res.status(400).json({ error: "Invalid case ID" });
  if (!(await requireCaseAccess(req.user!, id, res))) return;
  try {
    const [rows] = await pool.execute<any[]>(
      "SELECT m.user_id, m.access_level, m.added_at, u.full_name, u.email, u.role, u.status FROM case_members m JOIN users u ON u.user_id = m.user_id WHERE m.case_id = ? ORDER BY u.full_name",
      [id],
    );
    return res.json(rows);
  } catch (error) { console.error(error); return res.status(500).json({ error: "Failed to retrieve case members" }); }
});

router.post("/:id/members", async (req, res) => {
  const id = idOf(req.params.id); const userId = idOf(req.body?.user_id);
  if (!id || !userId) return res.status(400).json({ error: "Valid case and user IDs are required" });
  if (!(await requireCaseManage(req.user!, id, res))) return;
  const requested = req.body?.access_level === "MANAGE" ? "MANAGE" : "VIEW";
  const connection = await pool.getConnection();
  try {
    const [cases] = await connection.execute<any[]>("SELECT created_by FROM cases WHERE case_id = ?", [id]);
    if (!cases.length) return res.status(404).json({ error: "Case not found" });
    const [users] = await connection.execute<any[]>("SELECT user_id FROM users WHERE user_id = ? AND status = 'ACTIVE'", [userId]);
    if (!users.length) return res.status(404).json({ error: "Active user not found" });
    const accessLevel = Number(cases[0].created_by) === userId ? "MANAGE" : requested;
    await connection.beginTransaction();
    await connection.execute(
      "INSERT INTO case_members (case_id, user_id, access_level, added_by) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE access_level = ?, added_by = ?, added_at = CURRENT_TIMESTAMP",
      [id, userId, accessLevel, req.user!.userId, accessLevel, req.user!.userId],
    );
    await writeAudit(req.user!.userId, "CASE_MEMBER_ADDED", "CASE", id, { user_id: userId, access_level: accessLevel }, connection);
    await connection.commit();
    return res.json({ case_id: id, user_id: userId, access_level: accessLevel });
  } catch (error) {
    await connection.rollback().catch(() => undefined);
    console.error(error);
    return res.status(500).json({ error: "Failed to update case membership" });
  } finally { connection.release(); }
});

router.delete("/:id/members/:userId", async (req, res) => {
  const id = idOf(req.params.id); const userId = idOf(req.params.userId);
  if (!id || !userId) return res.status(400).json({ error: "Valid case and user IDs are required" });
  if (!(await requireCaseManage(req.user!, id, res))) return;
  const [cases] = await pool.execute<any[]>("SELECT created_by FROM cases WHERE case_id = ?", [id]);
  if (!cases.length) return res.status(404).json({ error: "Case not found" });
  if (userId === req.user!.userId) return res.status(409).json({ error: "You cannot remove your own case access" });
  if (Number(cases[0].created_by) === userId && req.user!.role !== "ADMIN") return res.status(409).json({ error: "Only an administrator can remove the case creator" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute<any>("DELETE FROM case_members WHERE case_id = ? AND user_id = ?", [id, userId]);
    if (!result.affectedRows) { await connection.rollback(); return res.status(404).json({ error: "Case member not found" }); }
    await writeAudit(req.user!.userId, "CASE_MEMBER_REMOVED", "CASE", id, { user_id: userId }, connection);
    await connection.commit();
    return res.json({ case_id: id, user_id: userId, removed: true });
  } catch (error) {
    await connection.rollback().catch(() => undefined);
    console.error(error);
    return res.status(500).json({ error: "Failed to remove case member" });
  } finally { connection.release(); }
});

router.patch("/:id/status", requireRoles("INVESTIGATOR", "ADMIN"), async (req, res) => {
  const id = idOf(req.params.id); const status = req.body?.status;
  if (!id || !["OPEN", "UNDER_INVESTIGATION", "CLOSED"].includes(status)) return res.status(400).json({ error: "Invalid case or status" });
  if (!(await requireCaseManage(req.user!, id, res))) return;
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
