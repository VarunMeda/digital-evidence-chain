import { Router } from "express";
import bcrypt from "bcryptjs";
import { requireAuth, requireRoles } from "../middleware/auth";
import pool from "../db/mysql";
import { writeAudit } from "../services/audit";
const router = Router();
router.get("/custodians", requireAuth, async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT user_id, full_name, email FROM users WHERE role = 'CUSTODIAN' AND status = 'ACTIVE' ORDER BY full_name");
    return res.json(rows);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to load active custodians" });
  }
});
router.use(requireAuth, requireRoles("ADMIN"));
router.get("/", async (_req, res) => { const [rows] = await pool.query("SELECT user_id, full_name, email, role, status, created_at FROM users ORDER BY created_at DESC"); res.json(rows); });
router.post("/", async (req, res) => {
  const { full_name, email, password, role = "INVESTIGATOR" } = req.body ?? {};
  if (typeof full_name !== "string" || full_name.trim().length < 2 || typeof email !== "string" || !email.includes("@") || typeof password !== "string" || password.length < 12 || !["INVESTIGATOR", "ANALYST", "CUSTODIAN", "ADMIN"].includes(role)) return res.status(400).json({ error: "Valid name, email, 12-character password, and role are required" });
  const connection = await pool.getConnection();
  try {
    const hash = await bcrypt.hash(password, 12);
    await connection.beginTransaction();
    const [result] = await connection.execute<any>("INSERT INTO users (full_name, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'ACTIVE')", [full_name.trim(), email.trim().toLowerCase(), hash, role]);
    await writeAudit(req.user!.userId, "USER_CREATED", "USER", result.insertId, { role }, connection);
    await connection.commit();
    return res.status(201).json({ user_id: result.insertId, full_name: full_name.trim(), email: email.trim().toLowerCase(), role });
  } catch (error: any) {
    await connection.rollback().catch((rollbackError) => console.error("User creation rollback failed", rollbackError));
    if (error.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Email already exists" });
    console.error(error);
    return res.status(500).json({ error: "Failed to create user" });
  } finally { connection.release(); }
});
router.patch("/:id/status", async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.status;
  if (!Number.isSafeInteger(id) || id < 1 || !["ACTIVE", "INACTIVE"].includes(status)) return res.status(400).json({ error: "Valid user and status are required" });
  if (id === req.user!.userId) return res.status(409).json({ error: "You cannot deactivate your own account" });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute<any>("UPDATE users SET status=? WHERE user_id=?", [status, id]);
    if (!result.affectedRows) { await connection.rollback(); return res.status(404).json({ error: "User not found" }); }
    await writeAudit(req.user!.userId, "USER_STATUS_CHANGED", "USER", id, { status }, connection);
    await connection.commit();
    return res.json({ user_id: id, status });
  } catch (error) {
    await connection.rollback().catch((rollbackError) => console.error("User status rollback failed", rollbackError));
    console.error(error);
    return res.status(500).json({ error: "Failed to update user status" });
  } finally { connection.release(); }
});
export default router;
