import { Router } from "express";
import bcrypt from "bcryptjs";
import { requireAuth, requireRoles } from "../middleware/auth";
import pool from "../db/mysql";
import { writeAudit } from "../services/audit";
const router = Router();
router.use(requireAuth, requireRoles("ADMIN"));
router.get("/", async (_req, res) => { const [rows] = await pool.query("SELECT user_id, full_name, email, role, status, created_at FROM users ORDER BY created_at DESC"); res.json(rows); });
router.post("/", async (req, res) => {
  const { full_name, email, password, role = "INVESTIGATOR" } = req.body ?? {};
  if (typeof full_name !== "string" || full_name.trim().length < 2 || typeof email !== "string" || !email.includes("@") || typeof password !== "string" || password.length < 12 || !["INVESTIGATOR", "ANALYST", "CUSTODIAN", "ADMIN"].includes(role)) return res.status(400).json({ error: "Valid name, email, 12-character password, and role are required" });
  try { const hash = await bcrypt.hash(password, 12); const [result] = await pool.execute<any>("INSERT INTO users (full_name, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'ACTIVE')", [full_name.trim(), email.trim().toLowerCase(), hash, role]); await writeAudit(req.user!.userId, "USER_CREATED", "USER", result.insertId, { role }); return res.status(201).json({ user_id: result.insertId, full_name: full_name.trim(), email: email.trim().toLowerCase(), role }); }
  catch (error: any) { if (error.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Email already exists" }); console.error(error); return res.status(500).json({ error: "Failed to create user" }); }
});
export default router;
