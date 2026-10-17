import { Router } from "express";
import pool from "../db/mysql";
import { requireAuth, requireRoles } from "../middleware/auth";
const router = Router(); router.use(requireAuth, requireRoles("ADMIN"));
router.get("/", async (req, res) => { const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200); const [rows] = await pool.query("SELECT log_id, user_id, action, entity_type, entity_id, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT " + limit); res.json(rows); });
export default router;
