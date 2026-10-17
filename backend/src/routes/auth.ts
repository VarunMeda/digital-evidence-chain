import { Router } from "express";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import { createSession, destroySession, loadUserByEmail } from "../middleware/auth";
import { writeAudit } from "../services/audit";
const router = Router();
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
router.post("/login", loginLimiter, async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
  try {
    const user = await loadUserByEmail(email);
    const valid = user && user.status === "ACTIVE" && await bcrypt.compare(password, user.password_hash);
    if (!valid || !user) { await writeAudit(user?.user_id || null, "LOGIN_FAILED", "USER", user?.user_id || null, { email }); return res.status(401).json({ error: "Invalid credentials" }); }
    const token = createSession({ userId: user.user_id, fullName: user.full_name, email: user.email, role: user.role });
    await writeAudit(user.user_id, "LOGIN_SUCCESS", "USER", user.user_id, {});
    return res.json({ token, user: { user_id: user.user_id, full_name: user.full_name, email: user.email, role: user.role } });
  } catch (error) { console.error("Login failed", error); return res.status(500).json({ error: "Authentication service unavailable" }); }
});
router.post("/logout", (req, res) => { destroySession(req.header("authorization")?.replace(/^Bearer\s+/i, "") || req.header("x-session-token")); res.status(204).send(); });
export default router;
