import bcrypt from "bcryptjs";
import pool from "../src/db/mysql";

const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
const name = process.env.BOOTSTRAP_ADMIN_NAME?.trim();
const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
if (!email || !name || !password || password.length < 12) throw new Error("Set BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_NAME, and a 12+ character BOOTSTRAP_ADMIN_PASSWORD");

try {
  const [existing] = await pool.execute<any[]>("SELECT user_id FROM users WHERE email=? LIMIT 1", [email]);
  if (existing.length) throw new Error("A user with this email already exists; no account was changed");
  const passwordHash = await bcrypt.hash(password, 12);
  const [result] = await pool.execute<any>("INSERT INTO users (full_name, email, password_hash, role, status) VALUES (?, ?, ?, 'ADMIN', 'ACTIVE')", [name, email, passwordHash]);
  console.log(`Administrator created with user ID ${result.insertId}`);
} finally { await pool.end(); }
