import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import pool from "../db/mysql";
import type { RowDataPacket } from "mysql2";

export type Role = "INVESTIGATOR" | "ANALYST" | "CUSTODIAN" | "ADMIN";
export interface AuthUser { userId: number; fullName: string; email: string; role: Role; }
interface UserRow extends RowDataPacket { user_id: number; full_name: string; email: string; password_hash: string; role: Role; status: string; }

const sessions = new Map<string, { user: AuthUser; expiresAt: number }>();
const ttlMs = 8 * 60 * 60 * 1000;

export function createSession(user: AuthUser): string {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { user, expiresAt: Date.now() + ttlMs });
  return token;
}

export function destroySession(token: string | undefined): void { if (token) sessions.delete(token); }

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.header("authorization")?.replace(/^Bearer\s+/i, "") || req.header("x-session-token");
  const session = token ? sessions.get(token) : undefined;
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  req.user = session.user;
  next();
}

export function requireRoles(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) { res.status(403).json({ error: "Insufficient permissions" }); return; }
    next();
  };
}

export async function loadUserByEmail(email: string): Promise<UserRow | undefined> {
  const [rows] = await pool.execute<UserRow[]>("SELECT user_id, full_name, email, password_hash, role, status FROM users WHERE email = ? LIMIT 1", [email]);
  return rows[0];
}
