import type { Response } from "express";
import pool from "../db/mysql";
import type { AuthUser } from "../middleware/auth";
import { writeAudit } from "./audit";

export type CaseAccessLevel = "VIEW" | "MANAGE";

export async function caseAccessLevel(user: AuthUser, caseId: number): Promise<CaseAccessLevel | null> {
  if (user.role === "ADMIN") return "MANAGE";
  const [rows] = await pool.execute<any[]>("SELECT access_level FROM case_members WHERE case_id = ? AND user_id = ? LIMIT 1", [caseId, user.userId]);
  return (rows[0]?.access_level as CaseAccessLevel | undefined) ?? null;
}

export async function canAccessCase(user: AuthUser, caseId: number): Promise<boolean> {
  return (await caseAccessLevel(user, caseId)) !== null;
}

export async function denyCaseAccess(user: AuthUser, caseId: number, res: Response, message = "You do not have access to this case"): Promise<void> {
  await writeAudit(user.userId, "CASE_ACCESS_DENIED", "CASE", caseId, { role: user.role }).catch((error) => console.error("Case access denial audit failed", error));
  res.status(403).json({ error: message });
}

export async function requireCaseAccess(user: AuthUser, caseId: number, res: Response): Promise<boolean> {
  if (await canAccessCase(user, caseId)) return true;
  await denyCaseAccess(user, caseId, res);
  return false;
}

export async function requireCaseManage(user: AuthUser, caseId: number, res: Response): Promise<boolean> {
  if ((await caseAccessLevel(user, caseId)) === "MANAGE") return true;
  await denyCaseAccess(user, caseId, res, "Only case managers can change this case");
  return false;
}

export async function caseIdForEvidence(evidenceId: number): Promise<number | null> {
  const [rows] = await pool.execute<any[]>("SELECT case_id FROM evidence WHERE evidence_id = ? LIMIT 1", [evidenceId]);
  return rows.length ? Number(rows[0].case_id) : null;
}

export async function accessibleEvidenceIds(user: AuthUser): Promise<number[] | null> {
  if (user.role === "ADMIN") return null;
  const [rows] = await pool.execute<any[]>("SELECT e.evidence_id FROM evidence e WHERE e.case_id IN (SELECT case_id FROM case_members WHERE user_id = ?)", [user.userId]);
  return rows.map((row) => Number(row.evidence_id));
}
