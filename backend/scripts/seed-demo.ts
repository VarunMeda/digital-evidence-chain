import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import pool from "../src/db/mysql";
import { config } from "../src/config";

type User = { user_id: number; email: string };
type Case = { case_id: number };
type Evidence = { evidence_id: number; original_sha256: string };

const demoUsers = [
  { full_name: "Demo System Administrator", email: "admin.demo@example.test", password: "DemoAdmin123!", role: "ADMIN" },
  { full_name: "Demo Investigator", email: "investigator.demo@example.test", password: "DemoInvestigator123!", role: "INVESTIGATOR" },
  { full_name: "Demo Analyst", email: "analyst.demo@example.test", password: "DemoAnalyst123!", role: "ANALYST" },
  { full_name: "Demo Custodian One", email: "custodian.one@example.test", password: "DemoCustodian123!", role: "CUSTODIAN" },
  { full_name: "Demo Custodian Two", email: "custodian.two@example.test", password: "DemoCustodian456!", role: "CUSTODIAN" },
];

async function ensureUser(user: typeof demoUsers[number]): Promise<User> {
  const [existing] = await pool.execute<any[]>("SELECT user_id, email FROM users WHERE email=? LIMIT 1", [user.email]);
  if (existing.length) return existing[0] as User;
  const passwordHash = await bcrypt.hash(user.password, 12);
  const [result] = await pool.execute<any>("INSERT INTO users (full_name, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'ACTIVE')", [user.full_name, user.email, passwordHash, user.role]);
  return { user_id: result.insertId, email: user.email };
}

async function ensureCase(caseNumber: string, title: string, description: string, createdBy: number): Promise<Case> {
  const [existing] = await pool.execute<any[]>("SELECT case_id FROM cases WHERE case_number=? LIMIT 1", [caseNumber]);
  if (existing.length) return existing[0] as Case;
  const [result] = await pool.execute<any>("INSERT INTO cases (case_number, title, description, created_by) VALUES (?, ?, ?, ?)", [caseNumber, title, description, createdBy]);
  return { case_id: result.insertId };
}

async function ensureEvidence(code: string, caseId: number, name: string, custodianId: number, registeredBy: number, content: string): Promise<Evidence> {
  const [existing] = await pool.execute<any[]>("SELECT evidence_id, original_sha256 FROM evidence WHERE evidence_code=? LIMIT 1", [code]);
  if (existing.length) return existing[0] as Evidence;
  await fs.mkdir(config.storageRoot, { recursive: true });
  const storagePath = path.join(config.storageRoot, `demo-${code.toLowerCase()}.txt`);
  const bytes = Buffer.from(content, "utf8");
  await fs.writeFile(storagePath, bytes, { flag: "wx" }).catch((error: any) => { if (error.code !== "EEXIST") throw error; });
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  const [result] = await pool.execute<any>("INSERT INTO evidence (evidence_code, case_id, evidence_name, evidence_type, description, original_filename, storage_path, file_size_bytes, original_sha256, current_custodian, status, registered_by, collected_at) VALUES (?, ?, ?, 'TXT', ?, ?, ?, ?, ?, ?, 'IN_CUSTODY', ?, NOW())", [code, caseId, name, "Synthetic local demonstration evidence", `${code}.txt`, storagePath, bytes.length, digest, custodianId, registeredBy]);
  await pool.execute("INSERT INTO custody_records (evidence_id, event_type, from_user, to_user, performed_by, reason, location) VALUES (?, 'COLLECTED', NULL, ?, ?, 'Demo evidence registration', 'Local demo storage')", [result.insertId, custodianId, registeredBy]);
  return { evidence_id: result.insertId, original_sha256: digest };
}

async function ensureAnalysis(evidenceId: number, analystId: number, status: string, type: string, summary: string): Promise<void> {
  const [existing] = await pool.execute<any[]>("SELECT analysis_id FROM analysis_records WHERE evidence_id=? AND analysis_type=? LIMIT 1", [evidenceId, type]);
  if (existing.length) return;
  await pool.execute("INSERT INTO analysis_records (evidence_id, analyst_id, analysis_type, description, status, result_summary, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [evidenceId, analystId, type, "Synthetic local demonstration analysis", status, summary, status === "COMPLETED" ? new Date() : null, status === "COMPLETED" ? new Date() : null]);
}

async function ensureAlert(evidenceId: number, analystId: number, expected: string, actual: string): Promise<void> {
  const [existing] = await pool.execute<any[]>("SELECT alert_id FROM integrity_alerts WHERE evidence_id=? AND status <> 'RESOLVED' LIMIT 1", [evidenceId]);
  if (existing.length) return;
  await pool.execute("INSERT INTO integrity_alerts (evidence_id, expected_sha256, actual_sha256, detected_by, severity, status) VALUES (?, ?, ?, ?, 'HIGH', 'OPEN')", [evidenceId, expected, actual, analystId]);
}

async function ensureAudit(userId: number, action: string, entityType: string, entityId: number, details: object): Promise<void> {
  const [existing] = await pool.execute<any[]>("SELECT log_id FROM audit_logs WHERE action=? AND entity_type=? AND entity_id=? LIMIT 1", [action, entityType, entityId]);
  if (!existing.length) await pool.execute("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)", [userId, action, entityType, entityId, JSON.stringify(details)]);
}

async function main(): Promise<void> {
  const users = new Map<string, User>();
  for (const demoUser of demoUsers) users.set(demoUser.email, await ensureUser(demoUser));
  const admin = users.get("admin.demo@example.test")!;
  const investigator = users.get("investigator.demo@example.test")!;
  const analyst = users.get("analyst.demo@example.test")!;
  const custodianOne = users.get("custodian.one@example.test")!;
  const custodianTwo = users.get("custodian.two@example.test")!;
  const readyCase = await ensureCase("DEC-DEMO-001", "Local evidence workflow", "A safe synthetic case for demonstrating the complete dashboard workflow.", investigator.user_id);
  const alertCase = await ensureCase("DEC-DEMO-002", "Integrity alert workflow", "A synthetic case containing an intentionally open demonstration alert.", investigator.user_id);
  const readyEvidence = await ensureEvidence("EV-DEMO-001", readyCase.case_id, "Synthetic incident notes", custodianOne.user_id, investigator.user_id, "Synthetic evidence for local dashboard testing.\nThis is not real evidence.\n");
  const alertEvidence = await ensureEvidence("EV-DEMO-002", alertCase.case_id, "Synthetic altered notes", custodianTwo.user_id, investigator.user_id, "Synthetic evidence prepared for the integrity-alert demonstration.\n");
  await ensureAnalysis(readyEvidence.evidence_id, analyst.user_id, "COMPLETED", "Demo timeline review", "Synthetic timeline review completed.");
  await ensureAnalysis(alertEvidence.evidence_id, analyst.user_id, "PENDING", "Demo integrity review", "Pending demonstration analysis.");
  await ensureAlert(alertEvidence.evidence_id, analyst.user_id, alertEvidence.original_sha256, "0000000000000000000000000000000000000000000000000000000000000000");
  await ensureAudit(admin.user_id, "DEMO_DATA_SEEDED", "CASE", readyCase.case_id, { evidence_code: "EV-DEMO-001" });
  await ensureAudit(admin.user_id, "DEMO_DATA_SEEDED", "CASE", alertCase.case_id, { evidence_code: "EV-DEMO-002" });
  console.log("Local demo data is ready. Existing records were preserved.");
  console.log("Demo login accounts:");
  for (const user of demoUsers) console.log(`  ${user.role.padEnd(12)} ${user.email} / ${user.password}`);
  console.log("Cases: DEC-DEMO-001 (ready to close after review) and DEC-DEMO-002 (open alert/pending analysis).");
}

main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : "Demo seed failed"); process.exitCode = 1; }).finally(() => pool.end());
