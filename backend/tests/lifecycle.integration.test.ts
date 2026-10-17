import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

const testDatabase = process.env.LIFECYCLE_TEST_DATABASE;

test("evidence lifecycle integration", { skip: !testDatabase }, async () => {
  const configuredDatabase = process.env.DB_NAME || "digital_evidence_chain";
  assert.notEqual(testDatabase, configuredDatabase, "LIFECYCLE_TEST_DATABASE must be separate from DB_NAME");
  process.env.NODE_ENV = "test";
  process.env.DB_NAME = testDatabase;
  const storageRoot = await fs.mkdtemp(path.join(os.tmpdir(), "dec-lifecycle-storage-"));
  process.env.EVIDENCE_STORAGE_ROOT = storageRoot;
  process.env.PYTHON_SERVICE_PATH = path.resolve("..", "forensic-service", "hash_file.py");

  const mysql = await import("mysql2/promise");
  const bcrypt = await import("bcryptjs");
  const pool = mysql.default.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD,
    database: testDatabase,
  });
  const { app } = await import("../src/server");
  const { createSession } = await import("../src/middleware/auth");
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  const runId = crypto.randomBytes(5).toString("hex");
  const email = (role: string) => `lifecycle-${role.toLowerCase()}-${runId}@example.test`;
  const users: Record<string, { userId: number; fullName: string; email: string; role: any }> = {};
  const hash = await bcrypt.hash("integration-test-password", 4);

  async function request(route: string, init: RequestInit = {}) {
    const response = await fetch(`${base}${route}`, init);
    let body: any = null;
    try { body = await response.json(); } catch { /* empty response */ }
    return { status: response.status, body };
  }
  function auth(user: { userId: number; fullName: string; email: string; role: string }) { return { Authorization: `Bearer ${createSession(user as any)}` }; }
  async function makeUser(role: string, status = "ACTIVE") {
    const address = email(`${role}${status}${Object.keys(users).length}`);
    const [result] = await pool.execute<any>("INSERT INTO users (full_name, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)", [`Lifecycle ${role} ${runId}`, address, hash, role, status]);
    const user = { userId: result.insertId, fullName: `Lifecycle ${role}`, email: address, role };
    users[`${role}-${status}-${Object.keys(users).length}`] = user;
    return user;
  }
  async function makeCase(label: string) {
    const [result] = await pool.execute<any>("INSERT INTO cases (case_number, title, created_by) VALUES (?, ?, ?)", [`TEST-${runId}-${label}`, `Lifecycle ${label}`, users.investigator.userId]);
    return result.insertId as number;
  }
  async function makeEvidence(caseId: number, status = "REGISTERED", currentCustodian: number | null = users.investigator.userId) {
    const bytes = Buffer.from(`fixture-${runId}-${caseId}-${status}`);
    const filePath = path.join(storageRoot, `fixture-${caseId}-${status}`);
    await fs.writeFile(filePath, bytes);
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    const [result] = await pool.execute<any>("INSERT INTO evidence (evidence_code, case_id, evidence_name, evidence_type, original_filename, storage_path, file_size_bytes, original_sha256, current_custodian, status, registered_by, collected_at) VALUES (?, ?, ?, 'TXT', ?, ?, ?, ?, ?, ?, ?, NOW())", [`TEST-EV-${runId}-${caseId}-${status}`, caseId, "Lifecycle fixture", "fixture.txt", filePath, bytes.length, digest, currentCustodian, status, users.investigator.userId]);
    return { id: result.insertId as number, path: filePath };
  }

  try {
    users.investigator = await makeUser("INVESTIGATOR");
    users.analyst = await makeUser("ANALYST");
    users.custodian1 = await makeUser("CUSTODIAN");
    users.custodian2 = await makeUser("CUSTODIAN");
    users.custodian3 = await makeUser("CUSTODIAN");
    users.inactiveCustodian = await makeUser("CUSTODIAN", "INACTIVE");
    const caseId = await makeCase("upload");
    const investigatorHeaders = auth(users.investigator);
    const custodianHeaders = auth(users.custodian1);
    const analystHeaders = auth(users.analyst);

    const pdfBytes = Buffer.from("%PDF-1.7\nsynthetic lifecycle evidence");
    const uploadForm = new FormData();
    uploadForm.set("case_id", String(caseId));
    uploadForm.set("evidence_name", "Lifecycle PDF");
    uploadForm.set("evidence_type", "AUTO");
    uploadForm.set("evidence", new Blob([pdfBytes], { type: "application/pdf" }), "lifecycle.pdf");
    const uploaded = await request("/api/evidence", { method: "POST", headers: investigatorHeaders, body: uploadForm });
    assert.equal(uploaded.status, 201);
    const [rows] = await pool.execute<any[]>("SELECT * FROM evidence WHERE evidence_id = ?", [uploaded.body.evidence_id]);
    assert.equal(rows.length, 1);
    assert.equal(await fs.readFile(rows[0].storage_path).then((value) => value.equals(pdfBytes)), true);
    assert.equal(rows[0].original_sha256, crypto.createHash("sha256").update(pdfBytes).digest("hex"));

    const matching = await request(`/api/evidence/${uploaded.body.evidence_id}/verify`, { method: "POST", headers: analystHeaders });
    assert.equal(matching.status, 200);
    assert.equal(matching.body.matches, true);

    const invalidDestination = await request(`/api/evidence/${uploaded.body.evidence_id}/transfer`, { method: "POST", headers: investigatorHeaders, body: JSON.stringify({ to_user_id: users.analyst.userId }) });
    assert.equal(invalidDestination.status, 409);
    const validTransfer = await request(`/api/evidence/${uploaded.body.evidence_id}/transfer`, { method: "POST", headers: investigatorHeaders, body: JSON.stringify({ to_user_id: users.custodian1.userId, reason: "Examination" }) });
    assert.equal(validTransfer.status, 200);
    const staleTransfer = await request(`/api/evidence/${uploaded.body.evidence_id}/transfer`, { method: "POST", headers: investigatorHeaders, body: JSON.stringify({ to_user_id: users.custodian2.userId }) });
    assert.equal(staleTransfer.status, 409);
    const inactiveDestination = await request(`/api/evidence/${uploaded.body.evidence_id}/transfer`, { method: "POST", headers: custodianHeaders, body: JSON.stringify({ to_user_id: users.inactiveCustodian.userId }) });
    assert.equal(inactiveDestination.status, 409);

    const [stored] = await pool.execute<any[]>("SELECT storage_path, original_sha256 FROM evidence WHERE evidence_id = ?", [uploaded.body.evidence_id]);
    await fs.appendFile(stored[0].storage_path, Buffer.from("controlled test mutation"));
    const mismatch = await request(`/api/evidence/${uploaded.body.evidence_id}/verify`, { method: "POST", headers: analystHeaders });
    assert.equal(mismatch.status, 200);
    assert.equal(mismatch.body.matches, false);
    const [flagged] = await pool.execute<any[]>("SELECT status FROM evidence WHERE evidence_id = ?", [uploaded.body.evidence_id]);
    assert.equal(flagged[0].status, "FLAGGED");
    const [alerts] = await pool.execute<any[]>("SELECT COUNT(*) AS count FROM integrity_alerts WHERE evidence_id = ?", [uploaded.body.evidence_id]);
    assert.equal(Number(alerts[0].count), 1);
    await assert.rejects(() => pool.execute("UPDATE evidence SET original_sha256 = ? WHERE evidence_id = ?", ["0".repeat(64), uploaded.body.evidence_id]), /immutable/i);

    const missingCaseForm = new FormData();
    missingCaseForm.set("case_id", "999999999");
    missingCaseForm.set("evidence_name", "Missing case");
    missingCaseForm.set("evidence_type", "AUTO");
    missingCaseForm.set("evidence", new Blob([pdfBytes]), "missing.pdf");
    assert.equal((await request("/api/evidence", { method: "POST", headers: investigatorHeaders, body: missingCaseForm })).status, 404);
    const invalidForm = new FormData();
    invalidForm.set("case_id", String(caseId));
    invalidForm.set("evidence_name", "Invalid file");
    invalidForm.set("evidence_type", "AUTO");
    invalidForm.set("evidence", new Blob(["not a PDF"]), "fake.pdf");
    assert.equal((await request("/api/evidence", { method: "POST", headers: investigatorHeaders, body: invalidForm })).status, 400);

    const validCase = await makeCase("close-valid");
    assert.equal((await request(`/api/cases/${validCase}/status`, { method: "PATCH", headers: { ...investigatorHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ status: "CLOSED" }) })).status, 200);
    const pendingCase = await makeCase("close-pending");
    const pendingEvidence = await makeEvidence(pendingCase);
    await pool.execute("INSERT INTO analysis_records (evidence_id, analyst_id, analysis_type, status) VALUES (?, ?, 'pending fixture', 'PENDING')", [pendingEvidence.id, users.analyst.userId]);
    assert.equal((await request(`/api/cases/${pendingCase}/status`, { method: "PATCH", headers: { ...investigatorHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ status: "CLOSED" }) })).status, 409);
    const alertCase = await makeCase("close-alert");
    const alertEvidence = await makeEvidence(alertCase);
    await pool.execute("INSERT INTO integrity_alerts (evidence_id, expected_sha256, actual_sha256, detected_by, severity) VALUES (?, ?, ?, ?, 'HIGH')", [alertEvidence.id, "1".repeat(64), "2".repeat(64), users.analyst.userId]);
    assert.equal((await request(`/api/cases/${alertCase}/status`, { method: "PATCH", headers: { ...investigatorHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ status: "CLOSED" }) })).status, 409);
    const custodyCase = await makeCase("close-custody");
    await makeEvidence(custodyCase, "REGISTERED", null);
    assert.equal((await request(`/api/cases/${custodyCase}/status`, { method: "PATCH", headers: { ...investigatorHeaders, "Content-Type": "application/json" }, body: JSON.stringify({ status: "CLOSED" }) })).status, 409);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await pool.end();
    await fs.rm(storageRoot, { recursive: true, force: true });
  }
});
