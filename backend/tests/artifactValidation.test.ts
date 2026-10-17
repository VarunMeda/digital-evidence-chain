import assert from "node:assert/strict";
import test from "node:test";
import { validateArtifactInput } from "../src/services/artifactValidation";

const valid = { evidence_id: 7, artifact_type: "IMAGE_METADATA", source_filename: "photo.jpg", fields: { width: 100, height: 80 }, parser: { name: "demo-parser", version: "1.0.0" }, observed_at: "2026-10-17T10:00:00.000Z", extraction_status: "COMPLETED", error: null, provenance: { source: "forensic-service", input_sha256: "a".repeat(64), method: "metadata-only" }, idempotency_key: "demo-artifact-001" };

test("accepts a valid artifact document", () => { const result = validateArtifactInput(valid); assert.equal(result.evidence_id, 7); assert.equal(result.provenance.source, "forensic-service"); assert.ok(result.observed_at instanceof Date); });
test("rejects unsupported types and malformed provenance", () => { assert.throws(() => validateArtifactInput({ ...valid, artifact_type: "RAW_BINARY" }), /Unsupported artifact_type/); assert.throws(() => validateArtifactInput({ ...valid, provenance: { ...valid.provenance, input_sha256: "bad" } }), /provenance/); });
test("rejects failed artifacts without a safe error and forbidden credentials", () => { assert.throws(() => validateArtifactInput({ ...valid, extraction_status: "FAILED", error: null }), /Failed artifacts/); assert.throws(() => validateArtifactInput({ ...valid, fields: { session_token: "secret" } }), /prohibited credential/); });
test("rejects oversized fields and unsafe filenames", () => { assert.throws(() => validateArtifactInput({ ...valid, fields: { payload: "x".repeat(256 * 1024) } }), /256 KB/); assert.throws(() => validateArtifactInput({ ...valid, source_filename: "..\\secret.txt" }), /safe filename/); });
