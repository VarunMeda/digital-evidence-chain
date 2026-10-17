export const ARTIFACT_TYPES = ["IMAGE_METADATA", "VIDEO_METADATA", "AUDIO_METADATA", "DOCUMENT_METADATA", "EXTRACTED_METADATA", "PARSER_FINDING", "OBSERVATION"] as const;
export const EXTRACTION_STATUSES = ["COMPLETED", "FAILED"] as const;

const sha256Pattern = /^[a-f0-9]{64}$/i;
const idempotencyPattern = /^[A-Za-z0-9._:-]{8,128}$/;
const forbiddenKeys = /password|token|secret|credential|session/i;

export type ArtifactInput = {
  evidence_id: number;
  artifact_type: typeof ARTIFACT_TYPES[number];
  source_filename: string | null;
  fields: Record<string, unknown>;
  parser: { name: string; version: string };
  observed_at: Date;
  extraction_status: typeof EXTRACTION_STATUSES[number];
  error: string | null;
  provenance: { source: string; input_sha256: string; method: string };
  idempotency_key: string;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function containsForbiddenKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsForbiddenKey);
  if (!isPlainObject(value)) return false;
  return Object.entries(value).some(([key, nested]) => forbiddenKeys.test(key) || containsForbiddenKey(nested));
}

export function validateArtifactInput(body: unknown): ArtifactInput {
  if (!isPlainObject(body)) throw new Error("Artifact payload must be a JSON object");
  if (containsForbiddenKey(body)) throw new Error("Artifact payload contains a prohibited credential field");
  const evidenceId = Number(body.evidence_id);
  if (!Number.isSafeInteger(evidenceId) || evidenceId < 1) throw new Error("A valid evidence_id is required");
  if (typeof body.artifact_type !== "string" || !ARTIFACT_TYPES.includes(body.artifact_type as any)) throw new Error("Unsupported artifact_type");
  if (!isPlainObject(body.fields)) throw new Error("fields must be a JSON object");
  if (JSON.stringify(body.fields).length > 256 * 1024) throw new Error("Artifact fields exceed the 256 KB limit");
  if (!isPlainObject(body.parser) || typeof body.parser.name !== "string" || typeof body.parser.version !== "string" || !body.parser.name.trim() || !body.parser.version.trim() || body.parser.name.length > 120 || body.parser.version.length > 60) throw new Error("parser name and version are required");
  const observed = typeof body.observed_at === "string" || body.observed_at instanceof Date ? new Date(body.observed_at) : new Date();
  if (Number.isNaN(observed.getTime())) throw new Error("observed_at must be a valid timestamp");
  if (typeof body.extraction_status !== "string" || !EXTRACTION_STATUSES.includes(body.extraction_status as any)) throw new Error("Invalid extraction_status");
  const error = body.error == null ? null : body.error;
  if (error !== null && (typeof error !== "string" || error.length > 1000)) throw new Error("error must be at most 1000 characters");
  if (body.extraction_status === "FAILED" && !error) throw new Error("Failed artifacts must include a safe error message");
  if (body.extraction_status === "COMPLETED" && error) throw new Error("Completed artifacts cannot include an error");
  if (!isPlainObject(body.provenance) || body.provenance.source !== "forensic-service" || typeof body.provenance.method !== "string" || !body.provenance.method.trim() || typeof body.provenance.input_sha256 !== "string" || !sha256Pattern.test(body.provenance.input_sha256)) throw new Error("provenance must identify forensic-service, method, and a SHA-256 input hash");
  if (typeof body.idempotency_key !== "string" || !idempotencyPattern.test(body.idempotency_key)) throw new Error("idempotency_key must be 8-128 safe characters");
  let sourceFilename: string | null = null;
  if (body.source_filename != null) {
    if (typeof body.source_filename !== "string" || !body.source_filename.trim() || body.source_filename.length > 255 || /[\\/]/.test(body.source_filename)) throw new Error("source_filename must be a safe filename");
    sourceFilename = body.source_filename.trim();
  }
  return { evidence_id: evidenceId, artifact_type: body.artifact_type as ArtifactInput["artifact_type"], source_filename: sourceFilename, fields: body.fields, parser: { name: body.parser.name.trim(), version: body.parser.version.trim() }, observed_at: observed, extraction_status: body.extraction_status as ArtifactInput["extraction_status"], error: error as string | null, provenance: { source: "forensic-service", input_sha256: body.provenance.input_sha256.toLowerCase(), method: body.provenance.method.trim() }, idempotency_key: body.idempotency_key };
}
