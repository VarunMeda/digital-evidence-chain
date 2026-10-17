import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { detectEvidenceType, validateEvidenceFile } from "../src/services/evidenceValidation";

const vectors: Array<[string, Buffer, string]> = [
  ["sample.pdf", Buffer.from("%PDF-1.7\nsynthetic"), "PDF"],
  ["sample.docx", Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00]), "DOCX"],
  ["sample.jpg", Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00]), "JPG"],
  ["sample.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "PNG"],
  ["sample.mp4", Buffer.from([0, 0, 0, 0, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]), "MP4"]
];

describe("evidence format validation", () => {
  let directory: string;
  beforeEach(async () => { directory = await mkdtemp(path.join(os.tmpdir(), "dec-evidence-")); });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  for (const [name, bytes, expected] of vectors) it(`accepts ${expected}`, async () => { const file = path.join(directory, name); await writeFile(file, bytes); assert.equal(await validateEvidenceFile(file, name, 1024 * 1024), expected); });
  it("rejects a renamed unsupported file", async () => { const file = path.join(directory, "fake.pdf"); await writeFile(file, Buffer.from("not a PDF")); await assert.rejects(() => detectEvidenceType(file, "fake.pdf"), /does not match/); });
  it("rejects an oversized file before registration", async () => { const file = path.join(directory, "large.txt"); await writeFile(file, Buffer.from("0123456789")); await assert.rejects(() => validateEvidenceFile(file, "large.txt", 4), /exceeds/); });
});
