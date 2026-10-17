import { spawn } from "node:child_process";
import path from "node:path";
import { config } from "../config";

export type MetadataExtraction = { artifact_type: string; fields: Record<string, unknown>; extraction_status: "COMPLETED"; parser: { name: string; version: string }; provenance: { source: "forensic-service"; method: string } };

export function runMetadataExtractor(filePath: string, originalFilename: string, maxBytes = config.maxAnalysisBytes): Promise<MetadataExtraction> {
  const resolved = path.resolve(filePath);
  const root = path.resolve(config.storageRoot);
  if (resolved === root || !resolved.startsWith(`${root}${path.sep}`)) return Promise.reject(new Error("Evidence path is outside configured storage"));
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.PYTHON_BIN || "python", [config.pythonExtractorService], { env: { ...process.env, EVIDENCE_STORAGE_ROOT: root, PYTHONUNBUFFERED: "1" }, stdio: ["pipe", "pipe", "pipe"] });
    let output = ""; let errorOutput = ""; let settled = false;
    const finishError = (error: Error) => { if (!settled) { settled = true; clearTimeout(timer); child.kill(); reject(error); } };
    const timer = setTimeout(() => finishError(new Error("Metadata extraction timed out")), config.analysisTimeoutMs);
    child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); if (Buffer.byteLength(output) > config.maxAnalysisOutputBytes) finishError(new Error("Metadata extraction output exceeded the configured limit")); });
    child.stderr.on("data", (chunk: Buffer) => { errorOutput += chunk.toString(); if (errorOutput.length > 512) errorOutput = errorOutput.slice(0, 512); });
    child.on("error", (error) => finishError(new Error(error.message || "Metadata extraction service could not start")));
    child.on("close", (code) => {
      if (settled) return;
      clearTimeout(timer);
      if (code !== 0) { settled = true; reject(new Error(errorOutput.trim() || "Metadata extraction failed")); return; }
      try {
        const parsed = JSON.parse(output) as MetadataExtraction;
        if (!parsed || parsed.extraction_status !== "COMPLETED" || typeof parsed.artifact_type !== "string" || !parsed.fields || !parsed.parser?.name || !parsed.parser?.version || parsed.provenance?.source !== "forensic-service") throw new Error("Metadata extraction returned an invalid result");
        settled = true; resolve(parsed);
      } catch (error) { settled = true; reject(error instanceof Error ? error : new Error("Metadata extraction returned invalid JSON")); }
    });
    child.stdin.end(JSON.stringify({ path: resolved, original_filename: path.basename(originalFilename), max_bytes: maxBytes, max_output_bytes: config.maxAnalysisOutputBytes }));
  });
}
