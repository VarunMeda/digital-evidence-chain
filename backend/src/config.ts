import path from "node:path";
import dotenv from "dotenv";

dotenv.config();

const storageRoot = process.env.EVIDENCE_STORAGE_ROOT || path.resolve(process.cwd(), "evidence-storage");

export const config = {
  port: Number(process.env.PORT) || 4000,
  frontendOrigin: process.env.FRONTEND_ORIGIN || "http://localhost:3000",
  storageRoot: path.resolve(storageRoot),
  maxUploadBytes: Number(process.env.MAX_UPLOAD_BYTES) || 512 * 1024 * 1024,
  pythonService: process.env.PYTHON_SERVICE_PATH || path.resolve(process.cwd(), "..", "forensic-service", "hash_file.py"),
  pythonExtractorService: process.env.PYTHON_EXTRACTOR_PATH || path.resolve(process.cwd(), "..", "forensic-service", "extract_metadata.py"),
  maxAnalysisBytes: Number(process.env.MAX_ANALYSIS_BYTES) || 512 * 1024 * 1024,
  maxAnalysisOutputBytes: Number(process.env.MAX_ANALYSIS_OUTPUT_BYTES) || 256 * 1024,
  analysisTimeoutMs: Number(process.env.ANALYSIS_TIMEOUT_MS) || 30_000,
  sessionSecret: process.env.SESSION_SECRET || "development-only-change-me",
};

if (config.sessionSecret === "development-only-change-me" && process.env.NODE_ENV === "production") {
  throw new Error("SESSION_SECRET must be configured in production");
}
