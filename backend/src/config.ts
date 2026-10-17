import path from "node:path";
import dotenv from "dotenv";

dotenv.config();

const storageRoot = process.env.EVIDENCE_STORAGE_ROOT || path.resolve(process.cwd(), "evidence-storage");

export const config = {
  port: Number(process.env.PORT) || 4000,
  frontendOrigin: process.env.FRONTEND_ORIGIN || "http://localhost:3000",
  storageRoot: path.resolve(storageRoot),
  maxUploadBytes: Number(process.env.MAX_UPLOAD_BYTES) || 10 * 1024 * 1024,
  pythonService: process.env.PYTHON_SERVICE_PATH || path.resolve(process.cwd(), "..", "forensic-service", "hash_file.py"),
  sessionSecret: process.env.SESSION_SECRET || "development-only-change-me",
};

if (config.sessionSecret === "development-only-change-me" && process.env.NODE_ENV === "production") {
  throw new Error("SESSION_SECRET must be configured in production");
}
