import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import healthRouter from "./routes/health";
import dbHealthRouter from "./routes/dbHealth";
import casesRouter from "./routes/cases";
import authRouter from "./routes/auth";
import usersRouter from "./routes/users";
import evidenceRouter from "./routes/evidence";
import analysisRouter from "./routes/analysis";
import auditRouter from "./routes/audit";
import integrationsRouter from "./routes/integrations";
import operationsRouter from "./routes/operations";
import fs from "node:fs/promises";
import { config } from "./config";

dotenv.config();

export const app = express();
const PORT = Number(process.env.PORT) || 4000;

const configuredFrontendOrigin = process.env.FRONTEND_ORIGIN;
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origin === configuredFrontendOrigin || (!configuredFrontendOrigin && process.env.NODE_ENV !== "production" && /^https?:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin))) {
      callback(null, true);
      return;
    }
    callback(new Error("Frontend origin is not allowed"));
  }
}));
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    message: "Digital Evidence Chain API",
    documentation: "Health check: /api/health"
  });
});

app.use("/api/health", healthRouter);
app.use("/api/db-health", dbHealthRouter);
app.use("/api/auth", authRouter);
app.use("/api/users", usersRouter);

app.use("/api/cases", casesRouter);
app.use("/api/evidence", evidenceRouter);
app.use("/api/analysis", analysisRouter);
app.use("/api/audit", auditRouter);
app.use("/api/integrations", integrationsRouter);
app.use("/api/operations", operationsRouter);

app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (error?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "Uploaded file exceeds the configured size limit" });
  if (error?.message === "Invalid filename") return res.status(400).json({ error: "Invalid evidence filename" });
  console.error("Unhandled API error", error);
  return res.status(500).json({ error: "Internal server error" });
});

if (process.env.NODE_ENV !== "test") {
  fs.mkdir(config.storageRoot, { recursive: true }).catch((error) => console.error("Could not create evidence storage", error));
  app.listen(PORT, () => console.log(`Digital Evidence Chain API running at http://localhost:${PORT}`));
}
