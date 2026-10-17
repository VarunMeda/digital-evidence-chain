import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import healthRouter from "./routes/health";
import dbHealthRouter from "./routes/dbHealth";
import casesRouter from "./routes/cases";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 4000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    message: "Digital Evidence Chain API",
    documentation: "Health check: /api/health"
  });
});

app.use("/api/health", healthRouter);
app.use("/api/db-health", dbHealthRouter);

app.use("/api/cases", casesRouter);

app.listen(PORT, () => {
  console.log(`Digital Evidence Chain API running at http://localhost:${PORT}`);
});
