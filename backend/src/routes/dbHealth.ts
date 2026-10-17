import { Router } from "express";
import pool from "../db/mysql";

const router = Router();

router.get("/", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT DATABASE() AS database_name, VERSION() AS mysql_version");
    res.status(200).json({
      status: "connected",
      database: rows
    });
  } catch (error) {
    console.error("Database connection failed:", error);
    res.status(500).json({
      status: "error",
      message: "Could not connect to the database"
    });
  }
});

export default router;
