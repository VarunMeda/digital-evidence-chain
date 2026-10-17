import { Router } from "express";
import pool from "../db/mysql";
import type { ResultSetHeader, RowDataPacket } from "mysql2";

const router = Router();

interface CaseRow extends RowDataPacket {
  case_id: number;
  case_number: string;
  title: string;
  description: string | null;
  created_by: number;
  status: string;
  created_at: Date;
}

// Create a case
router.post("/", async (req, res) => {
  const { case_number, title, description, created_by } = req.body ?? {};

  if (
    typeof case_number !== "string" ||
    !case_number.trim() ||
    typeof title !== "string" ||
    !title.trim() ||
    !Number.isInteger(created_by) ||
    created_by <= 0
  ) {
    return res.status(400).json({
      error: "case_number, title, and a valid created_by user ID are required"
    });
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO cases (case_number, title, description, created_by)
       VALUES (?, ?, ?, ?)`,
      [
        case_number.trim(),
        title.trim(),
        typeof description === "string" ? description.trim() || null : null,
        created_by
      ]
    );

    return res.status(201).json({
      message: "Case created successfully",
      case_id: result.insertId,
      case_number: case_number.trim()
    });
  } catch (error: unknown) {
    const mysqlError = error as { code?: string };

    if (mysqlError.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        error: "A case with this case number already exists"
      });
    }

    console.error("Case creation failed:", error);

    return res.status(500).json({
      error: "Failed to create case"
    });
  }
});

// List cases
router.get("/", async (_req, res) => {
  try {
    const [rows] = await pool.query<CaseRow[]>(
      `SELECT case_id, case_number, title, description,
              created_by, status, created_at
       FROM cases
       ORDER BY created_at DESC`
    );

    return res.json(rows);
  } catch (error) {
    console.error("Failed to retrieve cases:", error);
    return res.status(500).json({ error: "Failed to retrieve cases" });
  }
});

// Retrieve one case
router.get("/:id", async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid case ID" });
  }

  try {
    const [rows] = await pool.execute<CaseRow[]>(
      `SELECT case_id, case_number, title, description,
              created_by, status, created_at
       FROM cases
       WHERE case_id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Case not found" });
    }

    return res.json(rows[0]);
  } catch (error) {
    console.error("Failed to retrieve case:", error);
    return res.status(500).json({ error: "Failed to retrieve case" });
  }
});

export default router;