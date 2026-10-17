import pool from "../db/mysql";

export async function writeAudit(userId: number | null, action: string, entityType: string, entityId: number | null, details: Record<string, unknown>): Promise<void> {
  await pool.execute("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)", [userId, action, entityType, entityId, JSON.stringify(details)]);
}
