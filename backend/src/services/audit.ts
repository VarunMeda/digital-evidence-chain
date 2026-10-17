import pool from "../db/mysql";
import type { Pool, PoolConnection } from "mysql2/promise";

type AuditExecutor = Pick<Pool, "execute"> | Pick<PoolConnection, "execute">;

export async function writeAudit(
  userId: number | null,
  action: string,
  entityType: string,
  entityId: number | null,
  details: Record<string, unknown>,
  executor: AuditExecutor = pool,
): Promise<void> {
  await executor.execute(
    "INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)",
    [userId, action, entityType, entityId, JSON.stringify(details)],
  );
}
