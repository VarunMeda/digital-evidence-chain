import { syncNeo4jGraph } from "../src/services/neo4jGraph";
import pool from "../src/db/mysql";

async function main() {
  const result = await syncNeo4jGraph();
  console.log(JSON.stringify({ status: "completed", sync: result }, null, 2));
}

main().catch((error) => {
  console.error("Neo4j synchronization failed:", error instanceof Error ? error.message : "unknown error");
  process.exitCode = 1;
}).finally(async () => { await pool.end(); });
