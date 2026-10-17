import assert from "node:assert/strict";
import test from "node:test";
import { Neo4jGraphNotFoundError, readGraphWithSession } from "../src/services/neo4jGraph";

function record(values: Record<string, unknown>) { return { get: (key: string) => values[key] }; }

test("reads a bounded graph with an integer Cypher LIMIT", async () => {
  const queries: string[] = [];
  const session = { run: async (query: string) => { queries.push(query); return queries.length === 1 ? { records: [record({ root_count: 1 })] } : { records: [record({ path_nodes: [{ graph_id: "evidence:1", labels: ["Evidence"], properties: { evidence_id: 1 } }], path_relationships: [{ type: "HAS_ANALYSIS", from: "evidence:1", to: "analysis:1", properties: {} }] })] }; } };
  const result = await readGraphWithSession(session, "Evidence", 1, 2, 100);
  assert.equal(result.nodes.length, 1);
  assert.equal(result.relationships.length, 1);
  assert.match(queries[1], /LIMIT 100$/);
  assert.doesNotMatch(queries[1], /LIMIT \$limit/);
});

test("reports a missing graph root instead of returning an empty success", async () => {
  const session = { run: async () => ({ records: [record({ root_count: 0 })] }) };
  await assert.rejects(() => readGraphWithSession(session, "Evidence", 999, 1, 100), (error: unknown) => error instanceof Neo4jGraphNotFoundError && error.graphId === "evidence:999");
});
