import assert from "node:assert/strict";
import test from "node:test";
import { getNeo4jSettings, Neo4jConfigurationError, verifyNeo4jConnection } from "../src/services/neo4j";

test("reports the exact missing Neo4j configuration variables without connecting", async () => {
  const names = ["NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD", "NEO4J_DATABASE"] as const;
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    const result = getNeo4jSettings();
    assert.deepEqual(result.missing, ["NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"]);
    await assert.rejects(verifyNeo4jConnection, (error: unknown) => error instanceof Neo4jConfigurationError && error.missing.join(",") === "NEO4J_URI,NEO4J_USER,NEO4J_PASSWORD");
  } finally {
    for (const name of names) { if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name]; }
  }
});
