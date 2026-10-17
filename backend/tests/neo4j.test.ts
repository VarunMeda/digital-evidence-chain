import assert from "node:assert/strict";
import http from "node:http";
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

test("protects the Neo4j health endpoint and accepts the existing Bearer session format", async () => {
  const names = ["NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD", "NEO4J_DATABASE"] as const;
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  const previousNodeEnv = process.env.NODE_ENV;
  try {
    for (const name of names) delete process.env[name];
    process.env.NODE_ENV = "test";
    const { app } = await import("../src/server");
    const { createSession } = await import("../src/middleware/auth");
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const base = `http://127.0.0.1:${address.port}`;
    try {
      const unauthenticated = await fetch(`${base}/api/integrations/neo4j-health`);
      assert.equal(unauthenticated.status, 401);
      assert.deepEqual(await unauthenticated.json(), { error: "Authentication required" });

      const token = createSession({ userId: 10, fullName: "Test Analyst", email: "analyst@example.test", role: "ANALYST" });
      const authenticated = await fetch(`${base}/api/integrations/neo4j-health`, { headers: { Authorization: `Bearer ${token}` } });
      assert.ok([200, 503].includes(authenticated.status));
      const body = await authenticated.json() as { service?: string; status: string; database?: string; error?: string; missing?: string[] };
      if (authenticated.status === 200) { assert.equal(body.status, "connected"); assert.equal(typeof body.database, "string"); }
      else { assert.equal(body.service, "neo4j"); assert.ok(["configuration_incomplete", "authentication_failed", "connectivity_failed", "query_failed"].includes(body.status)); assert.ok(body.error || body.missing); }

      const graphUnauthenticated = await fetch(`${base}/api/integrations/graph/evidence/1`);
      assert.equal(graphUnauthenticated.status, 401);
      const invalidGraphId = await fetch(`${base}/api/integrations/graph/evidence/not-an-id`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(invalidGraphId.status, 400);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  } finally {
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previousNodeEnv;
    for (const name of names) { if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name]; }
  }
});
