import neo4j, { type Session } from "neo4j-driver";

export type Neo4jSettings = { uri: string; user: string; password: string; database: string };

export function getNeo4jSettings(): { settings?: Neo4jSettings; missing: string[] } {
  const settings = { uri: process.env.NEO4J_URI?.trim(), user: process.env.NEO4J_USER?.trim(), password: process.env.NEO4J_PASSWORD, database: process.env.NEO4J_DATABASE?.trim() || "neo4j" };
  const missing = [!settings.uri && "NEO4J_URI", !settings.user && "NEO4J_USER", !settings.password && "NEO4J_PASSWORD"].filter(Boolean) as string[];
  return missing.length ? { missing } : { settings: settings as Neo4jSettings, missing: [] };
}

export class Neo4jConfigurationError extends Error {
  constructor(public readonly missing: string[]) { super("Neo4j configuration is incomplete"); }
}

export function createNeo4jDriver() {
  const configured = getNeo4jSettings();
  if (!configured.settings) throw new Neo4jConfigurationError(configured.missing);
  return neo4j.driver(configured.settings.uri, neo4j.auth.basic(configured.settings.user, configured.settings.password), { connectionTimeout: 1500, disableLosslessIntegers: true });
}

export async function withNeo4jSession<T>(mode: "READ" | "WRITE", operation: (session: Session) => Promise<T>): Promise<T> {
  const configured = getNeo4jSettings();
  if (!configured.settings) throw new Neo4jConfigurationError(configured.missing);
  const driver = createNeo4jDriver();
  const session = driver.session({ database: configured.settings.database, defaultAccessMode: mode === "READ" ? neo4j.session.READ : neo4j.session.WRITE });
  try { return await operation(session); }
  finally { await session.close(); await driver.close(); }
}

export async function verifyNeo4jConnection(): Promise<{ status: "connected"; database: string }> {
  const configured = getNeo4jSettings();
  if (!configured.settings) throw new Neo4jConfigurationError(configured.missing);
  const database = configured.settings.database;
  return await withNeo4jSession("READ", async (session) => {
    const result = await session.run("RETURN 1 AS ok");
    if (result.records[0]?.get("ok") !== 1) throw new Error("Neo4j health query returned an unexpected result");
    return { status: "connected", database };
  });
}
