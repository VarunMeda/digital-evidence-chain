import pool from "../db/mysql";
import { withNeo4jSession } from "./neo4j";
import type { Session } from "neo4j-driver";

type Row = Record<string, any>;
type GraphRecord = { graph_id: string; label: string; properties: Record<string, unknown> };

const SOURCE = "digital-evidence-chain:mysql";

function iso(value: unknown): string | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function graphNode(graph_id: string, label: string, properties: Record<string, unknown>): GraphRecord {
  return { graph_id, label, properties: { ...properties, graph_id, source_system: SOURCE } };
}

async function loadSourceData() {
  const rows = async (sql: string): Promise<Row[]> => (await pool.query(sql) as [Row[], unknown])[0];
  const [cases, evidence, users, custody, analysis] = await Promise.all([
    rows("SELECT case_id, case_number, title, description, status, created_by, created_at, closed_at FROM cases"),
    rows("SELECT evidence_id, evidence_code, case_id, evidence_name, evidence_type, original_filename, file_size_bytes, original_sha256, current_custodian, status, registered_by, collected_at, registered_at FROM evidence"),
    rows("SELECT user_id, full_name, email, role, status FROM users"),
    rows("SELECT custody_id, evidence_id, event_type, from_user, to_user, performed_by, reason, location, event_time FROM custody_records"),
    rows("SELECT analysis_id, evidence_id, analyst_id, analysis_type, description, status, result_summary, started_at, completed_at, created_at FROM analysis_records"),
  ]);

  const nodes: GraphRecord[] = [
    ...cases.map((row) => graphNode(`case:${row.case_id}`, "Case", { case_id: row.case_id, case_number: row.case_number, title: row.title, description: row.description, status: row.status, created_by: row.created_by, created_at: iso(row.created_at), closed_at: iso(row.closed_at) })),
    ...evidence.map((row) => graphNode(`evidence:${row.evidence_id}`, "Evidence", { evidence_id: row.evidence_id, evidence_code: row.evidence_code, case_id: row.case_id, name: row.evidence_name, evidence_type: row.evidence_type, original_filename: row.original_filename, file_size_bytes: row.file_size_bytes, original_sha256: row.original_sha256, current_custodian: row.current_custodian, status: row.status, registered_by: row.registered_by, collected_at: iso(row.collected_at), registered_at: iso(row.registered_at) })),
    ...users.map((row) => graphNode(`person:${row.user_id}`, "Person", { user_id: row.user_id, name: row.full_name, email: row.email, role: row.role, status: row.status })),
    ...custody.map((row) => graphNode(`custody:${row.custody_id}`, "CustodyEvent", { custody_id: row.custody_id, evidence_id: row.evidence_id, event_type: row.event_type, from_user: row.from_user, to_user: row.to_user, performed_by: row.performed_by, reason: row.reason, location: row.location, event_time: iso(row.event_time) })),
    ...analysis.map((row) => graphNode(`analysis:${row.analysis_id}`, "Analysis", { analysis_id: row.analysis_id, evidence_id: row.evidence_id, analyst_id: row.analyst_id, analysis_type: row.analysis_type, description: row.description, status: row.status, result_summary: row.result_summary, started_at: iso(row.started_at), completed_at: iso(row.completed_at), created_at: iso(row.created_at) })),
  ];
  return { cases, evidence, users, custody, analysis, nodes };
}

const constraints = [
  "CREATE CONSTRAINT case_graph_id_unique IF NOT EXISTS FOR (n:Case) REQUIRE n.graph_id IS UNIQUE",
  "CREATE CONSTRAINT evidence_graph_id_unique IF NOT EXISTS FOR (n:Evidence) REQUIRE n.graph_id IS UNIQUE",
  "CREATE CONSTRAINT person_graph_id_unique IF NOT EXISTS FOR (n:Person) REQUIRE n.graph_id IS UNIQUE",
  "CREATE CONSTRAINT custody_graph_id_unique IF NOT EXISTS FOR (n:CustodyEvent) REQUIRE n.graph_id IS UNIQUE",
  "CREATE CONSTRAINT analysis_graph_id_unique IF NOT EXISTS FOR (n:Analysis) REQUIRE n.graph_id IS UNIQUE",
];

export type GraphSyncResult = { cases: number; evidence: number; people: number; custody_events: number; analyses: number; removed_nodes: number; completed_at: string };
export class Neo4jGraphNotFoundError extends Error { constructor(public readonly graphId: string) { super("Graph root not found"); } }
let lastSync: GraphSyncResult | null = null;

export function getLastNeo4jSync(): GraphSyncResult | null { return lastSync; }

export async function syncNeo4jGraph(): Promise<GraphSyncResult> {
  const source = await loadSourceData();
  const validIds = source.nodes.map((node) => node.graph_id);
  const result = await withNeo4jSession("WRITE", async (session) => {
    for (const statement of constraints) await session.run(statement);
    const staleResult = await session.run("MATCH (n {source_system: $source}) WHERE NOT n.graph_id IN $validIds RETURN collect(n.graph_id) AS stale", { source: SOURCE, validIds });
    const staleIds = (staleResult.records[0]?.get("stale") || []) as string[];
    if (staleIds.length) await session.run("UNWIND $staleIds AS id MATCH (n {source_system: $source, graph_id: id}) DETACH DELETE n", { source: SOURCE, staleIds });
    for (const node of source.nodes) await session.run(`MERGE (n:${node.label} {graph_id: $graph_id}) SET n = $properties`, node);

    for (const row of source.evidence) {
      await session.run("MATCH (c:Case {graph_id:$caseId}), (e:Evidence {graph_id:$evidenceId}) MERGE (c)-[:HAS_EVIDENCE]->(e)", { caseId: `case:${row.case_id}`, evidenceId: `evidence:${row.evidence_id}` });
    }
    for (const row of source.custody) {
      await session.run("MATCH (ce:CustodyEvent {graph_id:$custodyId}), (e:Evidence {graph_id:$evidenceId}) MERGE (ce)-[:CONCERNS]->(e)", { custodyId: `custody:${row.custody_id}`, evidenceId: `evidence:${row.evidence_id}` });
      if (row.performed_by) await session.run("MATCH (p:Person {graph_id:$personId}), (ce:CustodyEvent {graph_id:$custodyId}) MERGE (p)-[:PERFORMED]->(ce)", { personId: `person:${row.performed_by}`, custodyId: `custody:${row.custody_id}` });
      if (row.event_type === "COLLECTED" && row.to_user) await session.run("MATCH (p:Person {graph_id:$personId}), (e:Evidence {graph_id:$evidenceId}) MERGE (p)-[:COLLECTED]->(e)", { personId: `person:${row.to_user}`, evidenceId: `evidence:${row.evidence_id}` });
      if (row.event_type === "TRANSFERRED" && row.to_user) await session.run("MATCH (p:Person {graph_id:$personId}), (ce:CustodyEvent {graph_id:$custodyId}) MERGE (p)-[:TRANSFERRED]->(ce)", { personId: `person:${row.to_user}`, custodyId: `custody:${row.custody_id}` });
    }
    for (const row of source.analysis) {
      await session.run("MATCH (e:Evidence {graph_id:$evidenceId}), (a:Analysis {graph_id:$analysisId}) MERGE (e)-[:HAS_ANALYSIS]->(a)", { evidenceId: `evidence:${row.evidence_id}`, analysisId: `analysis:${row.analysis_id}` });
      if (row.analyst_id) await session.run("MATCH (p:Person {graph_id:$personId}), (a:Analysis {graph_id:$analysisId}) MERGE (p)-[:PERFORMED]->(a)", { personId: `person:${row.analyst_id}`, analysisId: `analysis:${row.analysis_id}` });
    }
    return staleIds.length;
  });
  lastSync = { cases: source.cases.length, evidence: source.evidence.length, people: source.users.length, custody_events: source.custody.length, analyses: source.analysis.length, removed_nodes: result, completed_at: new Date().toISOString() };
  return lastSync;
}

function safeDepth(value: unknown): number { const n = Number(value); return Number.isInteger(n) && n >= 1 ? Math.min(n, 2) : 1; }
function safeLimit(value: unknown): number { const n = Number(value); return Number.isInteger(n) && n >= 1 ? Math.min(n, 200) : 100; }

export async function readGraph(rootLabel: "Case" | "Evidence", rootId: number, depthValue: unknown, limitValue: unknown) {
  const depth = safeDepth(depthValue); const limit = safeLimit(limitValue);
  return withNeo4jSession("READ", async (session) => readGraphWithSession(session, rootLabel, rootId, depth, limit));
}

export async function readGraphWithSession(session: Pick<Session, "run">, rootLabel: "Case" | "Evidence", rootId: number, depth: number, limit: number) {
    const graphId = `${rootLabel.toLowerCase()}:${rootId}`;
    const rootResult = await session.run(`MATCH (root:${rootLabel} {graph_id:$rootId, source_system:$source}) RETURN count(root) AS root_count`, { rootId: graphId, source: SOURCE });
    if (rootResult.records[0]?.get("root_count") !== 1) throw new Neo4jGraphNotFoundError(graphId);
    const result = await session.run(`MATCH p=(root:${rootLabel} {graph_id:$rootId, source_system:$source})-[*1..${depth}]-(n) RETURN [node IN nodes(p) | {graph_id: node.graph_id, labels: labels(node), properties: properties(node)}] AS path_nodes, [rel IN relationships(p) | {type: type(rel), from: startNode(rel).graph_id, to: endNode(rel).graph_id, properties: properties(rel)}] AS path_relationships LIMIT ${limit}`, { rootId: graphId, source: SOURCE });
    const nodes = new Map<string, any>(); const relationships = new Map<string, any>();
    for (const record of result.records) {
      for (const node of record.get("path_nodes") || []) nodes.set(node.graph_id, node);
      for (const rel of record.get("path_relationships") || []) relationships.set(`${rel.type}:${rel.from}:${rel.to}:${JSON.stringify(rel.properties || {})}`, rel);
    }
    return { root: graphId, depth, limit, nodes: [...nodes.values()], relationships: [...relationships.values()], last_sync: lastSync };
}
