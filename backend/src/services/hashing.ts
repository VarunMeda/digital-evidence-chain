import { spawn } from "node:child_process";
import path from "node:path";
import { config } from "../config";

export function hashStoredFile(filePath: string): Promise<string> {
  const root = path.resolve(config.storageRoot);
  const resolved = path.resolve(filePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) return Promise.reject(new Error("File path is outside evidence storage"));
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.PYTHON_BIN || "python", [config.pythonService], { stdio: ["pipe", "pipe", "pipe"] });
    let output = ""; let error = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error("Hashing service timed out")); }, 15_000);
    child.stdout.on("data", (chunk) => { output += chunk.toString(); });
    child.stderr.on("data", (chunk) => { error += chunk.toString(); });
    child.on("error", (err) => { clearTimeout(timer); reject(err); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(error.trim() || "Hashing service failed")); return; }
      const digest = output.trim();
      if (!/^[a-f0-9]{64}$/.test(digest)) { reject(new Error("Hashing service returned an invalid digest")); return; }
      resolve(digest);
    });
    child.stdin.end(JSON.stringify({ path: resolved }));
  });
}
