const { spawn } = require("node:child_process");

process.env.NEXT_DIST_DIR = process.env.NEXT_DIST_DIR || ".next-dev";

const nextBin = require.resolve("next/dist/bin/next");
const child = spawn(process.execPath, [nextBin, "dev", ...process.argv.slice(2)], {
  stdio: "inherit",
  env: process.env,
});

child.on("exit", (code) => process.exit(code ?? 0));
