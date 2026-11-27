#!/usr/bin/env node
// preToolUse hook: deny `git commit` calls whose message has no `Models:` trailer.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const reason = "Commit message has no Models: trailer. Invoke the /tc:commit skill to write the message, then commit with it.";

function command(event) {
  let args = event.toolArgs ?? event.tool_input ?? {};
  if (typeof args === "string") {
    try { args = JSON.parse(args); } catch { return args; }
  }
  return typeof args.command === "string" ? args.command : "";
}

function messageFile(cmd, cwd) {
  const match = cmd.match(/(?:-F|--file)[= ]\s*("[^"]+"|'[^']+'|\S+)/);
  if (!match) return "";
  try {
    return readFileSync(path.resolve(cwd, match[1].replace(/^["']|["']$/g, "")), "utf8");
  } catch {
    return "";
  }
}

export function decide(event) {
  const cmd = command(event);
  if (!/\bgit\b(?:\s+-\S+(?:\s+\S+)?)*\s+commit\b/.test(cmd)) return null;
  if (/--no-edit\b/.test(cmd) || /Models:\s*\S/.test(cmd)) return null;
  if (/^Models:\s*\S/m.test(messageFile(cmd, event.cwd ?? process.cwd()))) return null;
  return { permissionDecision: "deny", permissionDecisionReason: reason };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const decision = decide(JSON.parse(readFileSync(0, "utf8") || "{}"));
  if (decision) process.stdout.write(JSON.stringify(decision));
}
