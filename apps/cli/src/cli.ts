/**
 * `promptwarden` bin entry — dispatches to the subcommand modules. Every
 * import here is static; dynamic imports are banned by the CI no-egress
 * gate, so the whole dispatcher typechecks and bundles as one unit.
 * (no-egress-doc: the line above names a banned API as documentation.)
 */
import { pathToFileURL } from "node:url";
import { runEmitExclusions } from "./exclusions.js";
import { runClaudeCodeHook } from "./hooks/claude-code.js";
import { runMcpGateway } from "./mcp/gateway.js";
import { runScan } from "./scan.js";

const VERSION = "0.1.0";

const USAGE = `promptwarden — local, deterministic guardrail for sensitive data leaving this machine.

Usage:
  promptwarden scan [--stdin] [--file <path>]... [--json] [--strict] [--surface <label>]
  promptwarden hook claude-code
  promptwarden mcp -- <server command...>
  promptwarden emit-exclusions [options]
  promptwarden --version
  promptwarden --help

Everything runs locally: deterministic, no network calls, no LLM calls.
`;

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  switch (command) {
    case "scan":
      return runScan(rest);

    case "hook": {
      const [target, ...hookRest] = rest;
      if (target === "claude-code") return runClaudeCodeHook(hookRest);
      process.stderr.write(`promptwarden hook: unknown target "${target ?? ""}"\n\n${USAGE}`);
      return 3;
    }

    case "mcp":
      return runMcpGateway(rest);

    case "emit-exclusions":
      return runEmitExclusions(rest);

    case "--version":
    case "-v":
      process.stdout.write(`promptwarden ${VERSION}\n`);
      return 0;

    case "--help":
    case "-h":
      process.stdout.write(USAGE);
      return 0;

    case undefined:
      process.stderr.write(USAGE);
      return 3;

    default:
      process.stderr.write(`promptwarden: unknown subcommand "${command}"\n\n${USAGE}`);
      return 3;
  }
}

// Only auto-run when this module is the actual process entry point, not when
// a test imports `main` directly from the built module. Comparing resolved
// file:// URLs (rather than string-concatenating "file://" + argv[1])
// matters because argv[1] is a plain filesystem path and can contain
// characters — spaces above all — that a URL must percent-encode.
const isMain = (() => {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
})();

if (isMain) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
