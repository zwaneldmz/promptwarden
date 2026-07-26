/**
 * PromptWarden for VS Code — editor-side detection only.
 *
 * WHAT THIS DOES: runs the same pure, local policy engine
 * (`@promptwarden/policy-engine`) used by the CLI and the browser extension
 * over the text of files you open or save, and publishes the findings as
 * `vscode.Diagnostic`s in the Problems panel. Plus a status-bar count and two
 * commands for scanning the active file or a set of files/folders on demand.
 *
 * WHAT THIS DOES NOT DO, stated plainly because it is the boundary most
 * likely to be misread: per docs/ROADMAP.md §3, IDE inline completions
 * (GitHub Copilot, Cursor Tab, JetBrains AI) and any AI chat/agent panel are
 * ARCHITECTURALLY OUT OF REACH for a local OSS extension — the completion or
 * chat payload is assembled inside a closed process (the vendor's own
 * extension/service) and sent over its own connection this extension never
 * sees. This extension does not intercept, read, or gate the Copilot/Cursor
 * chat panel, inline suggestions, or any agent-mode tool call, and does not
 * attempt to. See docs/IDE.md for the full surface-by-surface breakdown and
 * `promptwarden emit-exclusions` (apps/cli/src/exclusions.ts) for the only
 * lever that reaches those surfaces at all: vendor-side, best-effort path
 * exclusions.
 *
 * Privacy: every diagnostic message is built from `finding.detector` and
 * `finding.action` only — never `finding.match`. A diagnostic is visible in
 * screenshots, Live Share sessions, and anything pasted into a chat, so the
 * same rule `toLogRecord`/`toUserMessage` enforce elsewhere in this project
 * (never put a matched value somewhere it can be re-exposed) applies here
 * too, even though diagnostics do not go through either of those functions
 * directly.
 */
import { isAbsolute, join } from "node:path";
import * as vscode from "vscode";
import { Action, EvaluationResult, Finding, Policy, evaluate, parsePolicy, toUserMessage } from "@promptwarden/policy-engine";
import { BUILTIN_DEFAULT_POLICY } from "./default-policy.js";

const CONFIG_SECTION = "promptwarden";
const POLICY_PATH_SETTING = "policyPath";
const DIAGNOSTIC_SOURCE = "PromptWarden";
const SKIP_DIRS_GLOB = "**/{node_modules,.git,dist,out,build}/**";

/** Only file-backed or unsaved-buffer documents are scanned — not output channels, diffs, settings JSON views, etc. */
function isScannable(document: vscode.TextDocument): boolean {
  return document.uri.scheme === "file" || document.uri.scheme === "untitled";
}

function severityFor(action: Action): vscode.DiagnosticSeverity {
  switch (action) {
    case "block":
      return vscode.DiagnosticSeverity.Error;
    case "redact":
    case "warn":
      return vscode.DiagnosticSeverity.Warning;
    case "observe":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Category/action only — see this module's doc comment. `document.positionAt`
 * converts the engine's string offsets (UTF-16 code units, matching
 * `document.getText()`) into the line/character `Position`s VS Code needs.
 */
function findingToDiagnostic(document: vscode.TextDocument, finding: Finding): vscode.Diagnostic {
  const range = new vscode.Range(document.positionAt(finding.start), document.positionAt(finding.end));
  const message = `PromptWarden: ${finding.detector} (${finding.action})`;
  const diagnostic = new vscode.Diagnostic(range, message, severityFor(finding.action));
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.detector;
  return diagnostic;
}

/** Merge several per-file results into one, for a single toUserMessage summary. Offsets are not reused across files. */
function mergeResults(results: EvaluationResult[]): EvaluationResult {
  return {
    findings: results.flatMap((r) => r.findings),
    redactedText: "",
    blocked: results.some((r) => r.blocked),
    needsWarning: results.some((r) => r.needsWarning),
  };
}

function resolvePolicyUri(raw: string, workspaceFolder: vscode.WorkspaceFolder | undefined): vscode.Uri | undefined {
  const trimmed = raw.trim();
  if (trimmed === "") return undefined;
  if (isAbsolute(trimmed)) return vscode.Uri.file(trimmed);
  if (!workspaceFolder) return vscode.Uri.file(trimmed);
  return vscode.Uri.file(join(workspaceFolder.uri.fsPath, trimmed));
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection(CONFIG_SECTION);
  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.name = "PromptWarden";
  statusBarItem.command = "promptwarden.scanActiveFile";
  context.subscriptions.push(diagnostics, statusBarItem);

  // Cached per-window; a config change to promptwarden.policyPath (or the
  // policy file itself being saved) invalidates it. Loading is async
  // (vscode.workspace.fs.readFile), so callers always go through getPolicy().
  let cachedPolicy: Policy | undefined;

  async function loadPolicy(): Promise<Policy> {
    const raw = vscode.workspace.getConfiguration(CONFIG_SECTION).get<string>(POLICY_PATH_SETTING, "");
    const uri = resolvePolicyUri(raw, vscode.workspace.workspaceFolders?.[0]);
    if (!uri) return BUILTIN_DEFAULT_POLICY;
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      return parsePolicy(JSON.parse(new TextDecoder("utf-8").decode(bytes)));
    } catch (err) {
      // Never let a bad policy file take the extension down — fall back and
      // say so once. The message names the configured path and the parse
      // error, never anything from a scanned document.
      void vscode.window.showWarningMessage(
        `PromptWarden: could not load policy from "${uri.fsPath}" (${(err as Error).message}). ` +
          `Using the built-in default policy instead.`,
      );
      return BUILTIN_DEFAULT_POLICY;
    }
  }

  async function getPolicy(): Promise<Policy> {
    if (!cachedPolicy) cachedPolicy = await loadPolicy();
    return cachedPolicy;
  }

  function updateStatusBar(): void {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !isScannable(editor.document)) {
      statusBarItem.text = "$(shield) PromptWarden";
      statusBarItem.tooltip = "PromptWarden: no scannable document active";
      statusBarItem.show();
      return;
    }
    const count = diagnostics.get(editor.document.uri)?.length ?? 0;
    statusBarItem.text = count === 0 ? "$(shield) PromptWarden: clean" : `$(shield) PromptWarden: ${count}`;
    statusBarItem.tooltip =
      count === 0
        ? "PromptWarden: no findings in the active file"
        : `PromptWarden: ${count} finding(s) in the active file — see the Problems panel`;
    statusBarItem.show();
  }

  async function scanDocument(document: vscode.TextDocument): Promise<EvaluationResult | undefined> {
    if (!isScannable(document)) return undefined;
    const policy = await getPolicy();
    const result = evaluate(document.getText(), policy);
    diagnostics.set(document.uri, result.findings.map((f) => findingToDiagnostic(document, f)));
    updateStatusBar();
    return result;
  }

  async function resolveSelectionTargets(clickedUri?: vscode.Uri, selectedUris?: vscode.Uri[]): Promise<vscode.Uri[]> {
    if (selectedUris && selectedUris.length > 0) return selectedUris;
    if (clickedUri) return [clickedUri];
    // Invoked from the Command Palette with no Explorer selection to draw
    // "the workspace selection" from — ask instead of guessing scope.
    const picked = await vscode.window.showOpenDialog({
      canSelectMany: true,
      canSelectFiles: true,
      canSelectFolders: true,
      openLabel: "Scan with PromptWarden",
    });
    return picked ?? [];
  }

  /** Expand files/folders into a flat file list, skipping common noise directories. */
  async function expandToFiles(targets: vscode.Uri[]): Promise<vscode.Uri[]> {
    const files: vscode.Uri[] = [];
    for (const target of targets) {
      const stat = await vscode.workspace.fs.stat(target);
      if (stat.type === vscode.FileType.Directory) {
        files.push(...(await vscode.workspace.findFiles(new vscode.RelativePattern(target, "**/*"), SKIP_DIRS_GLOB)));
      } else {
        files.push(target);
      }
    }
    return files;
  }

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => void scanDocument(doc)),
    vscode.workspace.onDidSaveTextDocument((doc) => void scanDocument(doc)),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri)),
    vscode.window.onDidChangeActiveTextEditor(() => updateStatusBar()),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration(`${CONFIG_SECTION}.${POLICY_PATH_SETTING}`)) {
        cachedPolicy = undefined;
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("promptwarden.scanActiveFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showInformationMessage("PromptWarden: no active file to scan.");
        return;
      }
      const result = await scanDocument(editor.document);
      if (result) void vscode.window.showInformationMessage(`PromptWarden: ${toUserMessage(result)}`);
    }),

    vscode.commands.registerCommand(
      "promptwarden.scanWorkspaceSelection",
      async (clickedUri?: vscode.Uri, selectedUris?: vscode.Uri[]) => {
        const targets = await resolveSelectionTargets(clickedUri, selectedUris);
        if (targets.length === 0) return;

        const fileUris = await expandToFiles(targets);
        const results: EvaluationResult[] = [];
        for (const uri of fileUris) {
          try {
            const document = await vscode.workspace.openTextDocument(uri);
            const result = await scanDocument(document);
            if (result) results.push(result);
          } catch {
            // Binary or otherwise unreadable-as-text file — skip it. This
            // command is a convenience scan, not a completeness guarantee;
            // apps/cli's `promptwarden scan --file` is the strict adapter.
          }
        }

        void vscode.window.showInformationMessage(
          `PromptWarden: scanned ${fileUris.length} file(s) — ${toUserMessage(mergeResults(results))}`,
        );
      },
    ),
  );

  // Scan whatever is already open when the extension activates, then set
  // the initial status-bar state.
  for (const document of vscode.workspace.textDocuments) {
    void scanDocument(document);
  }
  updateStatusBar();
}

export function deactivate(): void {
  // Diagnostics and the status-bar item are disposed via
  // context.subscriptions; nothing else holds a handle worth releasing.
}
