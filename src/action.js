// GitHub Action entry point (see action.yml). Reads the `with:` inputs from
// INPUT_* variables, scans, and reports through the runner's files: step
// outputs, a job summary table, and an error annotation per infected file.
// No @actions/* dependency — the protocol is a handful of env files.

import { appendFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { randomUUID } from "node:crypto";
import { detectCiContext } from "./ci.js";
import { createClient, DEFAULT_API_URL } from "./client.js";
import { expandPatterns } from "./files.js";
import { scanFiles, summarize, Status } from "./scan.js";

const input = (name, fallback = "") => {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === undefined || v.trim() === "" ? fallback : v.trim();
};
const bool = (name, fallback) => {
  const v = input(name, String(fallback)).toLowerCase();
  if (["true", "yes", "1"].includes(v)) return true;
  if (["false", "no", "0"].includes(v)) return false;
  throw new Error(`Input '${name}' must be true or false, got '${v}'.`);
};
const int = (name, fallback) => {
  const n = Number(input(name, String(fallback)));
  if (!Number.isInteger(n) || n < 1) throw new Error(`Input '${name}' must be a positive whole number.`);
  return n;
};

// Workflow commands: https://docs.github.com/actions/reference/workflow-commands-for-github-actions
const escapeData = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escapeProp = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
export const command = (name, props, message) => {
  const p = Object.entries(props)
    .map(([k, v]) => `${k}=${escapeProp(v)}`)
    .join(",");
  process.stdout.write(`::${name}${p ? " " + p : ""}::${escapeData(message)}\n`);
};

async function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delimiter = `ghadelimiter_${randomUUID()}`;
  await appendFile(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");

function summaryMarkdown(summary, results) {
  const icon = { CLEAN: "✅", INFECTED: "🛑", ERROR: "⚠️", SKIPPED: "➖" };
  const headline =
    summary.result === "infected"
      ? `🛑 **Malware found in ${summary.infected} file${summary.infected === 1 ? "" : "s"}.**`
      : summary.result === "error"
        ? `⚠️ **${summary.errors} file${summary.errors === 1 ? "" : "s"} could not be scanned.**`
        : `✅ **All ${summary.scanned} file${summary.scanned === 1 ? "" : "s"} clean.**`;
  // Infected and failed files first: they are what the reader is looking for.
  const order = { INFECTED: 0, ERROR: 1, CLEAN: 2, SKIPPED: 3 };
  const rows = [...results]
    .sort((a, b) => order[a.status] - order[b.status] || a.file.localeCompare(b.file))
    .map(
      (r) =>
        `| ${icon[r.status] || ""} ${r.status} | \`${cell(r.file)}\` | ${cell(r.threats.join(", ") || r.error || "")} | ${r.scanId ? `\`${r.scanId}\`` : ""} |`,
    );
  return [
    "### Virus Purge scan",
    "",
    headline,
    "",
    `${summary.scanned} scanned · ${summary.clean} clean · ${summary.infected} infected · ${summary.errors} failed · ${summary.skipped} skipped`,
    "",
    "| Result | File | Detail | Scan ID |",
    "|---|---|---|---|",
    ...rows,
    "",
  ].join("\n");
}

export async function run() {
  const apiKey = input("api-key");
  if (apiKey) process.stdout.write(`::add-mask::${apiKey}\n`);
  const patterns = input("files")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (patterns.length === 0) throw new Error("Input 'files' is required: one path or glob per line.");
  const ifNoFiles = input("if-no-files-found", "error");
  if (!["error", "warn", "ignore"].includes(ifNoFiles)) {
    throw new Error("Input 'if-no-files-found' must be error, warn or ignore.");
  }
  const failOnInfected = bool("fail-on-infected", true);
  const failOnError = bool("fail-on-error", true);
  const concurrency = int("concurrency", 4);
  const timeoutMs = int("timeout", 120) * 1000;
  const cwd = process.env.GITHUB_WORKSPACE || process.cwd();

  const client = createClient({ apiKey, apiUrl: input("api-url", DEFAULT_API_URL) });
  const { files, unmatched } = await expandPatterns(patterns, cwd);
  for (const p of unmatched) {
    if (ifNoFiles !== "ignore") command("warning", {}, `No files match '${p}'.`);
  }

  if (files.length === 0) {
    const message = "No files to scan.";
    await setOutput("result", "none");
    for (const name of ["scanned", "infected", "errors"]) await setOutput(name, "0");
    if (ifNoFiles === "error") throw new Error(message);
    if (ifNoFiles === "warn") command("warning", {}, message);
    return 0;
  }

  const label = (f) => relative(cwd, f) || f;
  const ci = detectCiContext(process.env);
  console.log(`Scanning ${files.length} file${files.length === 1 ? "" : "s"} with Virus Purge…`);
  const results = await scanFiles(client, files, {
    concurrency,
    timeoutMs,
    ci,
    cwdLabel: label,
    onResult: (r) => {
      if (r.status === Status.INFECTED) {
        command("error", { file: r.file, title: "Malware detected" }, `${r.file}: ${r.threats.join(", ")}`);
      } else if (r.status === Status.ERROR) {
        command(failOnError ? "error" : "warning", { file: r.file, title: "Scan failed" }, `${r.file}: ${r.error}`);
      } else {
        console.log(`  ${r.status.toLowerCase().padEnd(8)} ${r.file}`);
      }
    },
  });
  const summary = summarize(results);

  const reportPath = join(process.env.RUNNER_TEMP || cwd, `viruspurge-report-${Date.now()}.json`);
  await writeFile(reportPath, JSON.stringify({ version: 1, ...(ci ? { ci } : {}), summary, results }, null, 2) + "\n");
  await setOutput("result", summary.result);
  await setOutput("scanned", String(summary.scanned));
  await setOutput("infected", String(summary.infected));
  await setOutput("errors", String(summary.errors));
  await setOutput("report", reportPath);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(summary, results));
  }

  console.log(
    `\n${summary.scanned} scanned: ${summary.clean} clean, ${summary.infected} infected, ${summary.errors} failed, ${summary.skipped} skipped.`,
  );
  if (summary.infected && failOnInfected) {
    command("error", {}, `Malware found in ${summary.infected} file(s).`);
    return 1;
  }
  if (summary.errors && failOnError) {
    command("error", {}, `${summary.errors} file(s) could not be scanned.`);
    return 1;
  }
  return 0;
}
