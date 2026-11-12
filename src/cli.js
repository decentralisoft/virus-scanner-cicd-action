// `viruspurge` — the command-line interface. Exit codes:
//   0  every file is clean (or skipped)
//   1  malware was found
//   2  something failed: a scan, the API, or the command line itself

import { writeFile } from "node:fs/promises";
import { relative } from "node:path";
import { parseArgs } from "node:util";
import { detectCiContext } from "./ci.js";
import { createClient, DEFAULT_API_URL } from "./client.js";
import { expandPatterns } from "./files.js";
import { scanFiles, summarize, Status } from "./scan.js";
import { VERSION } from "./version.js";

export const EXIT = Object.freeze({ CLEAN: 0, INFECTED: 1, ERROR: 2 });

const HELP = `viruspurge ${VERSION} — scan files for malware with the Virus Purge API

Usage:
  viruspurge scan <path|glob>... [options]   Scan files, directories or globs
  viruspurge status <scanId>                 Show a scan's recorded verdict
  viruspurge webhooks list
  viruspurge webhooks create <url> [--events a,b] [--description text]
  viruspurge webhooks delete <webhookId>
  viruspurge webhooks test <webhookId>

Scan options:
  --json                 Print a JSON report instead of text
  --report <file>        Also write the JSON report to <file>
  --concurrency <n>      Files scanned in parallel (default 4)
  --timeout <seconds>    How long to wait for a verdict after a dropped upload (default 120)
  --no-fail-on-error     Exit 0 when scans fail but nothing is infected

Global options:
  --api-key <key>        API key (default: $VIRUSPURGE_API_KEY — prefer the variable)
  --api-url <url>        API base URL (default: $VIRUSPURGE_API_URL or ${DEFAULT_API_URL})
  -h, --help             Show this help
  -v, --version          Show the version

Globs: *, **, ?, [abc], {a,b}; prefix with ! to exclude, e.g. 'dist/**' '!dist/**/*.map'.
On GitHub Actions and GitLab CI, scans carry the repository, commit and run
(CI/CD integration — requires an Enterprise plan).
Exit codes: 0 clean, 1 malware found, 2 error.`;

const OPTIONS = {
  "api-key": { type: "string" },
  "api-url": { type: "string" },
  json: { type: "boolean", default: false },
  report: { type: "string" },
  concurrency: { type: "string" },
  timeout: { type: "string" },
  "fail-on-error": { type: "boolean", default: true },
  "no-fail-on-error": { type: "boolean", default: false },
  events: { type: "string" },
  description: { type: "string" },
  help: { type: "boolean", short: "h", default: false },
  version: { type: "boolean", short: "v", default: false },
};

class UsageError extends Error {}

function positiveInt(raw, name, fallback) {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new UsageError(`--${name} must be a positive whole number.`);
  return n;
}

/**
 * Run the CLI. Returns the exit code instead of exiting, so it can be tested.
 * @param {string[]} argv arguments after the program name
 * @param {{ env?: object, stdout?: object, stderr?: object, cwd?: string, fetch?: Function }} io
 */
export async function main(argv, io = {}) {
  const env = io.env ?? process.env;
  const out = io.stdout ?? process.stdout;
  const err = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();
  const print = (s = "") => out.write(s + "\n");
  const warn = (s) => err.write(s + "\n");

  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    warn(`viruspurge: ${e.message}\nRun 'viruspurge --help' for usage.`);
    return EXIT.ERROR;
  }
  const { values: opts, positionals } = parsed;
  if (opts.version) {
    print(VERSION);
    return EXIT.CLEAN;
  }
  const [command, ...rest] = positionals;
  if (opts.help || !command) {
    print(HELP);
    return opts.help ? EXIT.CLEAN : EXIT.ERROR;
  }

  try {
    const client = createClient({
      apiKey: opts["api-key"] || env.VIRUSPURGE_API_KEY,
      apiUrl: opts["api-url"] || env.VIRUSPURGE_API_URL || DEFAULT_API_URL,
      fetch: io.fetch,
    });

    switch (command) {
      case "scan":
        return await scanCommand(client, rest, opts, { cwd, print, warn, ci: detectCiContext(env) });
      case "status": {
        if (rest.length !== 1) throw new UsageError("Usage: viruspurge status <scanId>");
        const scan = await client.getScan(rest[0]);
        print(JSON.stringify(scan, null, 2));
        return scan.status === "INFECTED" ? EXIT.INFECTED : scan.status === "ERROR" ? EXIT.ERROR : EXIT.CLEAN;
      }
      case "webhooks":
        return await webhooksCommand(client, rest, opts, { print });
      default:
        throw new UsageError(`Unknown command '${command}'. Run 'viruspurge --help' for usage.`);
    }
  } catch (e) {
    warn(`viruspurge: ${e.message}`);
    return EXIT.ERROR;
  }
}

async function scanCommand(client, patterns, opts, { cwd, print, warn, ci }) {
  if (patterns.length === 0) throw new UsageError("Usage: viruspurge scan <path|glob>...");
  const concurrency = positiveInt(opts.concurrency, "concurrency", 4);
  const timeoutMs = positiveInt(opts.timeout, "timeout", 120) * 1000;
  const failOnError = opts["fail-on-error"] && !opts["no-fail-on-error"];

  const { files, unmatched } = await expandPatterns(patterns, cwd);
  for (const p of unmatched) warn(`viruspurge: nothing matches '${p}'`);
  if (files.length === 0) {
    warn("viruspurge: no files to scan.");
    return EXIT.ERROR;
  }

  const label = (f) => relative(cwd, f) || f;
  const results = await scanFiles(client, files, {
    concurrency,
    timeoutMs,
    ci,
    cwdLabel: label,
    onResult: opts.json ? undefined : (r) => print(formatLine(r)),
  });
  const summary = summarize(results);
  const report = { version: 1, apiUrl: client.apiUrl, ...(ci ? { ci } : {}), summary, results };

  if (opts.report) await writeFile(opts.report, JSON.stringify(report, null, 2) + "\n");
  if (opts.json) {
    print(JSON.stringify(report, null, 2));
  } else {
    print();
    print(
      `${summary.scanned} scanned: ${summary.clean} clean, ${summary.infected} infected` +
        (summary.errors ? `, ${summary.errors} failed` : "") +
        (summary.skipped ? `, ${summary.skipped} skipped` : ""),
    );
  }

  if (summary.infected) return EXIT.INFECTED;
  if (summary.errors && failOnError) return EXIT.ERROR;
  return EXIT.CLEAN;
}

function formatLine(r) {
  switch (r.status) {
    case Status.CLEAN:
      return `  clean     ${r.file}`;
    case Status.INFECTED:
      return `✗ INFECTED  ${r.file}  ${r.threats.join(", ")}`;
    case Status.SKIPPED:
      return `  skipped   ${r.file}  (${r.error})`;
    default:
      return `! error     ${r.file}  ${r.error || ""}`.trimEnd();
  }
}

async function webhooksCommand(client, args, opts, { print }) {
  const [sub, arg] = args;
  switch (sub) {
    case "list": {
      const { webhooks } = await client.listWebhooks();
      if (webhooks.length === 0) print("No webhooks.");
      for (const w of webhooks) {
        const last = w.lastDelivery
          ? `last delivery ${w.lastDelivery.at}: ${w.lastDelivery.status ?? w.lastDelivery.error}`
          : "never delivered";
        print(`${w.id}  ${w.url}\n  events: ${w.events.join(", ")}  (${last})`);
      }
      return EXIT.CLEAN;
    }
    case "create": {
      if (!arg) throw new UsageError("Usage: viruspurge webhooks create <url> [--events a,b]");
      const events = opts.events
        ?.split(",")
        .map((e) => e.trim())
        .filter(Boolean);
      const { webhook } = await client.createWebhook({ url: arg, events, description: opts.description });
      print(`Created ${webhook.id} → ${webhook.url}`);
      print(`Events: ${webhook.events.join(", ")}`);
      print(`Signing secret (shown once — store it now): ${webhook.secret}`);
      return EXIT.CLEAN;
    }
    case "delete": {
      if (!arg) throw new UsageError("Usage: viruspurge webhooks delete <webhookId>");
      await client.deleteWebhook(arg);
      print(`Deleted ${arg}.`);
      return EXIT.CLEAN;
    }
    case "test": {
      if (!arg) throw new UsageError("Usage: viruspurge webhooks test <webhookId>");
      const r = await client.testWebhook(arg);
      print(r.delivered ? `Delivered (HTTP ${r.status}).` : `Not delivered: ${r.error || `HTTP ${r.status}`}`);
      return r.delivered ? EXIT.CLEAN : EXIT.ERROR;
    }
    default:
      throw new UsageError("Usage: viruspurge webhooks <list|create|delete|test>");
  }
}
