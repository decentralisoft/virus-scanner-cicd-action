// Scan files end to end: permit → direct upload to the scanner → verdict.
// If the upload connection drops after the file was sent, the verdict is
// still recorded server-side, so it is fetched by scanId instead of lost.

import { stat } from "node:fs/promises";
import { basename } from "node:path";
import { ApiError } from "./client.js";

export const Status = Object.freeze({
  CLEAN: "CLEAN",
  INFECTED: "INFECTED",
  ERROR: "ERROR",
  /** Not scanned, and not a failure: an empty file has nothing to scan. */
  SKIPPED: "SKIPPED",
});

const FINAL = new Set(["CLEAN", "INFECTED", "ERROR"]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function threatsOf(v) {
  return [...(v.viruses || []), ...(v.yaraMatches || []), ...(v.imageFindings || [])];
}

/**
 * Wait for a scan's recorded verdict.
 * @returns {Promise<object|null>} the scan, or null if still running at the deadline
 */
export async function waitForVerdict(client, scanId, { timeoutMs = 120_000, pollMs = 2_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let scan = null;
    try {
      scan = await client.getScan(scanId);
    } catch (err) {
      // A transient failure while polling is retried until the deadline; an
      // authoritative refusal (401/403/404) is not.
      if (err instanceof ApiError && err.status && err.status < 500 && err.status !== 429) throw err;
    }
    if (scan && FINAL.has(scan.status)) return scan;
    if (Date.now() + pollMs > deadline) return null;
    await sleep(pollMs);
  }
}

/**
 * Scan one file. Never throws: every outcome is a result object.
 *
 * @returns {Promise<{file: string, status: string, scanId?: string, threats: string[],
 *   sha256?: string|null, error?: string, recoveredByPolling?: boolean}>}
 */
export async function scanFile(client, filePath, { displayName = filePath, timeoutMs, pollMs, ci } = {}) {
  const result = { file: displayName, status: Status.ERROR, threats: [] };
  let info;
  try {
    info = await stat(filePath);
  } catch (err) {
    return { ...result, error: `Cannot read file: ${err.code || err.message}` };
  }
  if (!info.isFile()) return { ...result, error: "Not a regular file." };
  if (info.size === 0) return { ...result, status: Status.SKIPPED, error: "Empty file — nothing to scan." };

  let permit;
  try {
    permit = await client.createScan({ fileName: basename(filePath), fileSize: info.size, ci });
  } catch (err) {
    return { ...result, error: err.message, fatal: isFatal(err) };
  }
  result.scanId = permit.scanId;

  let verdict;
  try {
    verdict = await client.upload(permit, filePath);
  } catch (err) {
    if (err instanceof ApiError && err.status) {
      // The scanner refused the upload (expired permit, too large, …): the
      // scan will never complete, so there is nothing to wait for.
      return { ...result, error: err.message };
    }
    // The connection broke. The file may well have arrived and been scanned:
    // the recorded verdict tells.
    const recorded = await waitForVerdict(client, permit.scanId, { timeoutMs, pollMs }).catch((e) => {
      result.error = e.message;
      return null;
    });
    if (!recorded) {
      return {
        ...result,
        error: result.error || `${err.message}; no verdict was recorded in time (check later: viruspurge status ${permit.scanId}).`,
      };
    }
    return fromScan(result, recorded, true);
  }

  return {
    ...result,
    status: verdict.isInfected ? Status.INFECTED : Status.CLEAN,
    threats: threatsOf(verdict),
    sha256: verdict.sha256 || null,
  };
}

function fromScan(result, scan, recoveredByPolling = false) {
  return {
    ...result,
    status: scan.status,
    threats: threatsOf(scan),
    sha256: scan.sha256 || null,
    ...(scan.status === "ERROR" ? { error: "The scan could not be completed." } : {}),
    ...(recoveredByPolling ? { recoveredByPolling: true } : {}),
  };
}

/** Errors that will fail every other file the same way: stop early. */
function isFatal(err) {
  return (
    err instanceof ApiError && (err.status === 401 || err.status === 403 || (err.status === 429 && err.retryAfter == null))
  );
}

/**
 * Scan many files with bounded concurrency. Stops starting new scans after an
 * error that would repeat for every file (bad key, no plan, quota spent).
 */
export async function scanFiles(client, files, { concurrency = 4, onResult, cwdLabel = (f) => f, ...opts } = {}) {
  const results = new Array(files.length);
  let next = 0;
  let stopped = null;

  async function worker() {
    while (next < files.length) {
      const i = next++;
      if (stopped) {
        results[i] = { file: cwdLabel(files[i]), status: Status.ERROR, threats: [], error: `Not scanned: ${stopped}` };
      } else {
        const r = await scanFile(client, files[i], { ...opts, displayName: cwdLabel(files[i]) });
        if (r.fatal) stopped = r.error;
        delete r.fatal;
        results[i] = r;
      }
      onResult?.(results[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, files.length)) }, worker));
  return results;
}

export function summarize(results) {
  const count = (s) => results.filter((r) => r.status === s).length;
  const summary = {
    scanned: results.filter((r) => r.status === Status.CLEAN || r.status === Status.INFECTED).length,
    clean: count(Status.CLEAN),
    infected: count(Status.INFECTED),
    errors: count(Status.ERROR),
    skipped: count(Status.SKIPPED),
  };
  summary.result = summary.infected ? "infected" : summary.errors ? "error" : "clean";
  return summary;
}
