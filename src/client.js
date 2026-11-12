// A small client for the Virus Purge REST API (/api/v1). No dependencies:
// Node 20+ ships fetch, FormData and file-backed Blobs.

import { openAsBlob } from "node:fs";
import { basename } from "node:path";
import { VERSION } from "./version.js";

export const DEFAULT_API_URL = "https://viruspurge.com";

/** An answer from the API (or the scanner) that was not a success. */
export class ApiError extends Error {
  constructor(message, { status = null, retryAfter = null, body = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfter = retryAfter;
    this.body = body;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function retryAfterSeconds(res) {
  const raw = res.headers.get("retry-after");
  const n = raw == null ? NaN : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

async function readJson(res) {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * @param {object} options
 * @param {string} options.apiKey   a personal (vp_…) or organization (vpo_…) key
 * @param {string} [options.apiUrl] defaults to https://viruspurge.com
 * @param {typeof fetch} [options.fetch]
 * @param {number} [options.maxRateLimitWaits] how many 429s to wait out per call
 */
export function createClient({
  apiKey,
  apiUrl = DEFAULT_API_URL,
  fetch: fetchImpl = globalThis.fetch,
  maxRateLimitWaits = 5,
} = {}) {
  if (!apiKey) {
    throw new ApiError(
      "No API key. Set VIRUSPURGE_API_KEY (or pass --api-key). Get one at https://viruspurge.com/dashboard/api",
    );
  }
  const base = apiUrl.replace(/\/+$/, "");
  const userAgent = `viruspurge-cli/${VERSION} node/${process.versions.node}`;

  /**
   * One API call. A per-minute rate limit (429 with Retry-After) is waited out;
   * a daily-quota refusal (429 without it) is not, since waiting would not help.
   * Idempotent reads are also retried on network errors and 5xx.
   */
  async function call(method, path, body) {
    const idempotent = method === "GET";
    let rateLimitWaits = 0;
    let failures = 0;
    for (;;) {
      let res;
      try {
        res = await fetchImpl(base + path, {
          method,
          headers: {
            authorization: `Bearer ${apiKey}`,
            "user-agent": userAgent,
            accept: "application/json",
            ...(body === undefined ? {} : { "content-type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      } catch (err) {
        if (idempotent && failures < 3) {
          await sleep(500 * 2 ** failures++);
          continue;
        }
        throw new ApiError(`Could not reach ${base}: ${err.cause?.code || err.message}`);
      }

      const data = await readJson(res);
      if (res.ok) return data;

      const retryAfter = retryAfterSeconds(res);
      if (res.status === 429 && retryAfter != null && retryAfter <= 60 && rateLimitWaits < maxRateLimitWaits) {
        rateLimitWaits++;
        await sleep(Math.max(retryAfter, 1) * 1000);
        continue;
      }
      if (idempotent && res.status >= 500 && failures < 3) {
        await sleep(500 * 2 ** failures++);
        continue;
      }
      throw new ApiError(data?.error || `HTTP ${res.status} from ${method} ${path}`, {
        status: res.status,
        retryAfter,
        body: data,
      });
    }
  }

  return {
    apiUrl: base,

    /** Reserve a scan and get an upload permit. */
    createScan: ({ fileName, fileSize, fileMimeType, ci }) =>
      call("POST", "/api/v1/scan", {
        fileName,
        fileSize,
        ...(fileMimeType ? { fileMimeType } : {}),
        ...(ci ? { ci } : {}),
      }),

    /** The recorded verdict of a scan. */
    getScan: (scanId) => call("GET", `/api/v1/scan/${encodeURIComponent(scanId)}`),

    /**
     * Upload a file to the scanner with its permit. Resolves to the scanner's
     * verdict. Throws ApiError with `status` for a refusal, and without one
     * when the connection failed — the scan may still complete, so callers
     * should then fall back to getScan.
     */
    async upload(permit, filePath, fileName = basename(filePath)) {
      if (!permit.uploadUrl) {
        throw new ApiError("The scanner is not configured on this server (no uploadUrl).", { status: 503 });
      }
      const form = new FormData();
      form.append("file", await openAsBlob(filePath), fileName);
      let res;
      try {
        res = await fetchImpl(permit.uploadUrl, {
          method: "POST",
          headers: { "x-scan-permit": permit.permit, "user-agent": userAgent },
          body: form,
        });
      } catch (err) {
        throw new ApiError(`Upload interrupted: ${err.cause?.code || err.message}`);
      }
      const data = await readJson(res);
      if (!res.ok) {
        throw new ApiError(data?.error || `The scanner answered HTTP ${res.status}`, {
          status: res.status,
          body: data,
        });
      }
      if (!data || typeof data.isInfected !== "boolean") {
        // A proxy page or a truncated body: treat like a dropped connection.
        throw new ApiError("The scanner's answer was unreadable.");
      }
      return data;
    },

    listWebhooks: () => call("GET", "/api/v1/webhooks"),
    createWebhook: ({ url, events, description }) =>
      call("POST", "/api/v1/webhooks", {
        url,
        ...(events?.length ? { events } : {}),
        ...(description ? { description } : {}),
      }),
    deleteWebhook: (id) => call("DELETE", `/api/v1/webhooks/${encodeURIComponent(id)}`),
    testWebhook: (id) => call("POST", `/api/v1/webhooks/${encodeURIComponent(id)}/test`),
  };
}
