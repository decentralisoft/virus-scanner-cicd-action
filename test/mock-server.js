// A stand-in for the Virus Purge API and the scanner, enough to drive the CLI
// and the Action through every path: clean, infected, a dropped upload
// connection, rate limiting, and refused keys.

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

export async function startMockServer({ rateLimitFirstScan = false } = {}) {
  const scans = new Map();
  const permits = new Map();
  const calls = [];
  const received = []; // every `ci` context a scan was started with
  let rateLimited = !rateLimitFirstScan;

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };
  const readBody = (req) =>
    new Promise((resolve) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => resolve(Buffer.concat(chunks)));
    });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    calls.push(`${req.method} ${url.pathname}`);
    const body = await readBody(req);
    const auth = req.headers.authorization;

    if (url.pathname === "/upload" && req.method === "POST") {
      const scanId = permits.get(req.headers["x-scan-permit"]);
      if (!scanId) return send(res, 403, { error: "Invalid or expired permit." });
      permits.delete(req.headers["x-scan-permit"]);
      const scan = scans.get(scanId);
      const infected = body.includes("EICAR");
      Object.assign(scan, {
        status: infected ? "INFECTED" : "CLEAN",
        isInfected: infected,
        viruses: infected ? ["Eicar-Test-Signature"] : [],
        sha256: "ab".repeat(32),
        completedAt: new Date().toISOString(),
      });
      // The scan finishes server-side, but the client never hears back.
      if (scan.fileName.includes("drop")) return req.socket.destroy();
      return send(res, 200, {
        scanId,
        sha256: scan.sha256,
        isInfected: infected,
        viruses: scan.viruses,
        yaraMatches: [],
        imageFindings: [],
        scannedAt: Math.floor(Date.now() / 1000),
      });
    }

    if (!url.pathname.startsWith("/api/v1/")) return send(res, 404, { error: "Not found" });
    if (auth === "Bearer free-key") return send(res, 403, { error: "API access requires a Premium subscription." });
    // good-key is on Enterprise; premium-key has the API but not CI/CD.
    if (auth !== "Bearer good-key" && auth !== "Bearer premium-key") return send(res, 401, { error: "Invalid API key." });

    if (url.pathname === "/api/v1/scan" && req.method === "POST") {
      if (!rateLimited) {
        rateLimited = true;
        return send(res, 429, { error: "Rate limit exceeded" }, { "retry-after": "1" });
      }
      const { fileName, fileSize, ci } = JSON.parse(body);
      if (ci && auth !== "Bearer good-key") {
        return send(res, 403, {
          error: "CI/CD integration (the GitHub Action, and the CLI in a CI pipeline) requires an Enterprise plan.",
          code: "enterprise_required",
        });
      }
      if (ci) received.push(ci);
      const scanId = randomUUID();
      const permit = `permit-${scanId}`;
      scans.set(scanId, {
        scanId, status: "SCANNING", isInfected: null, fileName, fileSize,
        viruses: [], yaraMatches: [], imageFindings: [], sha256: null,
      });
      permits.set(permit, scanId);
      return send(res, 200, {
        scanId, permit, uploadUrl: `${base}/upload`, maxSizeBytes: 268435456, isArchive: false,
        statusUrl: `${base}/api/v1/scan/${scanId}`,
      });
    }
    const m = url.pathname.match(/^\/api\/v1\/scan\/([^/]+)$/);
    if (m && req.method === "GET") {
      const scan = scans.get(m[1]);
      return scan ? send(res, 200, scan) : send(res, 404, { error: "Scan not found." });
    }
    if (url.pathname === "/api/v1/webhooks" && req.method === "GET") {
      return send(res, 200, { webhooks: [] });
    }
    if (url.pathname === "/api/v1/webhooks" && req.method === "POST") {
      const { url: target, events } = JSON.parse(body);
      return send(res, 201, {
        webhook: { id: "wh_1", url: target, events: events ?? ["scan.completed"], secret: "whsec_x" },
      });
    }
    return send(res, 404, { error: "Not found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    url: base,
    scans,
    calls,
    received,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
