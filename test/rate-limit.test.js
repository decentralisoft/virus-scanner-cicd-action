import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "../src/client.js";
import { scanFile } from "../src/scan.js";
import { startMockServer } from "./mock-server.js";

test("a per-minute rate limit is waited out, not reported as a failure", async () => {
  const server = await startMockServer({ rateLimitFirstScan: true });
  try {
    const dir = await mkdtemp(join(tmpdir(), "vp-rl-"));
    await writeFile(join(dir, "a.bin"), "data");
    const client = createClient({ apiKey: "good-key", apiUrl: server.url });
    const started = Date.now();
    const r = await scanFile(client, join(dir, "a.bin"));
    assert.equal(r.status, "CLEAN", JSON.stringify(r));
    assert.ok(Date.now() - started >= 900, "waited for Retry-After");
    assert.equal(server.calls.filter((c) => c === "POST /api/v1/scan").length, 2);
  } finally {
    await server.close();
  }
});
