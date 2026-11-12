import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, EXIT } from "../src/cli.js";
import { startMockServer } from "./mock-server.js";

let server;
let dir;

before(async () => {
  server = await startMockServer();
  dir = await mkdtemp(join(tmpdir(), "vp-cli-"));
  await writeFile(join(dir, "clean.bin"), "hello world");
  await writeFile(join(dir, "eicar.com"), "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  await writeFile(join(dir, "drop-connection.bin"), "EICAR again, but the reply is lost");
  await writeFile(join(dir, "empty.txt"), "");
});
after(() => server.close());

async function run(args, key = "good-key") {
  let stdout = "";
  let stderr = "";
  const code = await main(args, {
    env: { VIRUSPURGE_API_KEY: key, VIRUSPURGE_API_URL: server.url },
    stdout: { write: (s) => (stdout += s) },
    stderr: { write: (s) => (stderr += s) },
    cwd: dir,
  });
  return { code, stdout, stderr };
}

test("clean files exit 0", async () => {
  const r = await run(["scan", "clean.bin"]);
  assert.equal(r.code, EXIT.CLEAN, r.stderr);
  assert.match(r.stdout, /clean\s+clean\.bin/);
  assert.match(r.stdout, /1 scanned: 1 clean, 0 infected/);
});

test("malware exits 1 and is named in the JSON report", async () => {
  const report = join(dir, "report.json");
  const r = await run(["scan", "clean.bin", "eicar.com", "empty.txt", "--json", "--report", report]);
  assert.equal(r.code, EXIT.INFECTED, r.stderr);
  const printed = JSON.parse(r.stdout);
  assert.deepEqual(printed, JSON.parse(await readFile(report, "utf8")));
  assert.deepEqual(printed.summary, { scanned: 2, clean: 1, infected: 1, errors: 0, skipped: 1, result: "infected" });
  const eicar = printed.results.find((x) => x.file === "eicar.com");
  assert.equal(eicar.status, "INFECTED");
  assert.deepEqual(eicar.threats, ["Eicar-Test-Signature"]);
  assert.ok(eicar.scanId);
  assert.equal(printed.results.find((x) => x.file === "empty.txt").status, "SKIPPED");
});

test("a dropped upload connection recovers the verdict by scan id", async () => {
  const r = await run(["scan", "drop-connection.bin", "--json"]);
  const { results } = JSON.parse(r.stdout);
  assert.equal(results[0].status, "INFECTED", JSON.stringify(results[0]));
  assert.equal(results[0].recoveredByPolling, true);
  assert.equal(r.code, EXIT.INFECTED);
  assert.ok(server.calls.includes(`GET /api/v1/scan/${results[0].scanId}`));
});

test("a refused key stops after the first file and exits 2", async () => {
  const before = server.calls.length;
  const r = await run(["scan", "clean.bin", "eicar.com", "--concurrency", "1", "--json"], "free-key");
  assert.equal(r.code, EXIT.ERROR);
  const { results } = JSON.parse(r.stdout);
  assert.match(results[0].error, /Premium/);
  assert.match(results[1].error, /^Not scanned/);
  assert.equal(server.calls.length - before, 1, "only one API call was made");
});

test("errors can be tolerated with --no-fail-on-error", async () => {
  const r = await run(["scan", "clean.bin", "--no-fail-on-error"], "wrong-key");
  assert.equal(r.code, EXIT.CLEAN);
  assert.match(r.stdout, /Invalid API key/);
});

test("usage problems exit 2 with a hint", async () => {
  assert.equal((await run(["scan"])).code, EXIT.ERROR);
  assert.equal((await run(["scan", "nothing-here/*.zip"])).code, EXIT.ERROR);
  assert.equal((await run(["frobnicate"])).code, EXIT.ERROR);
  assert.equal((await run(["scan", "x", "--concurrency", "0"])).code, EXIT.ERROR);
  const noKey = await main(["scan", "clean.bin"], { env: {}, stdout: { write() {} }, stderr: { write() {} }, cwd: dir });
  assert.equal(noKey, EXIT.ERROR);
  const help = await run(["--help"]);
  assert.equal(help.code, EXIT.CLEAN);
  assert.match(help.stdout, /Exit codes/);
});

test("status prints the recorded verdict", async () => {
  const scanned = JSON.parse((await run(["scan", "eicar.com", "--json"])).stdout);
  const r = await run(["status", scanned.results[0].scanId]);
  assert.equal(r.code, EXIT.INFECTED);
  assert.equal(JSON.parse(r.stdout).status, "INFECTED");
});

test("webhooks can be created from the command line", async () => {
  const r = await run(["webhooks", "create", "https://ci.example.com/hook", "--events", "scan.infected"]);
  assert.equal(r.code, EXIT.CLEAN, r.stderr);
  assert.match(r.stdout, /whsec_x/);
  assert.match(r.stdout, /scan\.infected/);
});
