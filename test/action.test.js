import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockServer } from "./mock-server.js";

const MAIN = fileURLToPath(new URL("../src/action-main.js", import.meta.url));
let server;
let workspace;

before(async () => {
  server = await startMockServer();
  workspace = await mkdtemp(join(tmpdir(), "vp-action-"));
  await mkdir(join(workspace, "dist"));
  await writeFile(join(workspace, "dist", "app.tar.gz"), "release bytes");
  await writeFile(join(workspace, "dist", "app.tar.gz.sha256"), "abc");
  await writeFile(join(workspace, "dist", "evil.exe"), "EICAR");
});
after(() => server.close());

/** Run the action the way the runner does: inputs in env, results in files. */
async function runAction(inputs) {
  const runnerTemp = await mkdtemp(join(tmpdir(), "vp-runner-"));
  const outputFile = join(runnerTemp, "output");
  const summaryFile = join(runnerTemp, "summary");
  await writeFile(outputFile, "");
  await writeFile(summaryFile, "");
  const env = {
    PATH: process.env.PATH,
    GITHUB_ACTIONS: "true",
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    RUNNER_TEMP: runnerTemp,
    "INPUT_API-URL": server.url,
    ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v])),
  };
  const { code, stdout } = await new Promise((resolve) => {
    execFile(process.execPath, [MAIN], { env }, (err, stdout) => resolve({ code: err ? err.code : 0, stdout }));
  });
  const outputs = {};
  const raw = await readFile(outputFile, "utf8");
  for (const m of raw.matchAll(/^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2$/gm)) outputs[m[1]] = m[3];
  return { code, stdout, outputs, summary: await readFile(summaryFile, "utf8") };
}

test("infected artifacts fail the step, annotate the file and fill the summary", async () => {
  const r = await runAction({ "api-key": "good-key", files: "dist/**\n!dist/*.sha256" });
  assert.equal(r.code, 1, r.stdout);
  assert.equal(r.outputs.result, "infected");
  assert.equal(r.outputs.scanned, "2");
  assert.equal(r.outputs.infected, "1");
  assert.match(r.stdout, /::add-mask::good-key/);
  assert.match(r.stdout, /::error file=dist\/evil\.exe,title=Malware detected::/);
  assert.match(r.summary, /Malware found in 1 file/);
  assert.match(r.summary, /\| 🛑 INFECTED \| `dist\/evil\.exe` \| Eicar-Test-Signature \|/);
  const report = JSON.parse(await readFile(r.outputs.report, "utf8"));
  assert.equal(report.results.length, 2, "the .sha256 file was excluded");
});

test("clean artifacts pass", async () => {
  const r = await runAction({ "api-key": "good-key", files: "dist/app.tar.gz" });
  assert.equal(r.code, 0, r.stdout);
  assert.equal(r.outputs.result, "clean");
  assert.match(r.summary, /All 1 file clean/);
});

test("fail-on-infected: false reports without failing", async () => {
  const r = await runAction({ "api-key": "good-key", files: "dist/evil.exe", "fail-on-infected": "false" });
  assert.equal(r.code, 0);
  assert.equal(r.outputs.result, "infected");
});

test("no matching files is an error unless told otherwise", async () => {
  assert.equal((await runAction({ "api-key": "good-key", files: "out/**" })).code, 1);
  const ignored = await runAction({ "api-key": "good-key", files: "out/**", "if-no-files-found": "ignore" });
  assert.equal(ignored.code, 0);
  assert.equal(ignored.outputs.result, "none");
});

test("a missing key fails with a clear message", async () => {
  const r = await runAction({ files: "dist/**" });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /::error::No API key/);
});
