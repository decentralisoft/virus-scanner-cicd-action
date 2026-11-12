import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { expandPatterns, globToRegExp } from "../src/files.js";

test("globs match the way shells and GitHub workflows do", () => {
  const cases = [
    ["*.zip", "a.zip", true],
    ["*.zip", "dir/a.zip", false],
    ["**/*.zip", "a.zip", true],
    ["**/*.zip", "x/y/a.zip", true],
    ["dist/**", "dist/a/b.bin", true],
    ["dist/*.{zip,tar.gz}", "dist/app.tar.gz", true],
    ["dist/*.{zip,tar.gz}", "dist/app.tgz", false],
    ["file?.txt", "file1.txt", true],
    ["file[0-9].txt", "fileA.txt", false],
    ["file[!0-9].txt", "fileA.txt", true],
    ["a+b(1).txt", "a+b(1).txt", true],
  ];
  for (const [glob, path, expected] of cases) {
    assert.equal(globToRegExp(glob).test(path), expected, `${glob} vs ${path}`);
  }
});

test("paths, directories, globs and exclusions expand to a sorted file list", async () => {
  const root = await mkdtemp(join(tmpdir(), "vp-files-"));
  for (const f of ["dist/app.zip", "dist/app.zip.map", "dist/sub/lib.so", "README.md", ".git/config"]) {
    await mkdir(join(root, f, ".."), { recursive: true });
    await writeFile(join(root, f), "x");
  }
  const rel = (files) => files.map((f) => relative(root, f));

  let r = await expandPatterns(["dist", "!**/*.map"], root);
  assert.deepEqual(rel(r.files), ["dist/app.zip", "dist/sub/lib.so"]);

  r = await expandPatterns(["**/*.md", "dist/*.zip", "nope/*.exe", "missing.txt"], root);
  assert.deepEqual(rel(r.files), ["README.md", "dist/app.zip"]);
  assert.deepEqual(r.unmatched, ["nope/*.exe", "missing.txt"]);

  // .git is never walked into.
  r = await expandPatterns(["."], root);
  assert.ok(!rel(r.files).some((f) => f.startsWith(".git")));
});
