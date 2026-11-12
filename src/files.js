// Expand the paths and glob patterns a user (or a workflow's `files:` input)
// names into a sorted list of files. Supports `*`, `**`, `?`, `[abc]`,
// `{a,b}` and `!pattern` exclusions — enough for "dist/**/*.{zip,tar.gz}"
// without a dependency.

import { readdir, stat } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const GLOB_CHARS = /[*?[\]{}]/;
const SKIP_DIRS = new Set([".git"]);

const escapeRe = (s) => s.replace(/[.+^$()|\\/]/g, "\\$&");

/** Regex source for one glob (no anchors). Paths use `/` separators. */
function globSource(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?"; // `**/` — zero or more directories
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (c === "[") {
      const end = glob.indexOf("]", i + 2);
      if (end === -1) {
        re += "\\[";
      } else {
        let cls = glob.slice(i + 1, end).replace(/\\/g, "\\\\");
        if (cls.startsWith("!")) cls = "^" + cls.slice(1);
        re += `[${cls}]`;
        i = end;
      }
    } else if (c === "{") {
      const end = matchingBrace(glob, i);
      if (end === -1) {
        re += "\\{";
      } else {
        const alternatives = splitTopLevel(glob.slice(i + 1, end));
        re += "(?:" + alternatives.map(globSource).join("|") + ")";
        i = end;
      }
    } else {
      re += escapeRe(c);
    }
  }
  return re;
}

function matchingBrace(s, open) {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === "{") depth++;
    else if (s[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function splitTopLevel(s) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "{") depth++;
    else if (s[i] === "}") depth--;
    else if (s[i] === "," && depth === 0) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts;
}

export function globToRegExp(glob) {
  return new RegExp("^" + globSource(glob) + "$");
}

const toPosix = (p) => p.split(sep).join("/");

async function* walk(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/** The directory part of a pattern before its first glob segment. */
function baseOf(pattern) {
  const segments = pattern.split("/");
  const fixed = [];
  for (const seg of segments) {
    if (GLOB_CHARS.test(seg)) break;
    fixed.push(seg);
  }
  // A pattern without any glob segment was handled as a plain path.
  return fixed.join("/") || ".";
}

/**
 * @param {string[]} patterns paths, directories or globs; `!glob` excludes
 * @param {string} [cwd]
 * @returns {Promise<{ files: string[], unmatched: string[] }>} absolute paths
 */
export async function expandPatterns(patterns, cwd = process.cwd()) {
  const include = new Set();
  const excludes = [];
  const unmatched = [];

  for (const raw of patterns) {
    const pattern = toPosix(raw.trim());
    if (!pattern || pattern.startsWith("#")) continue;
    if (pattern.startsWith("!")) {
      const glob = pattern.slice(1);
      excludes.push(globToRegExp(isAbsolute(glob) ? toPosix(relative(cwd, glob)) : glob.replace(/^\.\//, "")));
      continue;
    }

    let found = 0;
    if (!GLOB_CHARS.test(pattern)) {
      const full = resolve(cwd, pattern);
      const info = await stat(full).catch(() => null);
      if (info?.isFile()) {
        include.add(full);
        found++;
      } else if (info?.isDirectory()) {
        for await (const file of walk(full)) {
          include.add(file);
          found++;
        }
      }
    } else {
      const absolute = isAbsolute(pattern);
      const base = baseOf(pattern);
      const root = resolve(cwd, base);
      const re = globToRegExp(absolute ? pattern : pattern.replace(/^\.\//, ""));
      for await (const file of walk(root)) {
        const candidate = absolute ? toPosix(file) : toPosix(relative(cwd, file));
        if (re.test(candidate)) {
          include.add(file);
          found++;
        }
      }
    }
    if (found === 0) unmatched.push(raw.trim());
  }

  const files = [...include]
    .filter((file) => !excludes.some((re) => re.test(toPosix(relative(cwd, file)))))
    .sort();
  return { files, unmatched };
}
