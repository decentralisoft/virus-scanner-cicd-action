# Virus Purge — CLI & GitHub Action

Scan files for malware with the [Virus Purge API](https://viruspurge.com/docs)
(ClamAV, YARA and an image-payload check) from your terminal or your CI.

- **No dependencies.** Node 20+ only.
- **Files never touch our web servers.** Each file is uploaded straight to an
  isolated scanner with a short-lived signed permit.
- **Resilient.** If an upload connection drops, the verdict is fetched by scan
  id instead of being lost.
- **CI-friendly.** Exit code `1` when malware is found, a JSON report, and on
  GitHub: annotations plus a job summary.

**Requires an Enterprise plan** for use in CI/CD. In a pipeline (GitHub
Actions, GitLab CI) every scan carries the repository, commit, branch and
workflow run it came from, and results are organized per repository and run on
your [CI/CD page](https://viruspurge.com/dashboard/ci). On other plans the API
refuses pipeline scans (`403 enterprise_required`); outside CI the CLI works
with any plan that has API access (Premium). Get your key from the
[API dashboard](https://viruspurge.com/dashboard/api).

## CLI

```bash
export VIRUSPURGE_API_KEY=vp_...

npx viruspurge scan dist/                      # a directory, recursively
npx viruspurge scan "build/**/*.{zip,exe}" '!build/**/*.map'
npx viruspurge scan dist/ --json --report scan-report.json
npx viruspurge status <scanId>                 # look a scan up again
```

```
  clean     dist/app-1.4.0.tar.gz
✗ INFECTED  dist/tools/helper.exe  Win.Trojan.Agent-123
  skipped   dist/.keep  (Empty file — nothing to scan.)

2 scanned: 1 clean, 1 infected, 1 skipped
```

| Exit code | Meaning |
|---|---|
| `0` | Every file is clean (empty files are skipped) |
| `1` | Malware was found |
| `2` | A file could not be scanned, the API refused the request, or bad usage |

Options: `--json`, `--report <file>`, `--concurrency <n>` (default 4),
`--timeout <seconds>` (how long to wait for a verdict after a dropped upload,
default 120), `--no-fail-on-error`, `--api-url <url>`. Prefer the
`VIRUSPURGE_API_KEY` variable to `--api-key`, which shows up in process lists.

Globs support `*`, `**`, `?`, `[abc]` and `{a,b}`; prefix a pattern with `!` to
exclude matches. `.git` directories are never scanned.

### Webhooks

Get told about infected files and quota usage instead of polling:

```bash
npx viruspurge webhooks create https://ci.example.com/hooks/vp --events scan.infected,quota.threshold
npx viruspurge webhooks list
npx viruspurge webhooks test wh_...
npx viruspurge webhooks delete wh_...
```

Events: `scan.completed`, `scan.infected`, `quota.threshold`. Deliveries are
signed — see [Verifying signatures](https://viruspurge.com/docs#webhooks).

## GitHub Action

Requires a Virus Purge **Enterprise** plan.

```yaml
- uses: decentralisoft/virus-scanner-cicd-action@v1
  id: scan
  with:
    api-key: ${{ secrets.VIRUSPURGE_API_KEY }}
    files: |
      dist/**
      !dist/**/*.map
```

| Input | Default | |
|---|---|---|
| `api-key` | — | **Required.** Store it as a secret. |
| `files` | — | **Required.** One path, directory or glob per line; `!` excludes. |
| `fail-on-infected` | `true` | Fail the step when malware is found. |
| `fail-on-error` | `true` | Fail the step when a file could not be scanned. |
| `if-no-files-found` | `error` | `error`, `warn` or `ignore`. |
| `concurrency` | `4` | Files scanned in parallel. |
| `timeout` | `120` | Seconds to wait for a verdict after a dropped upload. |
| `api-url` | `https://viruspurge.com` | |

| Output | |
|---|---|
| `result` | `clean`, `infected`, `error`, or `none` when nothing matched |
| `scanned`, `infected`, `errors` | Counts |
| `report` | Path to the JSON report: every file's verdict, threats, SHA-256 and scan id |

A complete workflow that scans every published release and attaches the
report to it is in [`examples/scan-release.yml`](examples/scan-release.yml).

## Library

```js
import { createClient, scanFile } from "viruspurge";

const client = createClient({ apiKey: process.env.VIRUSPURGE_API_KEY });
const result = await scanFile(client, "upload.zip");
// { file, status: "CLEAN" | "INFECTED" | "ERROR" | "SKIPPED", threats, sha256, scanId }
```

## Development

```bash
npm test     # node --test, against a local mock of the API and the scanner
```

The machine-readable API contract is at
<https://viruspurge.com/api/v1/openapi.json>.
