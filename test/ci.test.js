import { test } from "node:test";
import assert from "node:assert/strict";
import { detectCiContext } from "../src/ci.js";

test("GitHub Actions runs are described by repository, commit and run", () => {
  const ci = detectCiContext({
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "acme/app",
    GITHUB_REF: "refs/tags/v2.0.0",
    GITHUB_SHA: "67207a30c316e85bb2331b4dbd1acda9729a4e5a",
    GITHUB_WORKFLOW: "Release",
    GITHUB_RUN_ID: "42",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_ACTOR: "octocat",
  });
  assert.deepEqual(ci, {
    provider: "github",
    repository: "acme/app",
    ref: "refs/tags/v2.0.0",
    commit: "67207a30c316e85bb2331b4dbd1acda9729a4e5a",
    workflow: "Release",
    runId: "42",
    runAttempt: 2,
    runUrl: "https://github.com/acme/app/actions/runs/42",
    actor: "octocat",
  });
});

test("GitLab pipelines are recognised too", () => {
  const ci = detectCiContext({
    GITLAB_CI: "true",
    CI_PROJECT_PATH: "group/sub/project",
    CI_COMMIT_SHA: "abcdef1",
    CI_PIPELINE_ID: "777",
    CI_PIPELINE_URL: "https://gitlab.com/group/sub/project/-/pipelines/777",
  });
  assert.equal(ci.provider, "gitlab");
  assert.equal(ci.repository, "group/sub/project");
  assert.equal(ci.runId, "777");
});

test("outside CI there is no context, and a non-https run URL is dropped", () => {
  assert.equal(detectCiContext({}), null);
  assert.equal(detectCiContext({ CI: "true" }), null, "a generic CI flag names no repository");
  const ghes = detectCiContext({
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "acme/app",
    GITHUB_RUN_ID: "1",
    GITHUB_SERVER_URL: "http://ghes.internal",
  });
  assert.equal(ghes.runUrl, undefined);
});
