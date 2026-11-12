// Where a scan comes from when it runs in a build pipeline. Sent with every
// scan as `ci`, so results can be traced to their repository, commit and run
// and browsed per repository on the Virus Purge CI/CD page.
//
// CI/CD integration is an Enterprise feature: the API refuses a `ci` context
// from any other plan (403, code `enterprise_required`).

const clean = (obj) =>
  Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null && v !== ""));

const https = (url) => (typeof url === "string" && url.startsWith("https://") ? url : undefined);

/**
 * The pipeline context from a CI runner's environment, or null when not on a
 * recognised CI system.
 * @param {Record<string, string | undefined>} env
 */
export function detectCiContext(env = process.env) {
  if (env.GITHUB_ACTIONS === "true" && env.GITHUB_REPOSITORY) {
    const server = (env.GITHUB_SERVER_URL || "https://github.com").replace(/\/+$/, "");
    return clean({
      provider: "github",
      repository: env.GITHUB_REPOSITORY,
      ref: env.GITHUB_REF || env.GITHUB_REF_NAME,
      commit: env.GITHUB_SHA,
      workflow: env.GITHUB_WORKFLOW,
      runId: env.GITHUB_RUN_ID,
      runAttempt: Number(env.GITHUB_RUN_ATTEMPT) || undefined,
      runUrl: env.GITHUB_RUN_ID ? https(`${server}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`) : undefined,
      actor: env.GITHUB_ACTOR,
    });
  }
  if (env.GITLAB_CI === "true" && env.CI_PROJECT_PATH) {
    return clean({
      provider: "gitlab",
      repository: env.CI_PROJECT_PATH,
      ref: env.CI_COMMIT_REF_NAME,
      commit: env.CI_COMMIT_SHA,
      workflow: env.CI_JOB_NAME,
      runId: env.CI_PIPELINE_ID,
      runUrl: https(env.CI_PIPELINE_URL),
      actor: env.GITLAB_USER_LOGIN,
    });
  }
  return null;
}
