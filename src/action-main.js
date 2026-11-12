// The runner executes this file (action.yml → runs.main).
import { command, run } from "./action.js";

try {
  process.exitCode = await run();
} catch (err) {
  command("error", {}, err.message);
  process.exitCode = 1;
}
