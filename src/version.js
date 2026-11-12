import { createRequire } from "node:module";

/** The package version, read from package.json so there is one source. */
export const VERSION = createRequire(import.meta.url)("../package.json").version;
