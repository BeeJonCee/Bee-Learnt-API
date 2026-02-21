// Patch yaml@2.x for swagger-jsdoc@6 compatibility.
// swagger-jsdoc@6 accesses yaml.defaultOptions.keepCstNodes which doesn't exist in yaml@2.x.
// This module MUST be imported before swagger-jsdoc to patch the require cache.
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const YAML = require("yaml") as Record<string, unknown>;

if (!YAML.defaultOptions) {
  YAML.defaultOptions = {};
}

if (YAML.defaultOptions && typeof YAML.defaultOptions === "object") {
  const opts = YAML.defaultOptions as Record<string, unknown>;
  if (!opts.keepCstNodes) {
    opts.keepCstNodes = false;
  }
}
