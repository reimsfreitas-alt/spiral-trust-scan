// Single source of truth for the scanner version: package.json.
import { readFileSync } from "node:fs";

export const PACKAGE_JSON = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
export const VERSION = PACKAGE_JSON.version;
