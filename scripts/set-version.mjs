#!/usr/bin/env node
// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Bump a package's version in EVERY file that carries it, atomically.
 * The antidote to editing four files by hand and missing one.
 *
 * Usage: node scripts/set-version.mjs <server|sdk|python|sdks|langchain|...> <version>
 *   server    -> package.json + server.json (x2); runtime code reads the
 *                version from package.json via src/version.ts, nothing to edit
 *   sdk       -> sdk/package.json
 *   python    -> sdk-python __init__.py only (pyproject uses hatchling
 *                dynamic versioning)
 *   sdks      -> sdk + python together: the two client SDKs ship at ONE
 *                version (publish-sdks.yml), so stage them with this key
 *   langchain -> langchain-tollwarden pyproject.toml + __init__.py
 *
 * Verifies the result with scripts/check-versions.mjs semantics: after
 * writing, re-reads every spot and fails loudly if anything still disagrees.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const [, , pkg, version] = process.argv;

if (!pkg || !version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("Usage: node scripts/set-version.mjs <server|sdk|python|sdks|langchain|...> <x.y.z>");
  process.exit(2);
}

const sub = (path, pattern, replacement) => {
  const p = join(ROOT, path);
  const before = readFileSync(p, "utf8");
  const after = before.replace(pattern, replacement);
  if (before === after) throw new Error(`no substitution made in ${path} — pattern drift? Fix scripts/set-version.mjs.`);
  writeFileSync(p, after);
  console.log(`  ✓ ${path}`);
};

const EDITS = {
  server: () => {
    sub("package.json", /("version":\s*")[^"]+(")/, `$1${version}$2`);
    sub("server.json", /("version":\s*")[^"]+(")/g, `$1${version}$2`); // both spots
  },
  sdk: () => sub("sdk/package.json", /("version":\s*")[^"]+(")/, `$1${version}$2`),
  "ai-sdk": () => sub("integrations/ai-sdk/package.json", /("version":\s*")[^"]+(")/, `$1${version}$2`),
  python: () => sub("sdk-python/src/tollwarden/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`),
  /** Lockstep group (publish-sdks.yml): both client SDKs at one version. */
  sdks: () => {
    EDITS.sdk();
    EDITS.python();
  },
  langchain: () => {
    sub("integrations/langchain-tollwarden/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/langchain-tollwarden/src/langchain_tollwarden/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
  crewai: () => {
    sub("integrations/crewai-tollwarden/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/crewai-tollwarden/src/crewai_tollwarden/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
  nemo: () => {
    sub("integrations/nemo-tollwarden/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/nemo-tollwarden/src/nemo_tollwarden/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
  agentkit: () => {
    sub("integrations/agentkit-tollwarden/pyproject.toml", /^(version = ")[^"]+(")/m, `$1${version}$2`);
    sub("integrations/agentkit-tollwarden/src/agentkit_tollwarden/__init__.py", /(__version__ = ")[^"]+(")/, `$1${version}$2`);
  },
};

if (!EDITS[pkg]) {
  console.error(`Unknown package "${pkg}". Valid: ${Object.keys(EDITS).join(", ")}`);
  process.exit(2);
}

console.log(`Setting ${pkg} -> ${version}`);
EDITS[pkg]();
console.log(`Done. Verify + registry-check with: node scripts/check-versions.mjs ${pkg} --registry`);
