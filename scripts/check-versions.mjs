#!/usr/bin/env node
// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Version-consistency gate. Zero dependencies.
 *
 * Every package's version lives in more than one file (a lesson learned the
 * hard way on 2026-07-16: a 0.3.1 in package.json nearly downgraded npm's
 * `latest` tag, an unpublished 1.1.2 broke mcp-publisher, and serviceInfo
 * reported 1.1.0 for a day). This script makes those drifts loud and early.
 *
 * Usage:
 *   node scripts/check-versions.mjs <server|sdk|python|sdks|langchain|all>
 *       Check that every file agrees on the version (offline, always safe).
 *       `sdks` is the lockstep group (publish-sdks.yml): the TS and Python
 *       client SDKs must carry ONE version, and the registry check below runs
 *       against npm AND PyPI.
 *   node scripts/check-versions.mjs <package> --registry
 *       Also query npm/PyPI: FAIL if the version is already published, and
 *       (npm only) FAIL if it is lower than the current `latest` — publishing
 *       a lower version would retag `latest` backwards and downgrade users.
 *
 * Run in CI before every publish (the workflows do); run locally any time.
 * To BUMP a version everywhere at once: node scripts/set-version.mjs <pkg> <v>
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const jsonVersion = (p) => JSON.parse(read(p)).version;
const match = (p, re, what) => {
  const m = read(p).match(re);
  if (!m) throw new Error(`could not find ${what} in ${p}`);
  return m[1];
};

/** Every file that carries each package's version. Add new spots HERE. */
const PACKAGES = {
  server: {
    registry: { type: "npm", name: "tollwarden" },
    // Runtime code (serviceInfo, OpenAPI, agent card, McpServer) reads the
    // version from package.json via src/version.ts — only the static files
    // carry copies, and `npm run build` syncs server.json automatically.
    spots: () => ({
      "package.json": jsonVersion("package.json"),
      "server.json (top-level)": JSON.parse(read("server.json")).version,
      "server.json (packages[0])": JSON.parse(read("server.json")).packages?.[0]?.version,
    }),
  },
  sdk: {
    registry: { type: "npm", name: "@tollwarden/client" },
    spots: () => ({ "sdk/package.json": jsonVersion("sdk/package.json") }),
  },
  "ai-sdk": {
    registry: { type: "npm", name: "@tollwarden/ai-sdk" },
    spots: () => ({ "integrations/ai-sdk/package.json": jsonVersion("integrations/ai-sdk/package.json") }),
  },
  python: {
    registry: { type: "pypi", name: "tollwarden" },
    // pyproject.toml uses hatchling dynamic versioning — __init__.py is the
    // single source; there is nothing else to drift.
    spots: () => ({
      "sdk-python __version__": match("sdk-python/src/tollwarden/__init__.py", /__version__ = "([^"]+)"/, "__version__"),
    }),
  },
  langchain: {
    registry: { type: "pypi", name: "langchain-tollwarden" },
    spots: () => ({
      "langchain pyproject.toml": match("integrations/langchain-tollwarden/pyproject.toml", /^version = "([^"]+)"/m, "version"),
      "langchain __version__": match("integrations/langchain-tollwarden/src/langchain_tollwarden/__init__.py", /__version__ = "([^"]+)"/, "__version__"),
    }),
  },
  crewai: {
    registry: { type: "pypi", name: "crewai-tollwarden" },
    spots: () => ({
      "crewai pyproject.toml": match("integrations/crewai-tollwarden/pyproject.toml", /^version = "([^"]+)"/m, "version"),
      "crewai __version__": match("integrations/crewai-tollwarden/src/crewai_tollwarden/__init__.py", /__version__ = "([^"]+)"/, "__version__"),
    }),
  },
  nemo: {
    registry: { type: "pypi", name: "nemo-tollwarden" },
    spots: () => ({
      "nemo pyproject.toml": match("integrations/nemo-tollwarden/pyproject.toml", /^version = "([^"]+)"/m, "version"),
      "nemo __version__": match("integrations/nemo-tollwarden/src/nemo_tollwarden/__init__.py", /__version__ = "([^"]+)"/, "__version__"),
    }),
  },
  agentkit: {
    registry: { type: "pypi", name: "agentkit-tollwarden" },
    spots: () => ({
      "agentkit pyproject.toml": match("integrations/agentkit-tollwarden/pyproject.toml", /^version = "([^"]+)"/m, "version"),
      "agentkit __version__": match("integrations/agentkit-tollwarden/src/agentkit_tollwarden/__init__.py", /__version__ = "([^"]+)"/, "__version__"),
    }),
  },
};

/** Lockstep group: the two client SDKs ship at ONE version (publish-sdks.yml).
 * Consistency means both files agree with each other; with --registry the
 * version must be unpublished on npm AND PyPI, and not an npm downgrade. */
PACKAGES.sdks = {
  registries: [PACKAGES.sdk.registry, PACKAGES.python.registry],
  spots: () => ({ ...PACKAGES.sdk.spots(), ...PACKAGES.python.spots() }),
};

const semverCmp = (a, b) => {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};

async function registryState(reg) {
  if (reg.type === "npm") {
    const res = await fetch(`https://registry.npmjs.org/${reg.name}`);
    if (res.status === 404) return { published: [], latest: null }; // new package
    if (!res.ok) throw new Error(`npm registry ${res.status}`);
    const data = await res.json();
    return { published: Object.keys(data.versions ?? {}), latest: data["dist-tags"]?.latest ?? null };
  }
  const res = await fetch(`https://pypi.org/pypi/${reg.name}/json`);
  if (res.status === 404) return { published: [], latest: null }; // new package
  if (!res.ok) throw new Error(`PyPI ${res.status}`);
  const data = await res.json();
  return { published: Object.keys(data.releases ?? {}), latest: data.info?.version ?? null };
}

async function checkPackage(key, withRegistry) {
  const pkg = PACKAGES[key];
  const spots = pkg.spots();
  const versions = new Set(Object.values(spots));
  const registries = pkg.registries ?? [pkg.registry];
  console.log(`\n${key} (${registries.map((r) => `${r.type}: ${r.name}`).join(", ")})`);
  for (const [where, v] of Object.entries(spots)) console.log(`  ${v}  ${where}`);

  const problems = [];
  if (versions.size !== 1) {
    problems.push(`INCONSISTENT: ${[...versions].join(" vs ")} — run: node scripts/set-version.mjs ${key} <version>`);
  } else if (withRegistry) {
    const v = [...versions][0];
    for (const registry of registries) {
      const before = problems.length;
      const state = await registryState(registry);
      if (state.published.includes(v)) {
        problems.push(`ALREADY PUBLISHED: ${registry.name}@${v} exists on ${registry.type} — bump before publishing.`);
      }
      if (registry.type === "npm" && state.latest && semverCmp(v, state.latest) < 0) {
        problems.push(
          `DOWNGRADE: ${v} < published latest ${state.latest} — npm's \`latest\` tag follows the most recent ` +
            `publish, so this would silently downgrade every installer. Use a higher version.`,
        );
      }
      if (problems.length === before) console.log(`  ✓ not yet on ${registry.type} (${registry.name} latest: ${state.latest ?? "none"}) — safe to publish`);
    }
  }
  for (const p of problems) console.error(`  ✗ ${p}`);
  return problems.length === 0;
}

const target = process.argv[2];
const withRegistry = process.argv.includes("--registry");
const keys = target === "all" || !target ? Object.keys(PACKAGES).filter((k) => k !== "sdks") : [target];
if (keys.some((k) => !PACKAGES[k])) {
  console.error(`Unknown package "${target}". Valid: ${Object.keys(PACKAGES).join(", ")}, all`);
  process.exit(2);
}
let ok = true;
for (const k of keys) ok = (await checkPackage(k, withRegistry)) && ok;
console.log(ok ? "\nAll version checks passed." : "\nVersion checks FAILED.");
process.exit(ok ? 0 : 1);
