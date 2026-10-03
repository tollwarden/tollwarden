#!/usr/bin/env node
// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Zero-touch releases: compute the NEXT version for a package from the
 * REGISTRY (not from git) and apply it everywhere via set-version.mjs.
 * Because the bump derives from what's actually published, a stale version in
 * git can never cause an "already published" publish failure again.
 *
 * Usage: node scripts/next-version.mjs <package|sdks> [patch|minor|major] [--dry-run]
 *   (packages are the same keys as check-versions.mjs / set-version.mjs)
 *
 * `sdks` is the LOCKSTEP group: @tollwarden/client (npm) and tollwarden (PyPI)
 * ship at one version (publish-sdks.yml). The bump starts from the HIGHER of
 * the two registries' latest releases, so a pair that drifted apart is
 * re-aligned by its next release, and both files are rewritten together.
 *
 * Rules:
 *  - next = registry latest with the requested part bumped (default: patch)
 *  - if the repo carries a HIGHER, not-yet-published version, the repo wins —
 *    that's a deliberate manual bump (e.g. staging a 2.0.0), honor it. For
 *    `sdks` both files must carry that same version; a stage on one side only
 *    is an error, never a guess
 *  - never published at all -> keep the repo version (first release as-is)
 *  - --dry-run prints the decision and writes nothing
 *
 * In GitHub Actions, writes `version=<x.y.z>` to $GITHUB_OUTPUT.
 */
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const jsonVersion = (p) => JSON.parse(read(p)).version;
const initVersion = (p) => {
  const m = read(p).match(/__version__ = "([^"]+)"/);
  if (!m) throw new Error(`could not find __version__ in ${p}`);
  return m[1];
};

/** Registry identity + where the repo's current version is read from. */
const PACKAGES = {
  server: { type: "npm", name: "tollwarden", current: () => jsonVersion("package.json") },
  sdk: { type: "npm", name: "@tollwarden/client", current: () => jsonVersion("sdk/package.json") },
  "ai-sdk": { type: "npm", name: "@tollwarden/ai-sdk", current: () => jsonVersion("integrations/ai-sdk/package.json") },
  python: { type: "pypi", name: "tollwarden", current: () => initVersion("sdk-python/src/tollwarden/__init__.py") },
  langchain: { type: "pypi", name: "langchain-tollwarden", current: () => initVersion("integrations/langchain-tollwarden/src/langchain_tollwarden/__init__.py") },
  crewai: { type: "pypi", name: "crewai-tollwarden", current: () => initVersion("integrations/crewai-tollwarden/src/crewai_tollwarden/__init__.py") },
  nemo: { type: "pypi", name: "nemo-tollwarden", current: () => initVersion("integrations/nemo-tollwarden/src/nemo_tollwarden/__init__.py") },
  agentkit: { type: "pypi", name: "agentkit-tollwarden", current: () => initVersion("integrations/agentkit-tollwarden/src/agentkit_tollwarden/__init__.py") },
};

/** Groups released at ONE shared version (set-version.mjs knows the same keys). */
const GROUPS = { sdks: ["sdk", "python"] };

const [, , key, ...rest] = process.argv;
const dryRun = rest.includes("--dry-run");
const bumpKind = rest.find((a) => !a.startsWith("--")) ?? "patch";
const members = GROUPS[key] ?? (PACKAGES[key] ? [key] : undefined);
if (!members || !["patch", "minor", "major"].includes(bumpKind)) {
  console.error(`Usage: node scripts/next-version.mjs <${[...Object.keys(PACKAGES), ...Object.keys(GROUPS)].join("|")}> [patch|minor|major] [--dry-run]`);
  process.exit(2);
}

const parse = (v) => v.split(".").map(Number);
const cmp = (a, b) => {
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};
const max = (vs) => vs.reduce((a, b) => (cmp(a, b) >= 0 ? a : b));
const bump = (v, kind) => {
  const [maj, min, pat] = parse(v);
  if (kind === "major") return `${maj + 1}.0.0`;
  if (kind === "minor") return `${maj}.${min + 1}.0`;
  return `${maj}.${min}.${pat + 1}`;
};

async function published(reg) {
  if (reg.type === "npm") {
    const res = await fetch(`https://registry.npmjs.org/${reg.name}`);
    if (res.status === 404) return [];
    if (!res.ok) throw new Error(`npm registry ${res.status} for ${reg.name}`);
    return Object.keys((await res.json()).versions ?? {});
  }
  const res = await fetch(`https://pypi.org/pypi/${reg.name}/json`);
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`PyPI ${res.status} for ${reg.name}`);
  return Object.keys((await res.json()).releases ?? {});
}

// One entry per member: what the repo says and what the registry has.
const state = [];
for (const m of members) {
  const reg = PACKAGES[m];
  const releases = (await published(reg)).filter((v) => /^\d+\.\d+\.\d+$/.test(v));
  state.push({ key: m, reg, current: reg.current(), releases, latest: releases.length ? max(releases) : null });
}
const label = state.map((s) => `${s.reg.name} (${s.reg.type}): repo ${s.current}, latest ${s.latest ?? "never published"}`).join("; ");
const currents = [...new Set(state.map((s) => s.current))];
const latests = state.map((s) => s.latest).filter((v) => v !== null);
const latest = latests.length ? max(latests) : null;
const publishedAnywhere = (v) => state.some((s) => s.releases.includes(v));

let next;
if (latest === null) {
  if (currents.length !== 1) {
    console.error(`${key}: never published, and the repo versions disagree (${label}). Run: node scripts/set-version.mjs ${key} <x.y.z>`);
    process.exit(1);
  }
  next = currents[0]; // first release: publish exactly what's in the repo
  console.log(`${key}: never published — keeping repo version ${next}`);
} else {
  const candidate = bump(latest, bumpKind);
  // A repo version above the registry that isn't published is a deliberate
  // manual bump (e.g. a staged minor/major) — honor it instead of the bump.
  const staged = state.filter((s) => cmp(s.current, candidate) > 0 && !publishedAnywhere(s.current));
  if (staged.length > 0 && currents.length !== 1) {
    console.error(`${key}: a staged version is not carried by every member (${label}). Stage them together: node scripts/set-version.mjs ${key} <x.y.z>`);
    process.exit(1);
  }
  next = staged.length > 0 ? currents[0] : candidate;
  console.log(`${key}: registry latest ${latest} -> next ${next} (${bumpKind}${next !== candidate ? ", honoring repo version" : ""})`);
  if (members.length > 1) console.log(`  ${label}`);
}

if (state.every((s) => s.current === next)) {
  console.log(`repo already at ${next}; nothing to rewrite`);
} else if (dryRun) {
  console.log(`dry run: would run set-version.mjs ${key} ${next}`);
} else {
  execFileSync("node", [join(ROOT, "scripts", "set-version.mjs"), key, next], { stdio: "inherit" });
}

if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version=${next}\n`);
