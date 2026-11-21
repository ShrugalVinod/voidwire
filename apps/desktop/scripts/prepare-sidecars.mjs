#!/usr/bin/env node
// Build `voidwired` (vw-daemon) and `voidwire` (vw-cli) from the workspace and
// copy them to src-tauri/binaries/<name>-<target-triple>[.exe], the layout
// Tauri's `bundle.externalBin` expects.
//
//   node scripts/prepare-sidecars.mjs                 # host triple, release
//   node scripts/prepare-sidecars.mjs --target x86_64-pc-windows-msvc
//   node scripts/prepare-sidecars.mjs --profile debug
//
// On Windows it also checks that src-tauri/resources/wintun.dll is present.

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const desktop = resolve(here, "..");
const workspace = resolve(desktop, "..", "..");
const binDir = join(desktop, "src-tauri", "binaries");

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const hostTriple = execFileSync("rustc", ["-vV"], { encoding: "utf8" })
  .split("\n")
  .find((l) => l.startsWith("host:"))
  ?.slice(5)
  .trim();
const triple = opt("--target") ?? hostTriple;
if (!triple) throw new Error("could not determine the target triple (is rustc installed?)");
const profile = opt("--profile") ?? "release";
const exe = triple.includes("windows") ? ".exe" : "";

const cargoArgs = ["build", "--target", triple, "-p", "vw-daemon", "--bin", "voidwired", "-p", "vw-cli", "--bin", "voidwire"];
if (profile === "release") cargoArgs.push("--release");
console.log(`cargo ${cargoArgs.join(" ")}`);
execFileSync("cargo", cargoArgs, { cwd: workspace, stdio: "inherit" });

const targetDir = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(workspace, "target");
const outDir = join(targetDir, triple, profile === "release" ? "release" : "debug");
mkdirSync(binDir, { recursive: true });
for (const name of ["voidwired", "voidwire"]) {
  const src = join(outDir, `${name}${exe}`);
  const dst = join(binDir, `${name}-${triple}${exe}`);
  if (!existsSync(src)) throw new Error(`expected build output ${src}`);
  copyFileSync(src, dst);
  if (!exe) chmodSync(dst, 0o755);
  console.log(`sidecar ${dst}`);
}

if (triple.includes("windows")) {
  const dll = join(desktop, "src-tauri", "resources", "wintun.dll");
  if (!existsSync(dll)) {
    console.error(
      `missing ${dll}: download the amd64 wintun.dll from https://www.wintun.net (see apps/desktop/README.md)`,
    );
    process.exit(1);
  }
}
