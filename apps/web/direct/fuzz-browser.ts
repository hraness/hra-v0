#!/usr/bin/env bun
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runDirectBombadilFuzz } from "@hraness/direct/tooling/bombadil";

const directRoot = fileURLToPath(new URL(".", import.meta.url));
const productRoot = resolve(directRoot, "..");
const repositoryRoot = resolve(directRoot, "../../..");

await runDirectBombadilFuzz({
  artifactName: "hra-v0-web",
  baseUrl: "http://127.0.0.1:5176",
  expectedRoute: "/",
  label: "HRA v0 web Direct Bombadil fuzzing",
  repositoryRoot,
  scenario: "tasks-rich-review",
  specificationPath: resolve(directRoot, "bombadil-campaign.ts"),
  targetQuery: { directFrame: "1" },
  server: {
    command: [
      resolve(productRoot, "node_modules/.bin/vite"),
      "--config",
      "direct/vite.config.ts",
      "--port",
      "{port}",
    ],
    cwd: productRoot,
    env: { CI: "1" },
    readinessPath: "/",
    startupTimeoutMs: 30_000,
  },
}, process.argv.slice(2));
