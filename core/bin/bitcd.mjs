#!/usr/bin/env node
// bitcd — the org-declaration CLI. The command itself is ../src/cli.mjs; this
// entry point only supplies the yaml parser, so the library needs none.
import { parse as parseYaml } from "yaml";
import { runBitcd } from "../src/cli.mjs";

await runBitcd({ parseYaml });
