#!/usr/bin/env node
// Runs the browser engine (web/js/analyzer.js) under Node and prints JSON.
// Used by tests/test_web_parity.py to prove the web demo scores emails
// exactly like the Python package.
//   node scripts/web_analyze.js file1.eml [file2.eml ...]
//   echo "raw email" | node scripts/web_analyze.js -
"use strict";
const fs = require("fs");
const path = require("path");
globalThis.PHISHCHECK_RULES = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "src", "phishcheck", "data", "rules.json"), "utf8"));
const PhishCheck = require(path.join(__dirname, "..", "web", "js", "analyzer.js"));

const files = process.argv.slice(2);
const results = files.map((f) => {
  const binary = f === "-" ? fs.readFileSync(0).toString("latin1") : fs.readFileSync(f).toString("latin1");
  return Object.assign({ file: f }, PhishCheck.analyze(binary));
});
process.stdout.write(JSON.stringify(results, null, 2) + "\n");
