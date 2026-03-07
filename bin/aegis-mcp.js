#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawn } = require("child_process");
const { ensurePythonEnvironment } = require("./prepare-python-env");

function main() {
  let runtime;
  try {
    runtime = ensurePythonEnvironment();
  } catch (error) {
    console.error(`[aegis-mcp] ${error.message}`);
    process.exit(1);
  }

  const runScript = path.join(runtime.projectRoot, "run_stdio.py");
  const env = {
    ...process.env,
    MCP_AUTH_DISABLED: process.env.MCP_AUTH_DISABLED || "true",
    PATH: `${runtime.scriptsDir}${path.delimiter}${process.env.PATH || ""}`
  };

  const child = spawn(runtime.pythonInVenv, [runScript, ...process.argv.slice(2)], {
    cwd: runtime.projectRoot,
    env,
    stdio: "inherit"
  });

  child.on("error", (error) => {
    console.error(`[aegis-mcp] Failed to start MCP server: ${error.message}`);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 0);
  });
}

main();
