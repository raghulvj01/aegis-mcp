#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const REQUIREMENTS_FILE = path.join(PROJECT_ROOT, "requirements.txt");
const RUNTIME_ROOT = process.env.AEGIS_HOME || path.join(os.homedir(), ".aegis-mcp");
const VENV_DIR = path.join(RUNTIME_ROOT, "venv");
const REQUIREMENTS_STAMP = path.join(RUNTIME_ROOT, ".requirements.sha256");
const IS_WINDOWS = process.platform === "win32";
const DEBUG = process.env.AEGIS_DEBUG === "1";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options
  });

  if (DEBUG && result.stdout) {
    process.stderr.write(result.stdout);
  }
  if (DEBUG && result.stderr) {
    process.stderr.write(result.stderr);
  }

  return result;
}

function throwCommandError(result, contextMessage) {
  const output = `${result?.stdout || ""}\n${result?.stderr || ""}`.trim();
  if (output) {
    process.stderr.write(`${output}\n`);
  }
  throw new Error(contextMessage);
}

function candidatePythonCommands() {
  const override = process.env.AEGIS_PYTHON;
  if (override && override.trim()) {
    const pieces = override.trim().split(/\s+/);
    return [{ command: pieces[0], prefixArgs: pieces.slice(1), label: override.trim() }];
  }

  if (IS_WINDOWS) {
    return [
      { command: "py", prefixArgs: ["-3"], label: "py -3" },
      { command: "python", prefixArgs: [], label: "python" },
      { command: "python3", prefixArgs: [], label: "python3" }
    ];
  }

  return [
    { command: "python3", prefixArgs: [], label: "python3" },
    { command: "python", prefixArgs: [], label: "python" }
  ];
}

function findWorkingPython() {
  for (const candidate of candidatePythonCommands()) {
    const versionCheck = run(candidate.command, [...candidate.prefixArgs, "--version"]);
    if (versionCheck.status === 0) {
      return candidate;
    }
  }

  throw new Error(
    "Python 3.12+ was not found. Install Python and make sure it is on PATH, or set AEGIS_PYTHON."
  );
}

function venvPythonPath() {
  if (IS_WINDOWS) {
    return path.join(VENV_DIR, "Scripts", "python.exe");
  }
  return path.join(VENV_DIR, "bin", "python");
}

function venvScriptsPath() {
  if (IS_WINDOWS) {
    return path.join(VENV_DIR, "Scripts");
  }
  return path.join(VENV_DIR, "bin");
}

function requirementsHash() {
  const content = fs.readFileSync(REQUIREMENTS_FILE);
  return crypto.createHash("sha256").update(content).digest("hex");
}

function ensureVirtualEnvironment(python) {
  fs.mkdirSync(RUNTIME_ROOT, { recursive: true });

  const pythonInVenv = venvPythonPath();
  if (fs.existsSync(pythonInVenv)) {
    return;
  }

  const created = run(python.command, [...python.prefixArgs, "-m", "venv", VENV_DIR]);
  if (created.status !== 0) {
    throwCommandError(created, "Failed to create Python virtual environment.");
  }
}

function installDependencies(pythonInVenv) {
  const pipUpgrade = run(pythonInVenv, [
    "-m",
    "pip",
    "install",
    "--disable-pip-version-check",
    "--quiet",
    "--upgrade",
    "pip"
  ]);
  if (pipUpgrade.status !== 0) {
    throwCommandError(pipUpgrade, "Failed to upgrade pip in virtual environment.");
  }

  const pipInstall = run(pythonInVenv, [
    "-m",
    "pip",
    "install",
    "--disable-pip-version-check",
    "--quiet",
    "-r",
    REQUIREMENTS_FILE
  ]);
  if (pipInstall.status !== 0) {
    throwCommandError(pipInstall, "Failed to install Python dependencies.");
  }
}

function ensurePythonEnvironment() {
  if (!fs.existsSync(REQUIREMENTS_FILE)) {
    throw new Error("requirements.txt was not found in package root.");
  }

  const python = findWorkingPython();
  ensureVirtualEnvironment(python);

  const pythonInVenv = venvPythonPath();
  const expectedHash = requirementsHash();
  const currentHash = fs.existsSync(REQUIREMENTS_STAMP)
    ? fs.readFileSync(REQUIREMENTS_STAMP, "utf8").trim()
    : "";

  if (currentHash !== expectedHash) {
    installDependencies(pythonInVenv);
    fs.writeFileSync(REQUIREMENTS_STAMP, `${expectedHash}\n`, "utf8");
  }

  return {
    projectRoot: PROJECT_ROOT,
    pythonInVenv,
    scriptsDir: venvScriptsPath()
  };
}

module.exports = {
  ensurePythonEnvironment
};

if (require.main === module) {
  try {
    ensurePythonEnvironment();
  } catch (error) {
    console.error(`[aegis-mcp] ${error.message}`);
    process.exit(1);
  }
}
