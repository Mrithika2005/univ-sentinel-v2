#!/usr/bin/env node

// univ-sentinel CLI  v2.2
// Usage: npx --yes github:Mrithika2005/univ-sentinel-logs-v2
// Run inside your project root

import fs        from 'fs';
import path      from 'path';
import { execSync, spawn } from 'child_process';
import { fileURLToPath }   from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ─────────────────────────────────────────────────────────────
   CONFIG — reads SENTINEL_HOST from env, defaults to LAN IP
───────────────────────────────────────────────────────────── */

const SENTINEL_HOST = process.env.SENTINEL_HOST || '192.168.1.153';
const SENTINEL_PORT = process.env.SENTINEL_PORT || '4318';
const SENTINEL_URL  = `http://${SENTINEL_HOST}:${SENTINEL_PORT}/sentinel/ingest`;

const C = {
  green:  (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red:    (s) => `\x1b[31m${s}\x1b[0m`,
  cyan:   (s) => `\x1b[36m${s}\x1b[0m`,
  bold:   (s) => `\x1b[1m${s}\x1b[0m`,
};

const log = {
  info: (s) => console.log(C.cyan(`[sentinel] ${s}`)),
  ok:   (s) => console.log(C.green(`[sentinel] ✓ ${s}`)),
  warn: (s) => console.log(C.yellow(`[sentinel] ⚠ ${s}`)),
  err:  (s) => console.log(C.red(`[sentinel] ✗ ${s}`)),
};

/* ─────────────────────────────────────────────────────────────
   PYTHON PATCH
───────────────────────────────────────────────────────────── */

const PYTHON_MARKER = '# ── sentinel-sdk ──';

const PYTHON_SNIPPET = `
${PYTHON_MARKER}
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), 'sentinel-sdk', 'python'))
try:
    from agent import init_sentinel as _init_sentinel
    _sentinel = _init_sentinel(
        service_name=_os.getenv('SENTINEL_SERVICE', 'python-service'),
        clickhouse_host=_os.getenv('CLICKHOUSE_HOST', 'http://${SENTINEL_HOST}:8123'),
        clickhouse_database=_os.getenv('CLICKHOUSE_DATABASE', 'sentinel'),
        clickhouse_table=_os.getenv('CLICKHOUSE_TABLE', 'logs'),
        clickhouse_user=_os.getenv('CLICKHOUSE_USER', ''),
        clickhouse_password=_os.getenv('CLICKHOUSE_PASSWORD', ''),
        debug=_os.getenv('SENTINEL_DEBUG', 'false').lower() == 'true',
        log_level=_os.getenv('LOG_LEVEL', 'INFO'),
    )
except Exception as _e:
    import logging as _logging
    _logging.warning(f'[sentinel] failed to init: {_e}')
# ── /sentinel-sdk ──
`;

function patchPython(filePath) {
  let src = fs.readFileSync(filePath, 'utf-8');
  if (src.includes(PYTHON_MARKER)) { log.warn(`${filePath} already patched — skipping`); return; }
  const lines = src.split('\n');
  let lastImport = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^(import |from )/.test(lines[i])) lastImport = i;
  }
  lines.splice(lastImport + 1, 0, PYTHON_SNIPPET);
  fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
  log.ok(`Patched Python: ${filePath}`);
}

/* ─────────────────────────────────────────────────────────────
   NODE.JS PATCH
───────────────────────────────────────────────────────────── */

const NODE_MARKER = '// ── sentinel-sdk-node ──';

const NODE_SNIPPET = `
${NODE_MARKER}
import { initSentinel as __initSentinel } from './sentinel-sdk/node/agent.ts';
await __initSentinel({
  serviceName:        process.env.SENTINEL_SERVICE        || 'node-service',
  clickhouseHost:     process.env.CLICKHOUSE_HOST         || 'http://${SENTINEL_HOST}:8123',
  clickhouseDatabase: process.env.CLICKHOUSE_DATABASE     || 'sentinel',
  clickhouseTable:    process.env.CLICKHOUSE_TABLE        || 'logs',
  clickhouseUser:     process.env.CLICKHOUSE_USER         || '',
  clickhousePassword: process.env.CLICKHOUSE_PASSWORD     || '',
  debug:              process.env.SENTINEL_DEBUG === 'true',
  logLevel:           process.env.LOG_LEVEL               || 'INFO',
  certCheckHosts:     process.env.SENTINEL_CERT_HOSTS
                        ? process.env.SENTINEL_CERT_HOSTS.split(',').map(h => h.trim())
                        : [],
});
// ── /sentinel-sdk-node ──
`;

const NODE_ENTRY_RE = /^(index|server|app|main)\.[jt]s$/;
const BROWSER_SIGS  = ['React', 'ReactDOM', 'createRoot', 'angular', 'NgModule', 'bootstrapModule'];

function isNodeEntryFile(filePath, src) {
  if (!NODE_ENTRY_RE.test(path.basename(filePath))) return false;
  for (const sig of BROWSER_SIGS) { if (src.includes(sig)) return false; }
  return true;
}

function patchNode(filePath) {
  let src = fs.readFileSync(filePath, 'utf-8');
  if (!isNodeEntryFile(filePath, src)) return false;
  if (src.includes(NODE_MARKER)) { log.warn(`${filePath} already patched — skipping`); return true; }
  const lines = src.split('\n');
  let lastImport = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^import /.test(lines[i])) lastImport = i;
  }
  lines.splice(lastImport + 1, 0, NODE_SNIPPET);
  fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
  log.ok(`Patched Node: ${filePath}`);
  return true;
}

/* ─────────────────────────────────────────────────────────────
   BROWSER PATCH — React + Angular
───────────────────────────────────────────────────────────── */

const BROWSER_MARKER = '// ── sentinel-sdk-browser ──';

const REACT_SNIPPET = `
${BROWSER_MARKER}
import { initBrowserSentinel as __initBrowserSentinel } from './sentinel-sdk/browser/agent.ts';
__initBrowserSentinel({
  serviceName:  (window.__SENTINEL_SERVICE__  || 'browser-app'),
  relayUrl:     (window.__SENTINEL_RELAY__    || '${SENTINEL_URL}'),
  debug:        (window.__SENTINEL_DEBUG__    || false),
  samplingRate: (window.__SENTINEL_SAMPLING__ || 1.0),
});
// ── /sentinel-sdk-browser ──
`;

const ANGULAR_SNIPPET = `
${BROWSER_MARKER}
// @ts-ignore
import { initBrowserSentinel as __initBrowserSentinel } from '../sentinel-sdk/browser/agent.ts';
try {
  __initBrowserSentinel({
    serviceName:  'angular-app',
    relayUrl:     '${SENTINEL_URL}',
    debug:        false,
    samplingRate: 1.0,
  });
} catch(e) { console.warn('[sentinel] init failed', e); }
// ── /sentinel-sdk-browser ──
`;

const REACT_FILE_RE   = /^[Aa]pp\.[jt]sx?$/;
const ANGULAR_FILE_RE = /^app\.(component|module)\.[jt]s$/;

function patchBrowser(filePath) {
  let src = fs.readFileSync(filePath, 'utf-8');
  if (src.includes(BROWSER_MARKER)) { log.warn(`${filePath} already patched — skipping`); return; }
  const name      = path.basename(filePath);
  const isAngular = ANGULAR_FILE_RE.test(name);
  const snippet   = isAngular ? ANGULAR_SNIPPET : REACT_SNIPPET;
  const label     = isAngular ? 'Angular' : 'React';
  const lines     = src.split('\n');
  let lastImport  = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^import /.test(lines[i])) lastImport = i;
  }
  lines.splice(lastImport + 1, 0, snippet);
  fs.writeFileSync(filePath, lines.join('\n'), 'utf-8');
  log.ok(`Patched ${label}: ${filePath}`);
}

/* ─────────────────────────────────────────────────────────────
   AUTO COPY sentinel-sdk into the right place
───────────────────────────────────────────────────────────── */

function copySentinelSdk(cwd, hasSrc) {
  const sdkSrc  = path.join(__dirname, 'sentinel-sdk');
  const sdkDest = hasSrc ? path.join(cwd, 'src', 'sentinel-sdk') : path.join(cwd, 'sentinel-sdk');

  if (!fs.existsSync(sdkSrc)) {
    log.warn('sentinel-sdk folder not found in package — skipping copy');
    return;
  }

  if (fs.existsSync(sdkDest)) {
    log.warn(`sentinel-sdk already exists at ${sdkDest} — skipping copy`);
    return;
  }

  fs.cpSync(sdkSrc, sdkDest, { recursive: true });
  log.ok(`Copied sentinel-sdk → ${sdkDest}`);
}

/* ─────────────────────────────────────────────────────────────
   AUTO START relay server in background
───────────────────────────────────────────────────────────── */

function startRelayServer() {
  const serverPath = path.join(__dirname, 'server.ts');
  if (!fs.existsSync(serverPath)) {
    log.warn('server.ts not found — skipping relay server start');
    return;
  }

  const CH_HOST = process.env.CLICKHOUSE_HOST     || `http://${SENTINEL_HOST}:8123`;
  const CH_USER = process.env.CLICKHOUSE_USER     || '';
  const CH_PASS = process.env.CLICKHOUSE_PASSWORD || '';

  log.info('Starting relay server in background...');

  const child = spawn('npx', ['tsx', serverPath], {
    detached: true,
    stdio:    'ignore',
    env: {
      ...process.env,
      CLICKHOUSE_HOST:     CH_HOST,
      CLICKHOUSE_USER:     CH_USER,
      CLICKHOUSE_PASSWORD: CH_PASS,
      SENTINEL_PORT:       SENTINEL_PORT,
    },
  });

  child.unref();
  log.ok(`Relay server started in background on port ${SENTINEL_PORT}`);
  log.info(`Health check: http://${SENTINEL_HOST}:${SENTINEL_PORT}/sentinel/health`);
}

/* ─────────────────────────────────────────────────────────────
   FILE FINDER
───────────────────────────────────────────────────────────── */

const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'dist', 'build', '.next', 'out']);

function findFiles(dir, matcher, results = []) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) findFiles(full, matcher, results);
    else if (matcher(entry.name)) results.push(full);
  }
  return results;
}

/* ─────────────────────────────────────────────────────────────
   MAIN
───────────────────────────────────────────────────────────── */

console.log(C.bold('\n  univ-sentinel v2.2 — LAN-aware auto-patch\n'));

const cwd    = process.cwd();
const hasSrc = fs.existsSync(path.join(cwd, 'src'));

log.info(`Scanning:      ${cwd}`);
log.info(`Relay target:  ${SENTINEL_URL}\n`);

let patched = 0;

// 1. Python
const pyFiles = findFiles(cwd, (n) => n === 'main.py');
if (pyFiles.length === 0) log.warn('No main.py found — skipping Python patch');
else pyFiles.forEach(f => { patchPython(f); patched++; });

// 2. Node backend
const nodeFiles = findFiles(cwd, (n) => NODE_ENTRY_RE.test(n));
nodeFiles.forEach(f => { if (patchNode(f)) patched++; });
if (nodeFiles.length === 0) log.warn('No Node entry file (index/server/app/main .ts/.js) — skipping Node patch');

// 3. React
const reactFiles = findFiles(cwd, (n) => REACT_FILE_RE.test(n));
if (reactFiles.length === 0) log.warn('No App.jsx/App.tsx found — skipping React patch');
else reactFiles.forEach(f => { patchBrowser(f); patched++; });

// 4. Angular
const angularFiles = findFiles(cwd, (n) => ANGULAR_FILE_RE.test(n));
if (angularFiles.length === 0) log.warn('No app.component.ts/app.module.ts — skipping Angular patch');
else angularFiles.forEach(f => { patchBrowser(f); patched++; });

if (patched === 0) {
  log.err('Nothing patched. Run this from your project root.');
  process.exit(1);
}

// 5. Auto-copy sentinel-sdk into the right place
console.log('');
copySentinelSdk(cwd, hasSrc);

// 6. Auto-start relay server in background
startRelayServer();

console.log('');
log.ok(`Done! ${patched} file(s) patched.`);
console.log(C.cyan(`
  ┌─────────────────────────────────────────────────────┐
  │  univ-sentinel v2.2 — all done!                     │
  │                                                     │
  │  Relay:  http://${SENTINEL_HOST}:${SENTINEL_PORT}/sentinel/health  │
  │  Logs:   http://${SENTINEL_HOST}:8123/play           │
  │                                                     │
  │  Just run your app — logs flow automatically!       │
  └─────────────────────────────────────────────────────┘
`));
