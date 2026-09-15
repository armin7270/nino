import express, { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import net from 'net';
import zlib from 'zlib';
import crypto from 'crypto';
import { spawn, ChildProcess, exec } from 'child_process';
import * as archiverModule from 'archiver';

// ==============================================================================
// AnyTLS Manager Panel — Railway-ready edition
//
// Networking model
// ------------------------------------------------------------------------------
// Railway allows exactly ONE TCP proxy per service, so only one port can ever be
// reachable from the internet. This panel therefore always owns that single
// public port itself:
//
//   internet ──► GATEWAY_PORT (Node TCP proxy, always listening)
//                     │  forwards to the "public" configuration
//                     ▼
//                 127.0.0.1:<config.port>   (one anytls-server child per config)
//
// Consequences:
//   * The public port is bound immediately at boot, so the platform can always
//     detect and route it — even before any tunnel is configured.
//   * Switching which client is exposed is a pointer change, not a restart.
//   * Traffic is measured inside the proxy (cross-platform, no /proc parsing).
//   * Every active configuration keeps its own process and its own password;
//     only the one marked "public" is reachable through the proxy.
//
// The web panel is a separate listener bound to $PORT, as Railway requires.
//
// NOTE: `vite` is intentionally NOT imported here. It is a devDependency, and
// importing it would crash a production container installed with --omit=dev.
// ==============================================================================

function createZipArchive(options?: any) {
  const mod: any = archiverModule;
  if (typeof mod.ZipArchive === 'function') {
    return new mod.ZipArchive(options);
  }
  if (typeof mod.default === 'function') {
    return mod.default('zip', options);
  }
  if (typeof mod === 'function') {
    return mod('zip', options);
  }
  throw new Error('Unable to initialize zip archive');
}

// ==============================================================================
// Runtime configuration
// ==============================================================================

const ANYTLS_VERSION = (process.env.ANYTLS_VERSION || 'v0.0.13').trim();
const ANYTLS_VERSION_NUM = ANYTLS_VERSION.replace(/^v/, '');
const SERVER_BINARY_NAME = process.platform === 'win32' ? 'anytls-server.exe' : 'anytls-server';

/** Web panel port. Railway injects PORT. */
const PORT = Number(process.env.PORT) || 3000;

/**
 * The single public port. This is the value to enter as the "application port"
 * when creating the Railway TCP Proxy. Override with ANYTLS_GATEWAY_PORT.
 */
const GATEWAY_PORT = Number(process.env.ANYTLS_GATEWAY_PORT) || 8443;

/** First port handed out to per-configuration tunnel processes. */
const INTERNAL_PORT_BASE = Number(process.env.ANYTLS_INTERNAL_PORT_BASE) || 20100;

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'config.json');

/** Where a runtime-downloaded anytls-server binary is written. */
const VENDOR_DIR = process.env.VENDOR_DIR
  ? path.resolve(process.env.VENDOR_DIR)
  : path.join(process.cwd(), 'vendor');

const isRailwayRuntime = Boolean(
  process.env.RAILWAY_ENVIRONMENT_ID ||
    process.env.RAILWAY_PROJECT_ID ||
    process.env.RAILWAY_SERVICE_ID ||
    process.env.RAILWAY_PUBLIC_DOMAIN ||
    process.env.RAILWAY_TCP_PROXY_DOMAIN
);

// ==============================================================================
// Types
// ==============================================================================

interface StoredConfig {
  id: string;
  remark: string;
  /** Internal loopback port for this configuration's anytls-server process. */
  port: number;
  password: string;
  sni: string;
  trafficLimitGB: number;
  trafficUsedBytes: number;
  expireDays: number;
  expireAt: string | null;
  createdAt: string;
  status: 'active' | 'disabled' | 'expired';
  insecure: boolean;
  notes?: string;
}

interface GatewayInfo {
  /** Configuration the public port currently forwards to. */
  activeConfigId: string | null;
  updatedAt: string;
}

interface AppData {
  admin: {
    username: string;
    passwordHash: string;
    salt: string;
  };
  /** Manual override for the public host (empty = auto-detect). */
  serverIp: string;
  /** Manual override for the public port (0 = auto-detect). */
  panelPort: number;
  isStandalone?: boolean;
  gateway?: GatewayInfo | null;
  configs: StoredConfig[];
}

interface ProcessInfo {
  configId: string;
  remark: string;
  port: number;
  process?: ChildProcess;
  pid?: number;
  status: 'running' | 'stopped' | 'failed';
  startedAt?: string;
  logs: string[];
  lastExit?: { code: number | null; signal: string | null; at: string };
  lastStartAttempt: number;
}

interface PublicEndpoint {
  host: string;
  port: number;
  source: 'manual' | 'railway-tcp' | 'railway-domain' | 'auto';
  manualHost: string;
  manualPort: number;
  autoIp: string;
  /** Railway HTTP domain (e.g. panel.up.railway.app) — HTTPS, port 443. */
  panelDomain: string | null;
  /** Railway TCP proxy host/port (e.g. shuttle.proxy.rlwy.net:15140). */
  tcpDomain: string | null;
  tcpPort: number | null;
  /** Internal port the TCP proxy must forward to. */
  gatewayPort: number;
}

const activeProcesses = new Map<string, ProcessInfo>();

/** Bytes observed by the proxy but not yet written to config.json. */
const pendingBytes = new Map<string, number>();

// ==============================================================================
// Data persistence
// ==============================================================================

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

function ensureDataDir(): void {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch (err) {
    console.error(`[Panel] Unable to create data directory ${DATA_DIR}:`, err);
  }
}

function getDefaultData(): AppData {
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(
    process.env.ADMIN_PASSWORD || process.env.PANEL_PASSWORD || 'admin123',
    salt
  );

  return {
    admin: {
      username: process.env.ADMIN_USERNAME || process.env.PANEL_USERNAME || 'admin',
      passwordHash,
      salt,
    },
    serverIp: process.env.PUBLIC_HOST || process.env.SERVER_IP || '',
    panelPort: Number(process.env.PUBLIC_PORT || process.env.SERVER_PORT) || 0,
    isStandalone: true,
    gateway: { activeConfigId: null, updatedAt: new Date().toISOString() },
    // Start empty: no demo data, so a fresh Railway deploy is clean.
    configs: [],
  };
}

function loadData(): AppData {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) {
    const defaultData = getDefaultData();
    saveData(defaultData);
    return defaultData;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8')) as AppData;
    let dirty = false;

    // Backward compatibility: plain-text password from older installs.
    if (parsed.admin && (parsed.admin as any).password && !parsed.admin.passwordHash) {
      const salt = crypto.randomBytes(16).toString('hex');
      parsed.admin.passwordHash = hashPassword((parsed.admin as any).password, salt);
      parsed.admin.salt = salt;
      delete (parsed.admin as any).password;
      dirty = true;
    }

    if (!parsed.configs || !Array.isArray(parsed.configs)) {
      parsed.configs = [];
      dirty = true;
    }
    if (parsed.gateway === undefined) {
      parsed.gateway = { activeConfigId: null, updatedAt: new Date().toISOString() };
      dirty = true;
    }

    if (ensureInternalPorts(parsed)) dirty = true;

    if (dirty) saveData(parsed);
    return parsed;
  } catch (err) {
    console.error('Error loading config.json:', err);
    return getDefaultData();
  }
}

function saveData(data: AppData): void {
  ensureDataDir();
  try {
    const tmp = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tmp, DATA_FILE);
  } catch (err) {
    console.error('Error saving config.json:', err);
  }
}

/**
 * Guarantees every configuration owns a unique loopback port that never
 * collides with the web panel port or the public tunnel port.
 * Returns true when something changed.
 */
function ensureInternalPorts(data: AppData): boolean {
  let changed = false;
  const used = new Set<number>();

  for (const cfg of data.configs) {
    const port = Number(cfg.port) || 0;
    if (port > 0 && port !== GATEWAY_PORT && port !== PORT && !used.has(port)) {
      used.add(port);
    } else if (cfg.port !== 0) {
      // A config pointing at the public/panel port (or a duplicate) must be moved.
      cfg.port = 0;
      changed = true;
    }
  }

  let candidate = INTERNAL_PORT_BASE;
  for (const cfg of data.configs) {
    if (!cfg.port) {
      while (used.has(candidate) || candidate === GATEWAY_PORT || candidate === PORT) {
        candidate++;
      }
      cfg.port = candidate;
      used.add(candidate);
      changed = true;
    }
  }

  return changed;
}

// ==============================================================================
// Public endpoint resolution (Railway aware)
// ==============================================================================

let cachedAutoIp = process.env.SERVER_IP || '';
let autoIpDetected = false;

function detectAutoIp(): void {
  if (autoIpDetected && cachedAutoIp) return;
  autoIpDetected = true;

  const fromEnv =
    process.env.SERVER_IP ||
    process.env.RAILWAY_TCP_PROXY_DOMAIN ||
    process.env.RAILWAY_PUBLIC_DOMAIN;
  if (fromEnv) {
    cachedAutoIp = fromEnv;
    return;
  }

  // Local interface fallback (works even when outbound HTTP is blocked).
  try {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const iface of ifaces[name] || []) {
        if (!iface.internal && iface.family === 'IPv4') {
          cachedAutoIp = iface.address;
          return;
        }
      }
    }
  } catch {
    // ignore
  }

  // Public IP lookup (best effort, never blocks the caller).
  fetch('https://api.ipify.org?format=json')
    .then((r) => r.json())
    .then((res: any) => {
      if (res && res.ip) cachedAutoIp = res.ip;
    })
    .catch(() => {
      try {
        exec('curl -s -4 --max-time 5 https://api.ipify.org', (err, stdout) => {
          const ip = (stdout || '').trim();
          if (!err && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) cachedAutoIp = ip;
        });
      } catch {
        // ignore
      }
    });
}

function resolvePublicEndpoint(data: AppData): PublicEndpoint {
  const tcpDomain = process.env.RAILWAY_TCP_PROXY_DOMAIN || null;
  const tcpPort = Number(process.env.RAILWAY_TCP_PROXY_PORT) || null;
  const panelDomain = process.env.RAILWAY_PUBLIC_DOMAIN || null;

  const manualHost = (data.serverIp || '').trim();
  const manualPort = Number(data.panelPort) || 0;

  const base = {
    manualHost,
    manualPort,
    autoIp: cachedAutoIp,
    panelDomain,
    tcpDomain,
    tcpPort,
    gatewayPort: GATEWAY_PORT,
  };

  // 1. Explicit environment override always wins.
  const envHost = (process.env.PUBLIC_HOST || '').trim();
  const envPort = Number(process.env.PUBLIC_PORT) || 0;
  if (envHost) {
    return {
      ...base,
      host: envHost,
      port: envPort || manualPort || tcpPort || GATEWAY_PORT,
      source: 'manual',
      manualHost: envHost,
      manualPort: envPort || manualPort,
    };
  }

  // 2. Manual override saved from the panel UI.
  if (manualHost && manualPort > 0) {
    return { ...base, host: manualHost, port: manualPort, source: 'manual' };
  }

  // 3. Railway TCP proxy — the address a VPN client must connect to.
  if (tcpDomain && tcpPort) {
    return { ...base, host: tcpDomain, port: tcpPort, source: 'railway-tcp' };
  }

  // 4. Railway HTTP domain (TCP proxy not created yet, or intentionally unused).
  if (panelDomain) {
    return { ...base, host: panelDomain, port: 443, source: 'railway-domain' };
  }

  // 5. Last resort: detected IP / configured host.
  return {
    ...base,
    host: manualHost || cachedAutoIp || '127.0.0.1',
    port: manualPort || tcpPort || GATEWAY_PORT,
    source: 'auto',
  };
}

// ==============================================================================
// AnyTLS server binary management
// ==============================================================================

function findSystemBinary(): string | null {
  const candidates = [
    process.env.ANYTLS_SERVER_BIN || '',
    '/usr/local/bin/anytls-server',
    '/usr/bin/anytls-server',
    path.join(process.cwd(), 'bin', SERVER_BINARY_NAME),
    path.join(VENDOR_DIR, SERVER_BINARY_NAME),
    '/opt/anytls-panel/bin/anytls-server',
    '/opt/anytls-panel/anytls-server',
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // ignore
    }
  }
  return null;
}

function detectReleaseArch(): string | null {
  if (process.arch === 'x64') return 'amd64';
  if (process.arch === 'arm64') return 'arm64';
  return null;
}

function detectReleasePlatform(): string | null {
  if (process.platform === 'linux') return 'linux';
  if (process.platform === 'darwin') return 'darwin';
  if (process.platform === 'win32') return 'windows';
  return null;
}

interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  dataOffset: number;
}

/**
 * Minimal ZIP central-directory reader, so the panel does not depend on the
 * `unzip` binary (absent from slim container images) when fetching the official
 * anytls-go release archive.
 */
function readZipEntries(buf: Buffer): ZipEntry[] {
  const EOCD_SIG = 0x06054b50;
  let eocd = -1;
  const scanStart = Math.max(0, buf.length - 66000);
  for (let i = buf.length - 22; i >= scanStart; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('Not a valid ZIP archive (no end-of-central-directory record)');

  const totalEntries = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];

  for (let i = 0; i < totalEntries; i++) {
    if (buf.readUInt32LE(offset) !== 0x02014b50) break;
    const method = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localOffset = buf.readUInt32LE(offset + 42);
    const name = buf.toString('utf8', offset + 46, offset + 46 + nameLen);

    // The payload offset must come from the local header, which repeats the
    // name/extra lengths (the central directory values may differ).
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLen + localExtraLen;

    entries.push({ name, method, compressedSize, dataOffset });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function extractZipEntry(buf: Buffer, entry: ZipEntry): Buffer {
  const raw = buf.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(raw);
  if (entry.method === 8) return zlib.inflateRawSync(raw);
  throw new Error(`Unsupported ZIP compression method ${entry.method}`);
}

let binaryEnsurePromise: Promise<string | null> | null = null;
let binaryDownloadState: 'idle' | 'downloading' | 'ready' | 'failed' = 'idle';
let binaryDownloadError = '';

async function downloadAnyTlsBinary(): Promise<string | null> {
  const platform = detectReleasePlatform();
  const arch = detectReleaseArch();
  if (!platform || !arch) {
    binaryDownloadState = 'failed';
    binaryDownloadError = `Unsupported platform ${process.platform}/${process.arch}`;
    return null;
  }

  const destDir = VENDOR_DIR;
  const dest = path.join(destDir, SERVER_BINARY_NAME);
  const url =
    process.env.ANYTLS_DOWNLOAD_URL ||
    `https://github.com/anytls/anytls-go/releases/download/${ANYTLS_VERSION}/anytls_${ANYTLS_VERSION_NUM}_${platform}_${arch}.zip`;

  binaryDownloadState = 'downloading';
  binaryDownloadError = '';

  try {
    fs.mkdirSync(destDir, { recursive: true });
    console.log(`[AnyTLS] Downloading server binary (${platform}/${arch}): ${url}`);

    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status} while downloading ${url}`);

    const zipBuf = Buffer.from(await res.arrayBuffer());
    const entries = readZipEntries(zipBuf);
    const wanted = entries.find((e) => /(^|\/)anytls-server(\.exe)?$/.test(e.name));
    if (!wanted) throw new Error('anytls-server binary not found inside the release archive');

    fs.writeFileSync(dest, extractZipEntry(zipBuf, wanted));
    if (process.platform !== 'win32') fs.chmodSync(dest, 0o755);

    binaryDownloadState = 'ready';
    console.log(`[AnyTLS] Server binary ready at ${dest}`);
    return dest;
  } catch (err: any) {
    binaryDownloadState = 'failed';
    binaryDownloadError = err?.message || String(err);
    console.error(`[AnyTLS] Binary download failed: ${binaryDownloadError}`);
    return null;
  }
}

/**
 * Returns a usable anytls-server path, downloading the official release on first
 * use when the container image did not bake one in.
 */
async function ensureAnyTlsBinary(): Promise<string | null> {
  const existing = findSystemBinary();
  if (existing) {
    binaryDownloadState = 'ready';
    return existing;
  }

  if (process.env.ANYTLS_AUTO_DOWNLOAD === 'false') return null;

  if (!binaryEnsurePromise) {
    binaryEnsurePromise = downloadAnyTlsBinary().finally(() => {
      binaryEnsurePromise = null;
    });
  }
  return binaryEnsurePromise;
}

// ==============================================================================
// Tunnel process manager
// ==============================================================================

const START_COOLDOWN_MS = 4000;
const MAX_LOG_LINES = 200;

function addProcessLog(configId: string, message: string): void {
  const info = activeProcesses.get(configId);
  if (!info) return;
  const timestamp = new Date().toLocaleTimeString();
  info.logs.push(`[${timestamp}] ${message}`);
  if (info.logs.length > MAX_LOG_LINES) info.logs.shift();
}

function killPortOccupant(port: number): void {
  if (os.platform() !== 'linux' || !port) return;
  try {
    exec(`fuser -k ${port}/tcp 2>/dev/null || true`, () => {});
  } catch {
    // ignore
  }
}

function probePortListening(port: number): Promise<{ isListening: boolean; details: string }> {
  return new Promise((resolve) => {
    if (!port) {
      resolve({ isListening: false, details: 'No port assigned' });
      return;
    }
    const client = new net.Socket();
    client.setTimeout(500);
    const finish = (isListening: boolean, details: string) => {
      client.destroy();
      resolve({ isListening, details });
    };
    client.once('connect', () => finish(true, `TCP probe connected to 127.0.0.1:${port}`));
    client.once('timeout', () => finish(false, 'Connection timed out'));
    client.once('error', (e: Error) => finish(false, e.message));
    client.connect(port, '127.0.0.1');
  });
}

async function checkPortInListenState(
  port: number
): Promise<{ isListening: boolean; details: string }> {
  if (os.platform() !== 'linux') return probePortListening(port);

  return new Promise((resolve) => {
    exec(`ss -lntp 2>/dev/null | grep ":${port} " || true`, (err, stdout) => {
      const line = (stdout || '').trim();
      if (line) {
        resolve({ isListening: true, details: line });
      } else {
        // `ss` may be unavailable in slim images; fall back to a TCP probe.
        probePortListening(port).then(resolve);
      }
    });
  });
}

function stopAnyTlsServer(configId: string): void {
  const info = activeProcesses.get(configId);
  if (!info) return;

  if (info.process) {
    try {
      addProcessLog(configId, `Stopping process (PID: ${info.pid})...`);
      const proc = info.process;
      proc.kill('SIGTERM');
      setTimeout(() => {
        if (proc && !proc.killed && proc.exitCode === null) {
          try {
            proc.kill('SIGKILL');
          } catch {
            // ignore
          }
        }
      }, 1500);
    } catch (err: any) {
      console.error(`[AnyTLS] Error stopping process ${configId}:`, err);
    }
  }

  killPortOccupant(info.port);

  info.status = 'stopped';
  info.pid = undefined;
  info.process = undefined;
}

async function startAnyTlsServer(
  config: StoredConfig,
  options: { force?: boolean } = {}
): Promise<boolean> {
  const listenPort = config.port;
  if (!listenPort) {
    console.error(`[AnyTLS] Configuration ${config.id} has no internal port assigned`);
    return false;
  }

  let info = activeProcesses.get(config.id);

  // Already healthy on the requested port — nothing to do. A forced restart
  // deliberately skips this so the operator can always bounce the tunnel.
  if (
    !options.force &&
    info &&
    info.process &&
    info.process.exitCode === null &&
    info.status === 'running' &&
    info.port === listenPort
  ) {
    return true;
  }

  if (info && info.process) {
    stopAnyTlsServer(config.id);
    info = activeProcesses.get(config.id);
  }

  if (!info) {
    const created: ProcessInfo = {
      configId: config.id,
      remark: config.remark,
      port: listenPort,
      status: 'stopped',
      logs: [],
      lastStartAttempt: 0,
    };
    activeProcesses.set(config.id, created);
    info = created;
  }

  info.remark = config.remark;
  info.port = listenPort;

  const now = Date.now();
  // A forced restart must not be swallowed by the anti-flap cooldown.
  if (!options.force && now - info.lastStartAttempt < START_COOLDOWN_MS) {
    addProcessLog(config.id, 'Skipping restart: previous attempt was less than 4s ago.');
    return false;
  }
  info.lastStartAttempt = now;

  const binaryPath = await ensureAnyTlsBinary();
  if (!binaryPath) {
    info.status = 'failed';
    const warnMsg = binaryDownloadError
      ? `anytls-server binary unavailable: ${binaryDownloadError}`
      : 'anytls-server binary not found and automatic download is disabled.';
    addProcessLog(config.id, warnMsg);
    console.warn(`[AnyTLS] ${warnMsg} (Config: ${config.remark}, Port: ${listenPort})`);
    return false;
  }

  try {
    // Tunnels only need to be reachable from the local proxy, so bind loopback.
    const bindAddr = `127.0.0.1:${listenPort}`;

    addProcessLog(config.id, `Starting: ${binaryPath} -l ${bindAddr} -p ******`);
    console.log(`[AnyTLS] Spawning ${binaryPath} -l ${bindAddr} for "${config.remark}"`);

    const child = spawn(binaryPath, ['-l', bindAddr, '-p', config.password], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
      env: {
        ...process.env,
        LOG_LEVEL: process.env.ANYTLS_LOG_LEVEL || process.env.LOG_LEVEL || 'info',
      },
    });

    info.process = child;
    info.pid = child.pid;
    info.status = 'running';
    info.startedAt = new Date().toISOString();

    addProcessLog(
      config.id,
      `Process started successfully (PID: ${child.pid}) listening on ${bindAddr}`
    );

    setTimeout(async () => {
      const current = activeProcesses.get(config.id);
      if (!current || current.process !== child) return;
      const check = await checkPortInListenState(listenPort);
      if (check.isListening) {
        addProcessLog(config.id, `Port ${listenPort} confirmed in LISTEN state: ${check.details}`);
      } else if (current.status === 'running') {
        addProcessLog(config.id, `Process PID ${child.pid} alive, waiting for port binding...`);
      }
    }, 800);

    child.stdout?.on('data', (data: Buffer) => {
      const msg = data.toString().trim();
      if (msg) {
        addProcessLog(config.id, msg);
        console.log(`[AnyTLS ${listenPort}] ${msg}`);
      }
    });

    child.stderr?.on('data', (data: Buffer) => {
      const msg = data.toString().trim();
      if (msg) {
        addProcessLog(config.id, msg);
        console.log(`[AnyTLS ${listenPort}] ${msg}`);
      }
    });

    child.on('error', (err: Error) => {
      if (info) info.status = 'failed';
      addProcessLog(config.id, `Process error: ${err.message}`);
      console.error(`[AnyTLS ${listenPort}] Process error:`, err);
    });

    child.on('exit', (code: number | null, signal: string | null) => {
      const current = activeProcesses.get(config.id);
      if (current && current.process === child) {
        current.status = 'stopped';
        current.pid = undefined;
        current.process = undefined;
        current.lastExit = { code, signal, at: new Date().toISOString() };
      }
      addProcessLog(
        config.id,
        `Process exited with code ${code ?? 'null'} signal ${signal ?? 'none'}`
      );
      console.log(`[AnyTLS ${listenPort}] Process exited with code ${code} signal ${signal}`);
    });

    return true;
  } catch (err: any) {
    info.status = 'failed';
    addProcessLog(config.id, `Failed to launch process: ${err.message}`);
    console.error(`[AnyTLS ${listenPort}] Failed to launch:`, err);
    return false;
  }
}

// ==============================================================================
// Public TCP proxy (the single Railway TCP proxy target)
// ==============================================================================

let tunnelProxy: net.Server | null = null;
let tunnelProxyListening = false;
let proxyRetries = 0;

/** Maximum number of automatic retries when the public port is still in use. */
const PROXY_MAX_RETRIES = 5;

function recordTraffic(configId: string, bytes: number): void {
  if (bytes <= 0) return;
  pendingBytes.set(configId, (pendingBytes.get(configId) || 0) + bytes);
}

/** Simple mutex to prevent concurrent writes to config.json. */
let saveLock = false;
const saveLockQueue: Array<() => void> = [];

function withSaveLock(fn: () => void): void {
  if (saveLock) {
    saveLockQueue.push(fn);
    return;
  }
  saveLock = true;
  try {
    fn();
  } finally {
    saveLock = false;
    const next = saveLockQueue.shift();
    if (next) setTimeout(next, 0);
  }
}

function flushTraffic(): void {
  if (pendingBytes.size === 0) return;
  withSaveLock(() => {
    const data = loadData();
    let changed = false;
    for (const cfg of data.configs) {
      const bytes = pendingBytes.get(cfg.id);
      if (bytes) {
        cfg.trafficUsedBytes += bytes;
        pendingBytes.delete(cfg.id);
        changed = true;
      }
    }
    if (changed) saveData(data);
  });
}

function startTunnelProxy(): void {
  if (tunnelProxy) return;

  tunnelProxy = net.createServer((client: net.Socket) => {
    const target = pickGatewayConfig(loadData());

    // Nothing is exposed yet: destroy quietly so the port still looks live.
    if (!target || !target.port) {
      client.destroy();
      return;
    }

    const upstream = net.connect(target.port, '127.0.0.1');
    let transferred = 0;
    let closed = false;

    const finish = () => {
      if (closed) return;
      closed = true;
      recordTraffic(target.id, transferred);
      client.destroy();
      upstream.destroy();
    };

    // The proxy must stay byte-transparent: count only, never modify.
    client.on('data', (chunk: Buffer) => {
      transferred += chunk.length;
    });
    upstream.on('data', (chunk: Buffer) => {
      transferred += chunk.length;
    });

    client.on('error', finish);
    upstream.on('error', finish);
    client.on('close', finish);
    upstream.on('close', finish);

    client.pipe(upstream);
    upstream.pipe(client);
  });

  tunnelProxy.on('error', (err: any) => {
    tunnelProxyListening = false;
    tunnelProxy = null;
    console.error(`[AnyTLS] Public TCP proxy failed on port ${GATEWAY_PORT}:`, err.message);

    if (err.code === 'EADDRINUSE' && proxyRetries < PROXY_MAX_RETRIES) {
      proxyRetries++;
      // Wait for the port to be released (e.g. a previous container draining).
      setTimeout(() => startTunnelProxy(), 3000);
      return;
    }

    if (err.code === 'EADDRINUSE') {
      console.error(
        `[AnyTLS] Giving up on port ${GATEWAY_PORT} after ${PROXY_MAX_RETRIES} attempts. ` +
          'Another process is using it — set ANYTLS_GATEWAY_PORT to a free port and make the ' +
          'Railway TCP Proxy target that port instead.'
      );
    }
  });

  tunnelProxy.listen(GATEWAY_PORT, '0.0.0.0', () => {
    tunnelProxyListening = true;
    proxyRetries = 0;
    console.log(`[AnyTLS] Public TCP proxy listening on 0.0.0.0:${GATEWAY_PORT}`);
  });
}

// ==============================================================================
// Reconciliation
// ==============================================================================

function pickGatewayConfig(data: AppData): StoredConfig | null {
  const stored = data.gateway?.activeConfigId;
  if (stored) {
    const found = data.configs.find((c) => c.id === stored && c.status === 'active');
    if (found) return found;
  }
  return data.configs.find((c) => c.status === 'active') || null;
}

/**
 * Brings running processes in line with config.json:
 *   * one anytls-server per ACTIVE configuration,
 *   * the public proxy pointed at the configuration marked "public".
 */
async function syncTunnels(data?: AppData): Promise<void> {
  const current = data || loadData();

  const activeIds = new Set(
    current.configs.filter((c) => c.status === 'active').map((c) => c.id)
  );

  // Stop anything that is no longer active, was removed, or moved port.
  for (const [id, info] of Array.from(activeProcesses.entries())) {
    const cfg = current.configs.find((c) => c.id === id);
    if (!activeIds.has(id) || !cfg || cfg.port !== info.port) {
      stopAnyTlsServer(id);
      activeProcesses.delete(id);
    }
  }

  const target = pickGatewayConfig(current);
  if (current.gateway && current.gateway.activeConfigId !== (target?.id ?? null)) {
    current.gateway.activeConfigId = target?.id ?? null;
    current.gateway.updatedAt = new Date().toISOString();
    saveData(current);
  }

  const binary = await ensureAnyTlsBinary();
  if (!binary) return;

  for (const cfg of current.configs) {
    if (cfg.status !== 'active') continue;
    const info = activeProcesses.get(cfg.id);
    const healthy =
      info &&
      info.process &&
      info.process.exitCode === null &&
      info.status === 'running' &&
      info.port === cfg.port;
    if (!healthy) await startAnyTlsServer(cfg);
  }

  startTunnelProxy();
}

/** Points the public port at a different configuration (instant, no restart). */
function activateGatewayConfig(config: StoredConfig, data: AppData): void {
  if (!data.gateway) {
    data.gateway = { activeConfigId: null, updatedAt: new Date().toISOString() };
  }
  data.gateway.activeConfigId = config.id;
  data.gateway.updatedAt = new Date().toISOString();
  saveData(data);
  console.log(`[AnyTLS] Public port now serves "${config.remark}" (${config.id})`);
}

// ==============================================================================
// Watchdog
// ==============================================================================

let watchdogTimer: NodeJS.Timeout | null = null;

function startProcessWatchdog(): void {
  if (watchdogTimer) return;

  watchdogTimer = setInterval(async () => {
    try {
      const data = loadData();
      const now = new Date();
      let changed = false;

      // 1. Expiration enforcement
      for (const cfg of data.configs) {
        const isTimeExpired = cfg.expireAt ? new Date(cfg.expireAt) < now : false;
        const isTrafficExpired =
          cfg.trafficLimitGB > 0 &&
          cfg.trafficUsedBytes >= cfg.trafficLimitGB * 1024 * 1024 * 1024;

        if ((isTimeExpired || isTrafficExpired) && cfg.status === 'active') {
          console.log(
            `[Watchdog] Config "${cfg.remark}" expired (time: ${isTimeExpired}, traffic: ${isTrafficExpired}).`
          );
          cfg.status = 'expired';
          stopAnyTlsServer(cfg.id);
          activeProcesses.delete(cfg.id);
          changed = true;
        }
      }

      // 2. Persist measured traffic
      flushTraffic();

      // 3. Reconcile processes and the public proxy target
      await syncTunnels(data);

      if (changed) saveData(data);
    } catch (err) {
      console.error('[Watchdog] Error during supervisor cycle:', err);
    }
  }, 15000);
}

function shutdown(): void {
  if (watchdogTimer) clearInterval(watchdogTimer);
  try {
    tunnelProxy?.close();
  } catch {
    // ignore
  }
  for (const id of Array.from(activeProcesses.keys())) {
    stopAnyTlsServer(id);
  }
}

process.on('SIGTERM', () => {
  console.log('[Panel] SIGTERM received, shutting down tunnels...');
  shutdown();
  setTimeout(() => process.exit(0), 500);
});

process.on('SIGINT', () => {
  console.log('[Panel] SIGINT received, shutting down tunnels...');
  shutdown();
  setTimeout(() => process.exit(0), 500);
});

// ==============================================================================
// HTTP API
// ==============================================================================

const activeTokens = new Set<string>();

async function startServer() {
  detectAutoIp();

  const app = express();
  loadData();

  app.disable('x-powered-by');
  app.set('trust proxy', true);
  app.use(express.json({ limit: '1mb' }));

  const requireAuth = (req: Request, res: Response, next: () => void) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Please sign in first' });
      return;
    }
    if (!activeTokens.has(authHeader.split(' ')[1])) {
      res.status(401).json({ error: 'Session expired' });
      return;
    }
    next();
  };

  function verifyPassword(data: AppData, password: string): boolean {
    if (!password) return false;
    // Only PBKDF2 is accepted. The legacy SHA-256 path was removed because it
    // allowed fast brute-force attacks. Passwords stored with SHA-256 were
    // already migrated to PBKDF2 on the first successful login (see loadData).
    return hashPassword(password, data.admin.salt) === data.admin.passwordHash;
  }

  // --------------------------------------------------
  // Health & deployment info (public)
  // --------------------------------------------------
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      ok: true,
      status: 'healthy',
      uptimeSeconds: Math.round(process.uptime()),
      publicPortListening: tunnelProxyListening,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/system-info', (req: Request, res: Response) => {
    const data = loadData();
    res.json({
      isStandalone: data.isStandalone !== false, // default true, but respect stored value
      serverIp: resolvePublicEndpoint(data).host,
      railway: isRailwayRuntime,
    });
  });

  app.get('/api/public-endpoint', (req: Request, res: Response) => {
    res.json({ publicEndpoint: resolvePublicEndpoint(loadData()) });
  });

  app.get('/api/railway/status', requireAuth, (req: Request, res: Response) => {
    const data = loadData();
    const gateway = pickGatewayConfig(data);
    res.json({
      onRailway: isRailwayRuntime,
      panelPort: PORT,
      gatewayPort: GATEWAY_PORT,
      publicPortListening: tunnelProxyListening,
      publicEndpoint: resolvePublicEndpoint(data),
      tcpProxyConfigured: Boolean(
        process.env.RAILWAY_TCP_PROXY_DOMAIN && process.env.RAILWAY_TCP_PROXY_PORT
      ),
      gateway: gateway
        ? { configId: gateway.id, remark: gateway.remark, internalPort: gateway.port }
        : null,
      runningTunnels: Array.from(activeProcesses.values())
        .filter((i) => i.status === 'running')
        .map((i) => ({ configId: i.configId, pid: i.pid, port: i.port })),
      binaryInstalled: Boolean(findSystemBinary()),
      binaryDownloadState,
      binaryDownloadError: binaryDownloadError || null,
      dataDir: DATA_DIR,
      version: ANYTLS_VERSION,
    });
  });

  // --------------------------------------------------
  // Simple in-memory rate limiter for the login endpoint
  // --------------------------------------------------
  const loginAttempts = new Map<string, { count: number; resetAt: number }>();
  const LOGIN_MAX_ATTEMPTS = 10;
  const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

  function checkLoginRateLimit(ip: string): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt <= now) {
      loginAttempts.set(ip, { count: 0, resetAt: now + LOGIN_WINDOW_MS });
      return { allowed: true, retryAfterSec: 0 };
    }
    if (entry.count >= LOGIN_MAX_ATTEMPTS) {
      return { allowed: false, retryAfterSec: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  function recordFailedLogin(ip: string): void {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt <= now) {
      loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    } else {
      entry.count++;
    }
  }

  function clearLoginAttempts(ip: string): void {
    loginAttempts.delete(ip);
  }

  // --------------------------------------------------
  // Auth
  // --------------------------------------------------
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body || {};
    const clientIp = (req.ip || req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');

    // Rate-limit check before touching any data.
    const rateCheck = checkLoginRateLimit(clientIp);
    if (!rateCheck.allowed) {
      res.status(429).json({
        error: `Too many failed login attempts. Try again in ${Math.ceil(rateCheck.retryAfterSec / 60)} minute(s).`,
      });
      return;
    }

    const data = loadData();

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    if (username !== data.admin.username) {
      recordFailedLogin(clientIp);
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    let isAuthenticated = verifyPassword(data, password);

    // Upgrade a legacy plain-text password on first successful login.
    if (!isAuthenticated && (data.admin as any).password === password) {
      isAuthenticated = true;
      delete (data.admin as any).password;
      const newSalt = crypto.randomBytes(16).toString('hex');
      data.admin.salt = newSalt;
      data.admin.passwordHash = hashPassword(password, newSalt);
      saveData(data);
    }

    if (!isAuthenticated) {
      recordFailedLogin(clientIp);
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    clearLoginAttempts(clientIp);
    const token = crypto.randomBytes(32).toString('hex');
    activeTokens.add(token);

    res.json({ success: true, token, username: data.admin.username });
  });

  app.get('/api/auth/me', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (
      !authHeader ||
      !authHeader.startsWith('Bearer ') ||
      !activeTokens.has(authHeader.split(' ')[1])
    ) {
      res.status(401).json({ isLoggedIn: false });
      return;
    }
    const data = loadData();
    res.json({
      isLoggedIn: true,
      username: data.admin.username,
      panelPort: resolvePublicEndpoint(data).port,
    });
  });

  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      activeTokens.delete(authHeader.split(' ')[1]);
    }
    res.json({ success: true });
  });

  app.post('/api/auth/change-password', requireAuth, (req: Request, res: Response) => {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: 'Current password and new password are required' });
      return;
    }
    if (String(newPassword).length < 6) {
      res.status(400).json({ error: 'New password must be at least 6 characters' });
      return;
    }

    const data = loadData();
    if (!verifyPassword(data, currentPassword)) {
      res.status(400).json({ error: 'Incorrect current password' });
      return;
    }

    const newSalt = crypto.randomBytes(16).toString('hex');
    data.admin.salt = newSalt;
    data.admin.passwordHash = hashPassword(newPassword, newSalt);
    saveData(data);

    res.json({ success: true, message: 'Password changed successfully' });
  });

  // --------------------------------------------------
  // Settings: admin password + public endpoint override
  // --------------------------------------------------
  app.post('/api/settings/update', requireAuth, (req: Request, res: Response) => {
    const { currentPassword, newPassword, newPort, host, port } = req.body || {};
    const data = loadData();

    if (!currentPassword) {
      res.status(400).json({ error: 'Current password is required to save changes' });
      return;
    }
    if (!verifyPassword(data, currentPassword)) {
      res.status(400).json({ error: 'Incorrect current password' });
      return;
    }

    let passwordChanged = false;
    if (newPassword && String(newPassword).trim() !== '') {
      if (String(newPassword).length < 6) {
        res.status(400).json({ error: 'New password must be at least 6 characters' });
        return;
      }
      const newSalt = crypto.randomBytes(16).toString('hex');
      data.admin.salt = newSalt;
      data.admin.passwordHash = hashPassword(newPassword, newSalt);
      passwordChanged = true;
    }

    let endpointChanged = false;

    if (host !== undefined) {
      const cleanHost = String(host).trim();
      if (cleanHost !== data.serverIp) {
        data.serverIp = cleanHost;
        endpointChanged = true;
      }
      // Clearing the host also clears the manual port override.
      if (!cleanHost && data.panelPort !== 0) {
        data.panelPort = 0;
        endpointChanged = true;
      }
    }

    // `newPort` is kept for backward compatibility with the original panel UI.
    const requestedPort = port ?? newPort;
    if (requestedPort !== undefined && requestedPort !== null && requestedPort !== '') {
      const parsedPort = parseInt(String(requestedPort), 10);
      if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        res.status(400).json({ error: 'Public port must be a number between 1 and 65535' });
        return;
      }
      if (parsedPort !== data.panelPort) {
        data.panelPort = parsedPort;
        endpointChanged = true;
      }
    }

    saveData(data);
    const endpoint = resolvePublicEndpoint(data);

    res.json({
      success: true,
      passwordChanged,
      portChanged: endpointChanged,
      newPort: endpoint.port,
      publicEndpoint: endpoint,
      message: endpointChanged
        ? `Settings saved. Public endpoint is now ${endpoint.host}:${endpoint.port}.`
        : 'Settings saved successfully.',
    });
  });

  // --------------------------------------------------
  // Configurations
  // --------------------------------------------------
  app.get('/api/configs', requireAuth, (req: Request, res: Response) => {
    const data = loadData();
    const now = new Date();
    let hasChanges = false;

    data.configs = data.configs.map((cfg) => {
      const isTimeExpired = cfg.expireAt ? new Date(cfg.expireAt) < now : false;
      const isTrafficExpired =
        cfg.trafficLimitGB > 0 && cfg.trafficUsedBytes >= cfg.trafficLimitGB * 1024 * 1024 * 1024;
      if ((isTimeExpired || isTrafficExpired) && cfg.status === 'active') {
        hasChanges = true;
        return { ...cfg, status: 'expired' as const };
      }
      return cfg;
    });

    if (hasChanges) saveData(data);

    const endpoint = resolvePublicEndpoint(data);
    const activeGatewayId = pickGatewayConfig(data)?.id ?? null;

    const configsWithProcess = data.configs.map((cfg) => {
      const proc = activeProcesses.get(cfg.id);
      return {
        ...cfg,
        processRunning: proc?.status === 'running' && Boolean(proc.process),
        processPid: proc?.pid,
        isGateway: cfg.id === activeGatewayId,
        listenPort: cfg.port,
        externalPort: endpoint.port,
      };
    });

    res.json({
      configs: configsWithProcess,
      serverIp: endpoint.host,
      publicEndpoint: endpoint,
      gatewayConfigId: activeGatewayId,
      publicPortListening: tunnelProxyListening,
      binaryInstalled: Boolean(findSystemBinary()),
      binaryDownloadState,
    });
  });

  app.post('/api/configs', requireAuth, async (req: Request, res: Response) => {
    const {
      remark,
      password,
      sni,
      trafficLimitGB = 0,
      expireDays = 30,
      notes = '',
      insecure = true,
    } = req.body || {};

    if (!remark || !String(remark).trim()) {
      res.status(400).json({ error: 'Remark is required' });
      return;
    }

    const data = loadData();
    const now = new Date();
    const daysNum = Number(expireDays);
    const expireAt =
      daysNum > 0 ? new Date(now.getTime() + daysNum * 24 * 60 * 60 * 1000).toISOString() : null;

    const finalPassword =
      password && String(password).trim()
        ? String(password).trim()
        : crypto.randomBytes(12).toString('base64url');

    const newConfig: StoredConfig = {
      id: 'cfg-' + crypto.randomBytes(6).toString('hex'),
      remark: String(remark).trim(),
      port: 0, // assigned by ensureInternalPorts below
      password: finalPassword,
      sni: typeof sni === 'string' ? sni.trim() : '',
      trafficLimitGB: Number(trafficLimitGB) || 0,
      trafficUsedBytes: 0,
      expireDays: daysNum,
      expireAt,
      createdAt: now.toISOString(),
      status: 'active',
      insecure: insecure !== false,
      notes: notes ? String(notes).trim() : '',
    };

    data.configs.unshift(newConfig);
    ensureInternalPorts(data);

    if (!data.gateway) {
      data.gateway = { activeConfigId: null, updatedAt: new Date().toISOString() };
    }
    if (!pickGatewayConfig(data)) {
      data.gateway.activeConfigId = newConfig.id;
    }
    saveData(data);

    await syncTunnels(loadData());

    const proc = activeProcesses.get(newConfig.id);
    const endpoint = resolvePublicEndpoint(loadData());
    res.json({
      success: true,
      config: {
        ...newConfig,
        processRunning: proc?.status === 'running',
        processPid: proc?.pid,
        isGateway: pickGatewayConfig(loadData())?.id === newConfig.id,
        listenPort: newConfig.port,
        externalPort: endpoint.port,
      },
      publicEndpoint: endpoint,
    });
  });

  app.put('/api/configs/:id', requireAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { remark, password, sni, trafficLimitGB, expireDays, notes, insecure } = req.body || {};

    const data = loadData();
    const current = data.configs.find((c) => c.id === id);
    if (!current) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    if (remark) current.remark = String(remark).trim();
    if (password) current.password = String(password).trim();
    if (sni !== undefined) current.sni = typeof sni === 'string' ? sni.trim() : '';
    if (notes !== undefined) current.notes = String(notes).trim();
    if (insecure !== undefined) current.insecure = Boolean(insecure);
    if (trafficLimitGB !== undefined) current.trafficLimitGB = Number(trafficLimitGB);

    if (expireDays !== undefined) {
      const daysNum = Number(expireDays);
      current.expireDays = daysNum;
      if (daysNum > 0) {
        const createdTime = new Date(current.createdAt).getTime();
        current.expireAt = new Date(createdTime + daysNum * 24 * 60 * 60 * 1000).toISOString();
      } else {
        current.expireAt = null;
      }
    }

    saveData(data);
    await syncTunnels(loadData());

    const proc = activeProcesses.get(current.id);
    res.json({
      success: true,
      config: {
        ...current,
        processRunning: proc?.status === 'running',
        processPid: proc?.pid,
        isGateway: pickGatewayConfig(loadData())?.id === current.id,
        listenPort: current.port,
        externalPort: resolvePublicEndpoint(loadData()).port,
      },
    });
  });

  app.post('/api/configs/:id/toggle', requireAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const data = loadData();
    const config = data.configs.find((c) => c.id === id);
    if (!config) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    if (config.status === 'active') {
      config.status = 'disabled';
      stopAnyTlsServer(config.id);
      activeProcesses.delete(config.id);
      if (data.gateway?.activeConfigId === id) data.gateway.activeConfigId = null;
    } else {
      config.status = 'active';
      if (!data.gateway) {
        data.gateway = { activeConfigId: null, updatedAt: new Date().toISOString() };
      }
      if (!pickGatewayConfig(data)) data.gateway.activeConfigId = config.id;
    }

    saveData(data);
    await syncTunnels(loadData());

    res.json({ success: true, status: config.status });
  });

  app.post('/api/configs/:id/activate', requireAuth, (req: Request, res: Response) => {
    const { id } = req.params;
    const data = loadData();
    const config = data.configs.find((c) => c.id === id);
    if (!config) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    if (config.status !== 'active') {
      config.status = 'active';
      saveData(data);
    }

    activateGatewayConfig(config, loadData());
    syncTunnels(loadData()).catch((err) => console.error('[AnyTLS] Resync failed:', err));

    res.json({
      success: true,
      gatewayConfigId: config.id,
      publicEndpoint: resolvePublicEndpoint(loadData()),
    });
  });

  app.post('/api/configs/:id/renew', requireAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { addDays = 30, addTrafficGB = 0, resetTraffic = false } = req.body || {};

    const data = loadData();
    const config = data.configs.find((c) => c.id === id);
    if (!config) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    const daysToAdd = Number(addDays) || 0;
    if (daysToAdd > 0) {
      const baseTime =
        config.expireAt && new Date(config.expireAt) > new Date()
          ? new Date(config.expireAt).getTime()
          : Date.now();
      config.expireAt = new Date(baseTime + daysToAdd * 24 * 60 * 60 * 1000).toISOString();
      config.expireDays += daysToAdd;
    }

    const trafficToAdd = Number(addTrafficGB) || 0;
    if (trafficToAdd > 0 && config.trafficLimitGB > 0) {
      config.trafficLimitGB += trafficToAdd;
    }

    if (resetTraffic) {
      config.trafficUsedBytes = 0;
      // Also discard any in-flight bytes not yet flushed to disk so they
      // are not re-added after the reset.
      pendingBytes.delete(id);
    }

    config.status = 'active';
    saveData(data);
    await syncTunnels(loadData());

    res.json({ success: true, config });
  });

  app.delete('/api/configs/:id', requireAuth, (req: Request, res: Response) => {
    const { id } = req.params;
    const data = loadData();
    if (!data.configs.some((c) => c.id === id)) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    data.configs = data.configs.filter((c) => c.id !== id);
    if (data.gateway?.activeConfigId === id) data.gateway.activeConfigId = null;

    stopAnyTlsServer(id);
    activeProcesses.delete(id);
    ensureInternalPorts(data);

    if (data.gateway && !pickGatewayConfig(data)) {
      data.gateway.activeConfigId = null;
    }

    saveData(data);
    syncTunnels(loadData()).catch((err) => console.error('[AnyTLS] Resync failed:', err));

    res.json({ success: true, message: 'Configuration deleted successfully' });
  });

  // --------------------------------------------------
  // Process details & diagnostics
  // --------------------------------------------------
  app.get('/api/configs/:id/process', requireAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const binaryPath = findSystemBinary();
    const info = activeProcesses.get(id);
    const data = loadData();
    const config = data.configs.find((c) => c.id === id);
    const targetPort = config?.port || info?.port || 0;

    const portCheck = await checkPortInListenState(targetPort);
    const endpoint = resolvePublicEndpoint(data);

    res.json({
      binaryPath,
      binaryExists: Boolean(binaryPath),
      binaryDownloadState,
      binaryDownloadError: binaryDownloadError || null,
      status: info?.status || (config?.status === 'active' ? 'stopped' : 'disabled'),
      pid: info?.pid,
      port: targetPort,
      listenPort: targetPort,
      isGateway: pickGatewayConfig(data)?.id === id,
      publicHost: endpoint.host,
      publicPort: endpoint.port,
      gatewayPort: GATEWAY_PORT,
      publicPortListening: tunnelProxyListening,
      isListening: portCheck.isListening,
      listenDetails: portCheck.details,
      startedAt: info?.startedAt,
      logs: info?.logs || [],
    });
  });

  app.post('/api/configs/:id/restart-process', requireAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const data = loadData();
    const config = data.configs.find((c) => c.id === id);
    if (!config) {
      res.status(404).json({ error: 'Configuration not found' });
      return;
    }

    if (config.status !== 'active') {
      config.status = 'active';
      saveData(data);
    }

    const success = await startAnyTlsServer(config, { force: true });
    const proc = activeProcesses.get(id);

    res.json({
      success,
      status: proc?.status || 'stopped',
      pid: proc?.pid,
      isGateway: pickGatewayConfig(loadData())?.id === id,
    });
  });

  // --------------------------------------------------
  // Server status
  // --------------------------------------------------
  app.get('/api/server/status', requireAuth, (req: Request, res: Response) => {
    const data = loadData();
    const totalMem = os.totalmem();
    const usedMem = totalMem - os.freemem();
    const endpoint = resolvePublicEndpoint(data);

    const runningTunnels = Array.from(activeProcesses.values()).filter(
      (i) => i.status === 'running' && i.process
    ).length;

    res.json({
      cpuUsage: Math.round((os.loadavg()[0] || 0) * 10) / 10,
      memoryUsedMB: Math.round(usedMem / 1024 / 1024),
      memoryTotalMB: Math.round(totalMem / 1024 / 1024),
      uptimeSeconds: Math.round(os.uptime()),
      processUptimeSeconds: Math.round(process.uptime()),
      serverIp: endpoint.host,
      panelPort: endpoint.port,
      publicEndpoint: endpoint,
      gatewayPort: GATEWAY_PORT,
      gatewayConfigId: pickGatewayConfig(data)?.id ?? null,
      gatewayRunning: tunnelProxyListening,
      runningTunnels,
      anytlsInstalled: Boolean(findSystemBinary()),
      anytlsVersion: `${ANYTLS_VERSION} (anytls-go)`,
      activeConfigsCount: data.configs.filter((c) => c.status === 'active').length,
      totalConfigsCount: data.configs.length,
      osInfo: `${os.type()} ${os.release()} (${os.arch()})`,
      isStandalone: true,
      onRailway: isRailwayRuntime,
      binaryDownloadState,
    });
  });

  // --------------------------------------------------
  // Maintenance
  // --------------------------------------------------
  app.post('/api/maintenance/install-binary', requireAuth, async (req: Request, res: Response) => {
    binaryEnsurePromise = null;
    const binaryPath = await ensureAnyTlsBinary();
    await syncTunnels(loadData());
    res.json({
      success: Boolean(binaryPath),
      binaryPath,
      binaryDownloadState,
      binaryDownloadError: binaryDownloadError || null,
    });
  });

  // --------------------------------------------------
  // Legacy Ubuntu one-click package
  // --------------------------------------------------
  app.get('/api/download-zip', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="anytls-panel-ubuntu.zip"');

    const archive = createZipArchive({ zlib: { level: 9 } });

    archive.on('error', (err: Error) => {
      console.error('Archiver error:', err);
      if (!res.headersSent) res.status(500).send({ error: err.message });
    });

    archive.pipe(res);

    const projectRoot = process.cwd();
    const filesToInclude = [
      'install.sh',
      'package.json',
      'tsconfig.json',
      'vite.config.ts',
      'index.html',
      'server.ts',
      'metadata.json',
      '.env.example',
      '.gitignore',
      'README.md',
    ];

    for (const file of filesToInclude) {
      const filePath = path.join(projectRoot, file);
      if (fs.existsSync(filePath)) archive.file(filePath, { name: file });
    }

    for (const dir of ['bin', 'src', 'public', 'scripts']) {
      const dirPath = path.join(projectRoot, dir);
      if (fs.existsSync(dirPath)) archive.directory(dirPath, dir);
    }

    archive.append('STANDALONE_PANEL=true\nVITE_STANDALONE=true\n', { name: '.env' });
    archive.finalize();
  });

  app.get('/api/install.sh', (req: Request, res: Response) => {
    const installScriptPath = path.join(process.cwd(), 'install.sh');
    if (fs.existsSync(installScriptPath)) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(fs.readFileSync(installScriptPath, 'utf-8'));
    } else {
      res.status(404).send('# install.sh not found');
    }
  });

  // --------------------------------------------------
  // Static assets
  //
  // The panel always runs as a standalone production server; the legacy
  // dev-only Vite middleware branch was removed so a Railway deployment can never
  // boot in an unbuilt state.
  // --------------------------------------------------
  const distPath = path.join(process.cwd(), 'dist');
  if (!fs.existsSync(path.join(distPath, 'index.html'))) {
    console.error(
      `[Panel] WARNING: ${path.join(distPath, 'index.html')} was not found. ` +
        'Run "npm run build" before "npm start".'
    );
  }

  app.use(express.static(distPath, { index: false, maxAge: '1h' }));
  app.get('*', (req: Request, res: Response) => {
    if (req.path.startsWith('/api/')) {
      res.status(404).json({ error: 'Not found' });
      return;
    }
    res.sendFile(path.join(distPath, 'index.html'));
  });

  // Error handler: a rejected request must never take the container down.
  app.use((err: any, req: Request, res: Response, next: () => void) => {
    console.error('[Panel] Unhandled request error:', err);
    if (res.headersSent) {
      next();
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  });

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('==============================================================');
    console.log('  AnyTLS Manager Panel');
    console.log('==============================================================');
    console.log(`  Web panel    : http://0.0.0.0:${PORT}`);
    console.log(`  Public tunnel: 0.0.0.0:${GATEWAY_PORT}  <- Railway TCP proxy target`);
    console.log(`  Data dir     : ${DATA_DIR}`);
    console.log(`  Railway mode : ${isRailwayRuntime ? 'yes' : 'no'}`);
    console.log('==============================================================');

    // Bind the public port immediately so the platform can detect and route it.
    startTunnelProxy();

    ensureAnyTlsBinary()
      .then(() => syncTunnels(loadData()))
      .then(() => {
        const endpoint = resolvePublicEndpoint(loadData());
        console.log(`  Public endpoint: ${endpoint.host}:${endpoint.port} (${endpoint.source})`);
      })
      .then(() => startProcessWatchdog())
      .catch((err) => console.error('Failed to initialize AnyTLS tunnels:', err));
  });

  server.on('error', (err) => {
    console.error('[Panel] HTTP server error:', err);
  });

  // Keep the panel alive on unexpected rejections (Railway restarts otherwise).
  process.on('unhandledRejection', (reason) => {
    console.error('[Panel] Unhandled promise rejection:', reason);
  });
  process.on('uncaughtException', (err) => {
    console.error('[Panel] Uncaught exception:', err);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});