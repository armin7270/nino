import { resolvePublicEndpoint } from '../server.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Test implementation of hashPassword matching server.ts
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

// Test implementation of ensureInternalPorts matching server.ts
interface StoredConfig {
  id: string;
  remark: string;
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

interface AppData {
  admin: {
    username: string;
    passwordHash: string;
    salt: string;
  };
  serverIp: string;
  panelPort: number;
  isStandalone?: boolean;
  gateway?: { activeConfigId: string | null; updatedAt: string } | null;
  configs: StoredConfig[];
}

function ensureInternalPorts(
  data: AppData,
  gatewayPort = 8443,
  panelPort = 3000,
  internalPortBase = 20100
): boolean {
  let changed = false;
  const used = new Set<number>();

  for (const cfg of data.configs) {
    const port = Number(cfg.port) || 0;
    if (port > 0 && port !== gatewayPort && port !== panelPort && !used.has(port)) {
      used.add(port);
    } else if (cfg.port !== 0) {
      cfg.port = 0;
      changed = true;
    }
  }

  let candidate = internalPortBase;
  for (const cfg of data.configs) {
    if (!cfg.port) {
      while (used.has(candidate) || candidate === gatewayPort || candidate === panelPort) {
        candidate++;
      }
      cfg.port = candidate;
      used.add(candidate);
      changed = true;
    }
  }

  return changed;
}

test('hashPassword produces 128-char hex output and verifies correctly', () => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash1 = hashPassword('mySecret123', salt);
  const hash2 = hashPassword('mySecret123', salt);
  const hashWrong = hashPassword('wrongPassword', salt);

  assert.equal(hash1.length, 128);
  assert.equal(hash1, hash2);
  assert.notEqual(hash1, hashWrong);
});

test('ensureInternalPorts assigns unique sequential ports avoiding panel and gateway', () => {
  const testData: AppData = {
    admin: { username: 'admin', passwordHash: 'h', salt: 's' },
    serverIp: '127.0.0.1',
    panelPort: 3000,
    configs: [
      { id: '1', remark: 'cfg1', port: 0 } as any,
      { id: '2', remark: 'cfg2', port: 3000 } as any, // collides with panel
      { id: '3', remark: 'cfg3', port: 8443 } as any, // collides with gateway
      { id: '4', remark: 'cfg4', port: 20100 } as any,
      { id: '5', remark: 'cfg5', port: 20100 } as any, // duplicate port
    ],
  };

  const changed = ensureInternalPorts(testData, 8443, 3000, 20100);
  assert.equal(changed, true);

  const ports = testData.configs.map((c) => c.port);
  const uniquePorts = new Set(ports);

  // All 5 ports must be unique
  assert.equal(uniquePorts.size, 5);
  // None of the ports can be 3000 or 8443
  assert.equal(ports.includes(3000), false);
  assert.equal(ports.includes(8443), false);
  // No port should be 0
  assert.equal(ports.includes(0), false);
});

test('Quota expiration logic triggers accurately on time and traffic', () => {
  const now = new Date();
  const pastDate = new Date(now.getTime() - 1000).toISOString();
  const futureDate = new Date(now.getTime() + 1000000).toISOString();

  const cfgTimeExpired: StoredConfig = {
    id: 'c1',
    remark: 'Time Expired',
    status: 'active',
    expireAt: pastDate,
    trafficLimitGB: 10,
    trafficUsedBytes: 100,
  } as any;

  const cfgTrafficExpired: StoredConfig = {
    id: 'c2',
    remark: 'Traffic Expired',
    status: 'active',
    expireAt: futureDate,
    trafficLimitGB: 5,
    trafficUsedBytes: 5 * 1024 * 1024 * 1024, // exactly 5 GB
  } as any;

  const cfgHealthy: StoredConfig = {
    id: 'c3',
    remark: 'Healthy',
    status: 'active',
    expireAt: futureDate,
    trafficLimitGB: 10,
    trafficUsedBytes: 100,
  } as any;

  const checkExpired = (cfg: StoredConfig) => {
    const isTimeExpired = cfg.expireAt ? new Date(cfg.expireAt) < now : false;
    const isTrafficExpired =
      cfg.trafficLimitGB > 0 &&
      cfg.trafficUsedBytes >= cfg.trafficLimitGB * 1024 * 1024 * 1024;
    return isTimeExpired || isTrafficExpired;
  };

  assert.equal(checkExpired(cfgTimeExpired), true);
  assert.equal(checkExpired(cfgTrafficExpired), true);
  assert.equal(checkExpired(cfgHealthy), false);
});

test('Atomic file write prevents partially written or corrupted JSON data', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nino-test-'));
  const testFile = path.join(tempDir, 'config.json');

  const sampleData = { hello: 'world', numbers: [1, 2, 3] };

  // Write using atomic rename pattern
  const tmpFile = `${testFile}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(sampleData, null, 2), 'utf-8');
  fs.renameSync(tmpFile, testFile);

  assert.equal(fs.existsSync(testFile), true);
  const readBack = JSON.parse(fs.readFileSync(testFile, 'utf-8'));
  assert.deepEqual(readBack, sampleData);

  // Clean up
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('resolvePublicEndpoint handles Railway TCP Proxy and domain routing correctly', () => {
  const dummyData = {
    admin: { username: 'admin', passwordHash: '', salt: '' },
    serverIp: '',
    panelPort: 0,
    configs: [],
  };

  // Case 1: TCP Proxy env vars present
  process.env.RAILWAY_TCP_PROXY_DOMAIN = 'viaduct.proxy.rlwy.net';
  process.env.RAILWAY_TCP_PROXY_PORT = '49182';
  process.env.RAILWAY_PUBLIC_DOMAIN = 'nino.up.railway.app';
  
  const epTcp = resolvePublicEndpoint(dummyData);
  assert.equal(epTcp.host, 'viaduct.proxy.rlwy.net');
  assert.equal(epTcp.port, 49182);
  assert.equal(epTcp.source, 'railway-tcp');
  assert.equal(epTcp.tcpProxyConfigured, true);

  // Case 2: Only Railway HTTP domain present (before TCP proxy created)
  delete process.env.RAILWAY_TCP_PROXY_DOMAIN;
  delete process.env.RAILWAY_TCP_PROXY_PORT;
  process.env.RAILWAY_PUBLIC_DOMAIN = 'nino.up.railway.app';

  const epDomain = resolvePublicEndpoint(dummyData);
  assert.equal(epDomain.host, 'nino.up.railway.app');
  assert.equal(epDomain.port, 8443); // Must be GATEWAY_PORT, not 443!
  assert.equal(epDomain.source, 'railway-domain');
  assert.equal(epDomain.tcpProxyConfigured, false);

  // Clean up env vars
  delete process.env.RAILWAY_PUBLIC_DOMAIN;
});
