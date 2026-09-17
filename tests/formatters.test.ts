import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatBytes,
  getDaysRemaining,
  generateAnyTlsLink,
  generateSingBoxJson,
  generateClashYaml,
  generateRandomPassword,
  getPublicPort,
  formatDate,
  formatDateToPersian,
} from '../src/lib/formatters.js';
import { AnyTlsConfig } from '../src/types.js';

const mockConfig: AnyTlsConfig = {
  id: 'cfg-test1',
  remark: 'Test User 1',
  port: 20100,
  password: 'secretPassword123',
  sni: 'cloudflare.com',
  trafficLimitGB: 50,
  trafficUsedBytes: 1073741824, // 1 GB
  expireDays: 30,
  expireAt: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(),
  createdAt: new Date().toISOString(),
  status: 'active',
  insecure: true,
  notes: 'Testing notes',
  listenPort: 20100,
  externalPort: 8443,
  isGateway: true,
};

test('formatBytes formats zero and various binary sizes', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1024), '1 KB');
  assert.equal(formatBytes(1048576), '1 MB');
  assert.equal(formatBytes(1073741824), '1 GB');
});

test('getPublicPort prioritizes externalPort over internal port', () => {
  assert.equal(getPublicPort(mockConfig), 8443);
  const withoutExternal = { ...mockConfig, externalPort: undefined };
  assert.equal(getPublicPort(withoutExternal), 20100);
});

test('getDaysRemaining handles null, future, and past dates', () => {
  assert.deepEqual(getDaysRemaining(null), { days: 9999, isExpired: false, text: 'Unlimited' });

  const future10Days = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000 + 1000).toISOString();
  const res10 = getDaysRemaining(future10Days);
  assert.equal(res10.isExpired, false);
  assert.match(res10.text, /1[01]d remaining/);

  const pastDate = new Date(Date.now() - 10000).toISOString();
  const resPast = getDaysRemaining(pastDate);
  assert.equal(resPast.isExpired, true);
  assert.equal(resPast.text, 'Expired');
});

test('generateAnyTlsLink generates valid standard AnyTLS URI', () => {
  const link = generateAnyTlsLink(mockConfig, '1.2.3.4');
  assert.match(link, /^anytls:\/\/secretPassword123@1\.2\.3\.4:8443/);
  assert.match(link, /sni=cloudflare\.com/);
  assert.match(link, /insecure=1/);
  assert.match(link, /#Test%20User%201/);
});

test('generateSingBoxJson produces valid JSON with all required properties', () => {
  const jsonStr = generateSingBoxJson(mockConfig, '1.2.3.4');
  const parsed = JSON.parse(jsonStr);
  assert.equal(parsed.type, 'anytls');
  assert.equal(parsed.tag, 'Test User 1');
  assert.equal(parsed.server, '1.2.3.4');
  assert.equal(parsed.server_port, 8443);
  assert.equal(parsed.password, 'secretPassword123');
  assert.equal(parsed.tls.enabled, true);
  assert.equal(parsed.tls.server_name, 'cloudflare.com');
  assert.equal(parsed.tls.insecure, true);
});

test('generateClashYaml produces well-formed Clash proxy entry', () => {
  const yaml = generateClashYaml(mockConfig, '1.2.3.4');
  assert.match(yaml, /name: "Test User 1"/);
  assert.match(yaml, /type: anytls/);
  assert.match(yaml, /server: 1\.2\.3\.4/);
  assert.match(yaml, /port: 8443/);
  assert.match(yaml, /sni: cloudflare\.com/);
  assert.match(yaml, /skip-cert-verify: true/);
});

test('generateRandomPassword returns string of requested length', () => {
  const pwd14 = generateRandomPassword(14);
  assert.equal(pwd14.length, 14);
  const pwd32 = generateRandomPassword(32);
  assert.equal(pwd32.length, 32);
});

test('formatDate and formatDateToPersian format dates properly', () => {
  assert.equal(formatDate(null), 'Unlimited');
  assert.equal(formatDateToPersian(null), 'نامحدود');

  const testIso = '2026-09-17T02:11:59.248Z';
  const enFormatted = formatDate(testIso);
  assert.match(enFormatted, /2026/);

  const faFormatted = formatDateToPersian(testIso);
  // Persian Shamsi year for 2026 is 1405
  assert.match(faFormatted, /۱۴۰۵|شهریور/);
});
