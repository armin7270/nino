import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp, loadData, shutdown } from '../server.js';

let server: http.Server;
let baseUrl = '';

test.before(async () => {
  process.env.NODE_ENV = 'test';
  const app = createApp();
  await new Promise<void>((resolve) => {
    server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (typeof address === 'object' && address) {
        baseUrl = `http://127.0.0.1:${address.port}`;
      }
      resolve();
    });
  });
});

test.after(async () => {
  shutdown();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
});

test('GET /api/health returns healthy status and security headers', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');

  const body: any = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.status, 'healthy');
  assert.equal(typeof body.uptimeSeconds, 'number');
});

test('GET /api/system-info and /api/public-endpoint return valid data', async () => {
  const resInfo = await fetch(`${baseUrl}/api/system-info`);
  assert.equal(resInfo.status, 200);
  const info: any = await resInfo.json();
  assert.equal(typeof info.isStandalone, 'boolean');

  const resEndpoint = await fetch(`${baseUrl}/api/public-endpoint`);
  assert.equal(resEndpoint.status, 200);
  const endpoint: any = await resEndpoint.json();
  assert.ok(endpoint.publicEndpoint);
  assert.equal(typeof endpoint.publicEndpoint.port, 'number');
});

test('Authentication flow: login, me, logout, and token protection', async () => {
  // 1. Unauthorized /api/auth/me
  const unauthRes = await fetch(`${baseUrl}/api/auth/me`);
  assert.equal(unauthRes.status, 401);

  // 2. Bad credentials
  const badLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'wrongpassword' }),
  });
  assert.equal(badLoginRes.status, 401);

  // 3. Successful login
  const data = loadData();
  const currentUsername = data.admin.username;

  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: currentUsername, password: 'admin123' }),
  });
  assert.equal(loginRes.status, 200);
  const loginBody: any = await loginRes.json();
  assert.equal(loginBody.success, true);
  assert.ok(loginBody.token);
  const token = loginBody.token;

  // 4. Authorized /api/auth/me
  const meRes = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(meRes.status, 200);
  const meBody: any = await meRes.json();
  assert.equal(meBody.isLoggedIn, true);
  assert.equal(meBody.username, currentUsername);

  // 5. Logout
  const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(logoutRes.status, 200);

  // 6. Token is invalidated after logout
  const afterLogout = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(afterLogout.status, 401);
});

test('Configuration CRUD lifecycle', async () => {
  const data = loadData();
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: data.admin.username, password: 'admin123' }),
  });
  const { token }: any = await loginRes.json();
  const authHeaders = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  };

  // 1. Validation check on create
  const emptyRemarkRes = await fetch(`${baseUrl}/api/configs`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ remark: '' }),
  });
  assert.equal(emptyRemarkRes.status, 400);

  // 2. Create valid config
  const createRes = await fetch(`${baseUrl}/api/configs`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      remark: 'Automated-Test-User',
      trafficLimitGB: 20,
      expireDays: 15,
      sni: 'speedtest.net',
      notes: 'Test configuration',
    }),
  });
  assert.equal(createRes.status, 200);
  const createBody: any = await createRes.json();
  assert.equal(createBody.success, true);
  const config = createBody.config;
  assert.equal(config.remark, 'Automated-Test-User');
  assert.equal(config.trafficLimitGB, 20);
  assert.ok(config.port > 0);

  // 3. Update config
  const updateRes = await fetch(`${baseUrl}/api/configs/${config.id}`, {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify({
      remark: 'Updated-Test-User',
      trafficLimitGB: 40,
    }),
  });
  assert.equal(updateRes.status, 200);
  const updateBody: any = await updateRes.json();
  assert.equal(updateBody.config.remark, 'Updated-Test-User');
  assert.equal(updateBody.config.trafficLimitGB, 40);

  // 4. Toggle config status
  const toggleRes = await fetch(`${baseUrl}/api/configs/${config.id}/toggle`, {
    method: 'POST',
    headers: authHeaders,
  });
  assert.equal(toggleRes.status, 200);
  const toggleBody: any = await toggleRes.json();
  assert.equal(toggleBody.status, 'disabled');

  // 5. Renew config
  const renewRes = await fetch(`${baseUrl}/api/configs/${config.id}/renew`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      addDays: 30,
      addTrafficGB: 10,
      resetTraffic: true,
    }),
  });
  assert.equal(renewRes.status, 200);
  const renewBody: any = await renewRes.json();
  assert.equal(renewBody.config.status, 'active');
  assert.equal(renewBody.config.trafficLimitGB, 50);

  // 6. Delete config
  const deleteRes = await fetch(`${baseUrl}/api/configs/${config.id}`, {
    method: 'DELETE',
    headers: authHeaders,
  });
  assert.equal(deleteRes.status, 200);
  const deleteBody: any = await deleteRes.json();
  assert.equal(deleteBody.success, true);
});

test('Password change invalidates all existing active tokens', async () => {
  const data = loadData();
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: data.admin.username, password: 'admin123' }),
  });
  const { token }: any = await loginRes.json();

  // Change password to new password
  const changeRes = await fetch(`${baseUrl}/api/auth/change-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      currentPassword: 'admin123',
      newPassword: 'newAdminPassword123!',
    }),
  });
  assert.equal(changeRes.status, 200);

  // The old token should now be rejected
  const meWithOldToken = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(meWithOldToken.status, 401);

  // Reset password back to admin123 for test cleanliness
  const newLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: data.admin.username, password: 'newAdminPassword123!' }),
  });
  assert.equal(newLoginRes.status, 200);
  const { token: newToken }: any = await newLoginRes.json();

  await fetch(`${baseUrl}/api/auth/change-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${newToken}`,
    },
    body: JSON.stringify({
      currentPassword: 'newAdminPassword123!',
      newPassword: 'admin123',
    }),
  });
});
