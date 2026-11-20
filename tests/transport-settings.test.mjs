import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseTransportSettings } from '../build/transport-settings.js';

test('stdio is default and has no HTTP listener', () => {
  assert.deepEqual(parseTransportSettings({}), { mode: 'stdio', host: '127.0.0.1', port: 3000 });
  assert.throws(() => parseTransportSettings({ SSH_MCP_HTTP_PORT: '3000' }), /require/);
});
test('HTTP mode defaults to loopback only', () => {
  assert.deepEqual(parseTransportSettings({ SSH_MCP_TRANSPORT: 'http' }), { mode: 'http', host: '127.0.0.1', port: 3000 });
  assert.deepEqual(parseTransportSettings({ SSH_MCP_TRANSPORT: 'http', SSH_MCP_HTTP_HOST: '::1', SSH_MCP_HTTP_PORT: '443' }), { mode: 'http', host: '::1', port: 443 });
});
test('HTTP mode rejects public binding and malformed ports', () => {
  for (const host of ['0.0.0.0', '::', '192.168.1.2', 'example.com']) {
    assert.throws(() => parseTransportSettings({ SSH_MCP_TRANSPORT: 'http', SSH_MCP_HTTP_HOST: host }), /loopback/);
  }
  for (const port of ['0', '65536', '-1', '3000.5', 'NaN', '']) {
    assert.throws(() => parseTransportSettings({ SSH_MCP_TRANSPORT: 'http', SSH_MCP_HTTP_PORT: port }), /port/i);
  }
  assert.throws(() => parseTransportSettings({ SSH_MCP_TRANSPORT: 'websocket' }), /stdio or http/);
});
