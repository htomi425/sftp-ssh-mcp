#!/usr/bin/env node

import { createToolServer } from './tool-server.js';
import { parseTargets } from './ssh/targets.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { parseTransportSettings } from './transport-settings.js';
import { parseHttpAccessPolicy } from './http-access.js';
import { createAuthenticatedHttpServer, listenLoopback } from './http-server.js';
import { createStreamableHttpHandler } from './http-mcp.js';
import { createGatewayAssertionVerifier } from './gateway-assertion.js';
import { createInMemoryReplayCache } from './gateway-replay.js';
import { parseIdentityTargetPolicy } from './identity-target-policy.js';
import { createGatewayHttpAuthenticator } from './gateway-http-auth.js';

// 解析命令行参数
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string> = {};
  for (const arg of args) {
    const match = arg.match(/^--([^=]+)=(.*)$/);
    if (match) {
      config[match[1]] = match[2];
    }
  }
  return config;
}
const argvConfig = parseArgv();

const HOST = argvConfig.host;
const PORT = argvConfig.port === undefined ? 22 : Number(argvConfig.port);
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const KEY = argvConfig.key;

// 配置验证
function validateConfig(config: Record<string, string>) {
  const errors = [];
  if (!config.host) errors.push('Missing required --host');
  if (!config.user) errors.push('Missing required --user');
  if (config.port !== undefined && (!Number.isInteger(Number(config.port)) || Number(config.port) < 1 || Number(config.port) > 65535)) errors.push('Invalid --port (1-65535)');
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (!process.env.SSH_MCP_TARGETS) validateConfig(argvConfig);
const targets = parseTargets(process.env.SSH_MCP_TARGETS, !process.env.SSH_MCP_TARGETS ? {
  host: HOST, port: PORT, user: USER, password: PASSWORD, key: KEY,
  hostKeySha256: process.env.SSH_HOST_KEY_SHA256 ?? '',
} : undefined);

// 启动 MCP 服务器
async function main() {
  const transportSettings = parseTransportSettings(process.env);
  if (transportSettings.mode === 'http') {
    // Explicit opt-in only. This static-token mode is NOT an OAuth implementation.
    // Loopback-only; use a trusted reverse proxy with TLS and strict access controls.
    const authMode = process.env.SSH_MCP_HTTP_AUTH_MODE ?? 'static';
    if (!['static', 'gateway'].includes(authMode)) throw new Error('Invalid SSH_MCP_HTTP_AUTH_MODE');
    const policy = authMode === 'gateway'
      ? createGatewayHttpAuthenticator(
          createGatewayAssertionVerifier({
            issuer: process.env.SSH_MCP_GATEWAY_ISSUER ?? '',
            audience: process.env.SSH_MCP_GATEWAY_AUDIENCE ?? '',
            publicKeyPem: process.env.SSH_MCP_GATEWAY_PUBLIC_KEY_PEM ?? '',
          }),
          createInMemoryReplayCache(),
          parseIdentityTargetPolicy(process.env.SSH_MCP_IDENTITY_TARGETS, new Set(Object.keys(targets))),
        )
      : parseHttpAccessPolicy(process.env.SSH_MCP_HTTP_CREDENTIALS, new Set(Object.keys(targets)));
    const handler = createStreamableHttpHandler(principal => createToolServer(targets, { principal }, 'http'));
    const http = createAuthenticatedHttpServer(policy, handler);
    const address = await listenLoopback(http, transportSettings.host, transportSettings.port);
    console.error(`SSH MCP Streamable HTTP listening on ${address.address}:${address.port} (auth: ${authMode}, not OAuth)`);
    return;
  }
  const server = createToolServer(targets, {}, 'stdio');
  // 比较简单的启动方式，直接连接到 stdio
  const transport = new StdioServerTransport();
  // 监听 stdio 输入，处理 MCP 请求
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");
}

// 启动服务器，处理错误
main().catch((error) => {
  // 处理启动过程中的错误
  console.error("Fatal error in main():", error);
  process.exit(1);
});