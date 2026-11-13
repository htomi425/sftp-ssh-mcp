#!/usr/bin/env node

import { createToolServer } from './tool-server.js';
import { parseTargets } from './ssh/targets.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { parseTransportSettings } from './transport-settings.js';

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
const server = createToolServer(targets, {}, 'stdio');

// 启动 MCP 服务器
async function main() {
  const transportSettings = parseTransportSettings(process.env);
  if (transportSettings.mode !== 'stdio') {
    throw new Error('HTTP transport is not enabled yet; refusing to start an unauthenticated listener');
  }
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