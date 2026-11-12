#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode, CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient } from 'ssh2';
import { z } from 'zod';
import { formatCommandResult } from './ssh/command-result.js';
import { formatDirectoryListing } from './ssh/directory-listing.js';
import { validateConnectionOptions } from './ssh/connection-config.js';
import { createHostKeyVerifier } from './ssh/host-key.js';
import { DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES, OutputLimiter } from './ssh/exec-limits.js';
import { uploadFile, downloadFile } from './ssh/sftp-transfer.js';
import { ConnectionGate, parseBoundedInteger, DEFAULT_MAX_TRANSFER_BYTES, DEFAULT_TRANSFER_TIMEOUT_MS, DEFAULT_MAX_CONCURRENT_CONNECTIONS } from './ssh/resource-limits.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

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

validateConfig(argvConfig);
validateConnectionOptions({ host: HOST, username: USER, port: PORT, readyTimeout: 10000 });
const hostKeyFingerprint = process.env.SSH_HOST_KEY_SHA256;
if (!hostKeyFingerprint) throw new Error('SSH_HOST_KEY_SHA256 is required (SHA-256 host key digest in hex)');
const hostVerifier = createHostKeyVerifier(hostKeyFingerprint);
const transferOptions = {
  maxBytes: parseBoundedInteger(process.env.SSH_MCP_MAX_TRANSFER_BYTES, DEFAULT_MAX_TRANSFER_BYTES, 1024, 1024 * 1024 * 1024, 'SSH_MCP_MAX_TRANSFER_BYTES'),
  timeoutMs: parseBoundedInteger(process.env.SSH_MCP_TRANSFER_TIMEOUT_MS, DEFAULT_TRANSFER_TIMEOUT_MS, 1000, 600000, 'SSH_MCP_TRANSFER_TIMEOUT_MS'),
};
const connectionGate = new ConnectionGate(parseBoundedInteger(
  process.env.SSH_MCP_MAX_CONNECTIONS, DEFAULT_MAX_CONCURRENT_CONNECTIONS, 1, 16, 'SSH_MCP_MAX_CONNECTIONS',
));

// MCP 服务器实例化
const server = new McpServer({
  name: 'SSH MCP Server', // 服务器名称
  version: '1.0.5', // 服务器版本
  capabilities: { // 服务器能力
    resources: {}, // 资源能力
    tools: {}, // 工具能力
  },
});

// 实现 SFTP 上传工具
server.tool(
  "sftp_upload", // 工具名称
  "Upload a file to remote server via SFTP", // 工具描述
  { // 工具参数
    localPath: z.string().describe("Local file path to upload"),
    remotePath: z.string().describe("Remote path to save the file"),
  },
  async ({ localPath, remotePath }) => { // 工具实现
    try {
      const fs = await import('fs/promises');
      const sshConfig: any = {
        host: HOST,
        port: PORT,
        username: USER,
        readyTimeout: 10000,
        hostHash: 'sha256',
        hostVerifier,
      };
      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
      await execSftpCommand(sshConfig, 'upload', localPath, remotePath);
      return {
        content: [{ // 返回结果
          type: 'text', // 结果类型
          text: `File uploaded to ${remotePath}` // 结果文本
        }]
      };
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Upload failed: ${err?.message || err}`);
    }
  }
);

// 实现 SFTP 下载工具
server.tool(
  "sftp_download",
  "Download a file from remote server via SFTP",
  {
    remotePath: z.string().describe("Remote file path to download"),
    localPath: z.string().describe("Local path to save the file"),
  },
  async ({ remotePath, localPath }) => {
    try {
      const fs = await import('fs/promises');
  // 重新构建 sshConfig 对象以解决找不到名称的问题
  const sshConfig: any = {
    host: HOST,
    port: PORT,
    username: USER,
    readyTimeout: 10000,
        hostHash: 'sha256',
        hostVerifier,
  };
  if (PASSWORD) {
    sshConfig.password = PASSWORD;
  } else if (KEY) {
    const fs = await import('fs/promises');
    sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
  }
  await execSftpCommand(sshConfig, 'download', remotePath, localPath);
      return { content: [{ type: 'text', text: `File downloaded to ${localPath}` }] };
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Download failed: ${err?.message || err}`);
    }
  }
);

// 实现 SFTP 列表工具
server.tool(
  "sftp_list",
  "List files in a remote directory via SFTP",
  {
    remotePath: z.string().describe("Remote directory path to list"),
  },
  async ({ remotePath }) => {
    try {
      const sshConfig: any = {
        host: HOST,
        port: PORT,
        username: USER,
        readyTimeout: 10000,
        hostHash: 'sha256',
        hostVerifier,
      };
      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
      const list = await execSftpCommand(sshConfig, 'list', remotePath) as { filename: string, longname: string }[];
      return {
        content: [{
          type: 'text',
          text: formatDirectoryListing(list)
        }]
      };
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `List failed: ${err?.message || err}`);
    }
  }
);

// 执行 SFTP 命令
async function execSftpCommand(sshConfig: any, action: string, ...args: any[]) {
  return new Promise((resolve, reject) => {
    let release: () => void;
    try { release = connectionGate.acquire(); } catch (error) { reject(error); return; }
    const conn = new SSHClient();
    conn.once('close', release);
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) {
          reject(new McpError(ErrorCode.InternalError, `SFTP error: ${err.message}`));
          conn.end();
          return;
        }

        switch (action) {
          case 'upload': {
            const [localPath, remotePath] = args as [string, string];
            uploadFile(sftp, localPath, remotePath, transferOptions)
              .then(() => { resolve(undefined); conn.end(); })
              .catch((error) => { reject(error); conn.end(); });
            break;
          }
          case 'download': {
            const [remotePath, localPath] = args as [string, string];
            downloadFile(sftp, remotePath, localPath, transferOptions)
              .then(() => { resolve(undefined); conn.end(); })
              .catch((error) => { reject(error); conn.end(); });
            break;
          }
          case 'list': {
            const [remotePath] = args;
            sftp.readdir(remotePath, (err, list) => {
              if (err) {
                reject(new McpError(ErrorCode.InternalError, `List error: ${err.message}`));
                conn.end();
                return;
              }
              resolve(list);
              conn.end();
            });
            break;
          }
          default:
            reject(new McpError(ErrorCode.InternalError, 'Invalid SFTP action'));
            conn.end();
        }
      });
    });
    conn.on('error', (err) => {
      release();
      reject(new McpError(ErrorCode.InternalError, `SFTP connection error: ${err.message}`));
    });
    try { conn.connect(sshConfig); } catch (error) { release(); reject(error); }
  });
}

server.tool(
  "exec",
  "Execute a shell command on the remote SSH server and return the output.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
  },
  async ({ command }) => {
    // Sanitize command input
    if (typeof command !== 'string' || !command.trim()) {
      throw new McpError(ErrorCode.InternalError, 'Command must be a non-empty string.');
    }
    const sshConfig: any = {
      host: HOST,
      port: PORT,
      username: USER,
    readyTimeout: 10000,
        hostHash: 'sha256',
        hostVerifier,
    };
    try {
      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
      const result = await execSshCommand(sshConfig, command);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

async function execSshCommand(sshConfig: any, command: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    let release: () => void;
    try { release = connectionGate.acquire(); } catch (error) { reject(error); return; }
    const conn = new SSHClient();
    conn.once('close', release);
    const output = new OutputLimiter(DEFAULT_MAX_OUTPUT_BYTES);
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error('SSH command timed out'));
    }, DEFAULT_EXEC_TIMEOUT_MS);

    function finish(error?: Error, result?: string) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      conn.end();
      release();
      if (error) {
        reject(new McpError(ErrorCode.InternalError, error.message));
      } else {
        resolve({ content: [{ type: 'text', text: result ?? '' }] });
      }
    }

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          finish(err);
          return;
        }
        stream.on('data', (chunk: Buffer) => {
          if (settled) return;
          try {
            output.add(chunk);
            stdout += chunk.toString();
          } catch (error) {
            stream.close();
            finish(error instanceof Error ? error : new Error(String(error)));
          }
        });
        stream.stderr.on('data', (chunk: Buffer) => {
          if (settled) return;
          try {
            output.add(chunk);
            stderr += chunk.toString();
          } catch (error) {
            stream.close();
            finish(error instanceof Error ? error : new Error(String(error)));
          }
        });
        stream.on('error', (error: Error) => finish(error));
        stream.on('close', (code: number | null, signal: string | null) => {
          if (settled) return;
          try {
            finish(undefined, formatCommandResult({ stdout, stderr, exitCode: code, signal }));
          } catch (error) {
            finish(error instanceof Error ? error : new Error(String(error)));
          }
        });
      });
    });
    conn.on('error', (error) => finish(error));
    try {
      conn.connect(sshConfig);
    } catch (error) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

// 启动 MCP 服务器
async function main() {
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