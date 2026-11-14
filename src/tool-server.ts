import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { Client as SSHClient } from 'ssh2';
import { z } from 'zod';
import { formatCommandResult } from './ssh/command-result.js';
import { formatDirectoryListing } from './ssh/directory-listing.js';
import { sshConfigForTarget, type TargetRegistry } from './ssh/targets.js';
import { resolveToolTarget, type ToolExecutionContext } from './tool-target.js';
import { DEFAULT_EXEC_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES, OutputLimiter } from './ssh/exec-limits.js';
import { uploadFile, downloadFile } from './ssh/sftp-transfer.js';
import { ConnectionGate, parseBoundedInteger, DEFAULT_MAX_TRANSFER_BYTES, DEFAULT_TRANSFER_TIMEOUT_MS, DEFAULT_MAX_CONCURRENT_CONNECTIONS } from './ssh/resource-limits.js';

const transferOptions = {
  maxBytes: parseBoundedInteger(process.env.SSH_MCP_MAX_TRANSFER_BYTES, DEFAULT_MAX_TRANSFER_BYTES, 1024, 1024 * 1024 * 1024, 'SSH_MCP_MAX_TRANSFER_BYTES'),
  timeoutMs: parseBoundedInteger(process.env.SSH_MCP_TRANSFER_TIMEOUT_MS, DEFAULT_TRANSFER_TIMEOUT_MS, 1000, 600000, 'SSH_MCP_TRANSFER_TIMEOUT_MS'),
};
const connectionGate = new ConnectionGate(parseBoundedInteger(
  process.env.SSH_MCP_MAX_CONNECTIONS, DEFAULT_MAX_CONCURRENT_CONNECTIONS, 1, 16, 'SSH_MCP_MAX_CONNECTIONS',
));

export function createToolServer(targets: TargetRegistry, context: ToolExecutionContext, mode: 'stdio' | 'http'): McpServer {
// MCP 服务器实例化
const server = new McpServer({
  name: 'SSH MCP Server', // 服务器名称
  version: '1.0.5', // 服务器版本
});

// 实现 SFTP 上传工具
server.tool(
  "sftp_upload", // 工具名称
  "Upload a file to remote server via SFTP", // 工具描述
  { // 工具参数
    target: z.string().optional().describe("Named SSH target"),
    localPath: z.string().describe("Local file path to upload"),
    remotePath: z.string().describe("Remote path to save the file"),
  },
  async ({ target, localPath, remotePath }) => { // 工具实现
    try {
      const selected = resolveToolTarget(targets, target, context, mode);
      if (mode === 'http') throw new McpError(ErrorCode.InvalidRequest, 'HTTP local file transfer is disabled: server filesystem access is not permitted');
      const sshConfig = await sshConfigForTarget(selected);
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
    target: z.string().optional().describe("Named SSH target"),
    remotePath: z.string().describe("Remote file path to download"),
    localPath: z.string().describe("Local path to save the file"),
  },
  async ({ target, remotePath, localPath }) => {
    try {
      const selected = resolveToolTarget(targets, target, context, mode);
      if (mode === 'http') throw new McpError(ErrorCode.InvalidRequest, 'HTTP local file transfer is disabled: server filesystem access is not permitted');
      const sshConfig = await sshConfigForTarget(selected);
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
    target: z.string().optional().describe("Named SSH target"),
    remotePath: z.string().describe("Remote directory path to list"),
  },
  async ({ target, remotePath }) => {
    try {
      const sshConfig = await sshConfigForTarget(resolveToolTarget(targets, target, context, mode));
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
    target: z.string().optional().describe("Named SSH target"),
    command: z.string().describe("Shell command to execute on the remote SSH server"),
  },
  async ({ target, command }) => {
    // Sanitize command input
    if (typeof command !== 'string' || !command.trim()) {
      throw new McpError(ErrorCode.InternalError, 'Command must be a non-empty string.');
    }
    try {
      const sshConfig = await sshConfigForTarget(resolveToolTarget(targets, target, context, mode));
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


return server;
}
