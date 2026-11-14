export type TransportMode = 'stdio' | 'http';

export interface TransportSettings {
  mode: TransportMode;
  host: string;
  port: number;
}

export function parseTransportSettings(env: Record<string, string | undefined>): TransportSettings {
  const mode = env.SSH_MCP_TRANSPORT ?? 'stdio';
  if (mode !== 'stdio' && mode !== 'http') throw new Error('SSH_MCP_TRANSPORT must be stdio or http');
  if (mode === 'stdio') {
    if (env.SSH_MCP_HTTP_HOST !== undefined || env.SSH_MCP_HTTP_PORT !== undefined) {
      throw new Error('HTTP settings require SSH_MCP_TRANSPORT=http');
    }
    return { mode, host: '127.0.0.1', port: 3000 };
  }
  const host = env.SSH_MCP_HTTP_HOST ?? '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') {
    throw new Error('HTTP transport must bind to loopback; use an authenticated reverse proxy for external access');
  }
  const rawPort = env.SSH_MCP_HTTP_PORT ?? '3000';
  if (!/^[0-9]+$/.test(rawPort)) throw new Error('SSH_MCP_HTTP_PORT must be an integer from 1 to 65535');
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('SSH_MCP_HTTP_PORT must be an integer from 1 to 65535');
  return { mode, host, port };
}
