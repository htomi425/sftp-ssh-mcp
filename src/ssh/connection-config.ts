export interface ConnectionOptions {
  host: string;
  username: string;
  port: number;
  readyTimeout: number;
}

export function validateConnectionOptions(options: ConnectionOptions): ConnectionOptions {
  if (!options.host.trim()) throw new Error('SSH host must not be empty');
  if (!options.username.trim()) throw new Error('SSH username must not be empty');
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error('SSH port must be an integer between 1 and 65535');
  }
  if (!Number.isInteger(options.readyTimeout) || options.readyTimeout < 1000 || options.readyTimeout > 120000) {
    throw new Error('SSH readyTimeout must be between 1000 and 120000 ms');
  }
  return options;
}
