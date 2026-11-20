export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal?: string | null;
}

export function formatCommandResult(result: CommandResult): string {
  const { stdout, stderr, exitCode, signal } = result;
  if (exitCode !== 0) {
    throw new Error(`Command failed (exit ${exitCode ?? 'unknown'}, signal ${signal ?? 'none'}):\n${stderr || stdout}`);
  }
  return stdout + (stderr ? `\n[stderr]\n${stderr}` : '');
}
