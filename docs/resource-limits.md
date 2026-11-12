# SSH/SFTP resource limits (development branch)

All limits are enforced inside the MCP process, independent of Cloudflare Access.

| Environment variable | Default | Allowed range |
| --- | --- | --- |
| `SSH_MCP_MAX_CONNECTIONS` | `2` | 1–16 |
| `SSH_MCP_MAX_TRANSFER_BYTES` | `67108864` (64 MiB) | 1024–1073741824 bytes |
| `SSH_MCP_TRANSFER_TIMEOUT_MS` | `120000` (120 s) | 1000–600000 ms |

Command execution currently has fixed limits: 30 seconds and 1 MiB of combined stdout/stderr. SSH handshake uses a 10-second `readyTimeout`.

When a connection limit is reached, the new request fails rather than waiting in an unbounded queue. A SFTP transfer is aborted if its byte or time limit is exceeded.

Downloads use a temporary file in the destination directory, then create the final name using a hard link. Existing destination files are not overwritten. The temporary file is removed in a `finally` block.

Uploads create remote files with exclusive-create semantics (`wx`), protecting existing remote files. **A failed upload may leave a partial remote file**, which should be handled before production use.

**Important:** `localPath` still refers to the MCP server's filesystem, not the remote ChatGPT client's filesystem. Remote HTTP MCP requires a separate content-transfer API and access controls.

This branch is not yet production-ready. CT 200 should continue using the approved deployment until the draft PR is reviewed and integration-tested.
