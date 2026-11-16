# SFTP-SSH MCP Server

**Documentation:** [日本語 / Japanese README](./README.ja.md) | [Cloudflare OAuth integration](./integrations/cloudflare/README.md) | [HTTP/OAuth architecture](./docs/http-oauth-architecture.md)

> **Development branch:** This README describes `refactor/core`, not necessarily `main` or the published npm package. The Cloudflare OAuth integration is validated in isolated tests but **is not production-deployed or ready for use with a real identity provider**.

A [Model Context Protocol](https://modelcontextprotocol.io/) server for remote shell command execution over SSH and SFTP directory listing/file transfers. Targets can be Linux or Windows hosts with an SSH/SFTP service.

## Build

Node.js 22 and 24 are exercised in CI.

```sh
git clone https://github.com/htomi425/sftp-ssh-mcp.git
cd sftp-ssh-mcp
git switch refactor/core
npm ci
npm run build
npm test
```

## Local MCP clients: stdio (default)

Start the local build with an SSH target and a **pre-verified, pinned SSH host-key SHA-256 fingerprint**:

```sh
SSH_HOST_KEY_SHA256="<64-character SHA-256 hexadecimal digest>" \
node build/index.js --host=192.0.2.10 --port=22 --user=operator --key=/absolute/path/to/private_key
```

The required fingerprint is **64 hexadecimal characters** (with an optional `SHA256:` prefix), not the Base64 fingerprint commonly printed by OpenSSH. Verify the fingerprint with the host administrator over a trusted channel before configuring it. Use exactly one of `--key` or `--password`. Avoid passwords on process command lines because they can be exposed in process listings and client configuration files.

Example stdio MCP client configuration (replace paths and fingerprint):

```json
{
  "mcpServers": {
    "sftp-ssh-mcp": {
      "command": "node",
      "args": [
        "/absolute/path/to/sftp-ssh-mcp/build/index.js",
        "--host=192.0.2.10",
        "--user=operator",
        "--key=/absolute/path/to/private_key"
      ],
      "env": {
        "SSH_HOST_KEY_SHA256": "<64-character SHA-256 hexadecimal digest>"
      }
    }
  }
}
```

For multiple named hosts, configure `SSH_MCP_TARGETS` as a JSON object mapping target names to connection options. Each target requires `host`, `user`, `hostKeySha256`, and exactly one of `password` or `key`; `port` defaults to 22. Up to 32 targets are supported. The optional `target` tool argument chooses among them; if multiple names exist without `default`, selection is required.

## MCP tools

| Tool | Purpose | stdio | HTTP |
|---|---|---|---|
| `exec` | Run a command over SSH | Enabled | Authorized target only |
| `sftp_list` | List a remote directory | Enabled | Authorized target only |
| `sftp_upload` | Upload a server-local file via SFTP | Enabled | Disabled |
| `sftp_download` | Download a file to the server-local filesystem | Enabled | Disabled |

HTTP file-transfer tools remain listed but reject invocation to prevent arbitrary access to the MCP server's own filesystem. Resource limits and no-overwrite SFTP upload handling are documented in [resource limits](./docs/resource-limits.md).

## Streamable HTTP (opt-in; not OAuth by itself)

Set `SSH_MCP_TRANSPORT=http` and choose `SSH_MCP_HTTP_AUTH_MODE=static` for a locally configured static Bearer credential policy, or `gateway` for verified Ed25519 gateway assertions. The default listener is `127.0.0.1:3000` at `/mcp`; public bind addresses are rejected. Configure a named SSH target registry and an explicit principal-to-target allowlist.

For static mode, `SSH_MCP_HTTP_CREDENTIALS` is a JSON array of `{"id":"operator","token":"<at least 32 random URL-safe characters>","targets":["alpha"]}` entries. This is **not OAuth** and does not make direct Internet exposure safe. The gateway mode requires `SSH_MCP_GATEWAY_ISSUER`, `SSH_MCP_GATEWAY_AUDIENCE`, `SSH_MCP_GATEWAY_PUBLIC_KEY_PEM` and `SSH_MCP_IDENTITY_TARGETS`. The Node origin independently verifies the signed request binding and replay nonce, then maps the verified issuer and subject to allowed SSH targets.

The optional Cloudflare implementation separates OAuth authorization and resource Workers, with provider validation over a private Service Binding and request-bound assertions to the Node origin. Isolated Miniflare/workerd tests cover discovery, registration, PKCE, explicit consent, subject mapping and test-only origin flows. **Real upstream IdP sign-in/session management, production secrets and private Tunnel routing are not implemented or validated for deployment.** See the [Cloudflare integration documentation](./integrations/cloudflare/README.md) for status and constraints.

## Security

SSH commands execute with the privileges of the configured SSH account; use least privilege. Never commit SSH keys, static tokens, OAuth credentials or signing keys. Only use verified host-key pins. The gateway replay cache is in-memory and supports one Node process; multiple instances require a shared atomic store. For detailed Japanese setup instructions, see [README.ja.md](./README.ja.md).

**No changes to `main`, CT 200 or production Cloudflare configuration are implied by these branch instructions.**
