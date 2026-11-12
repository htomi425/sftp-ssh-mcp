# SSH host key pinning (development branch)

The MCP server **requires** `SSH_HOST_KEY_SHA256` at startup. This is the SHA-256 digest of the SSH server's public host key, represented as 64 hexadecimal characters. The server rejects mismatching host keys.

## Obtain the fingerprint

On the **SSH target host**, run:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

This prints the usual `SHA256:<base64>` fingerprint. Convert the base64 part to hexadecimal:

```sh
node -e "const x=process.argv[1].replace(/^SHA256:/,''); console.log(Buffer.from(x,'base64').toString('hex'))" 'SHA256:PASTE_VERIFIED_FINGERPRINT_HERE'
```

Verify the fingerprint through a **trusted, independent channel** (such as a direct console or a previously authenticated SSH session). Do not trust an unauthenticated `ssh-keyscan` result alone.

Set the resulting hex string as `SSH_HOST_KEY_SHA256` in the MCP server's environment. Keep the server's existing `--host`, `--user`, and `--key` or `--password` options for now.

## Notes

- Pinning one host key is a temporary single-target configuration. Multi-target support will use per-target pinned host keys.
- Rotating the SSH host key requires updating the pinned digest.
- Do not put passwords, private keys or access tokens in the repository.
- This branch is not ready for deployment to CT 200; it remains a draft until tests and deployment documentation are complete.
