#!/bin/sh
set -eu

# Run only inside the disposable Alpine validation container.
test "$(cat /etc/alpine-release)" = "3.24.4"
mkdir -p /work
tar -C /source --exclude=.git -cf - . | tar -C /work -xf -
cd /work
apk add --no-cache nodejs npm openssh
printf 'Alpine: '; cat /etc/alpine-release
node --version
npm --version
printf 'cgroup memory.max: '; cat /sys/fs/cgroup/memory.max
printf 'cgroup cpu.max: '; cat /sys/fs/cgroup/cpu.max

npm ci
npm run build
# One test worker avoids multiplying Node heaps in the 512 MiB container.
node --test --test-concurrency=1 tests/*.test.mjs
npm audit --omit=dev --audit-level=high

adduser -D -s /bin/sh mcp-test
# An unlocked account is needed for public-key login; password auth is disabled.
echo 'mcp-test:unused-isolated-test-password' | chpasswd
fixture=/tmp/ssh-mcp-alpine-fixture
mkdir -p "$fixture" /run/sshd
chmod 755 "$fixture"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/client"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/host"
cp "$fixture/client.pub" "$fixture/authorized_keys"
chmod 644 "$fixture/authorized_keys"
cat > "$fixture/sshd_config" <<EOF
Port 22222
ListenAddress 127.0.0.1
HostKey $fixture/host
AuthorizedKeysFile $fixture/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
StrictModes no
Subsystem sftp internal-sftp
PidFile $fixture/sshd.pid
EOF
/usr/sbin/sshd -f "$fixture/sshd_config" -E "$fixture/sshd.log"
trap 'test ! -f "$fixture/sshd.pid" || kill "$(cat "$fixture/sshd.pid")" 2>/dev/null || true' EXIT
fingerprint="$(ssh-keygen -lf "$fixture/host.pub" -E sha256 | awk '{print $2}')"
hex="$(node -e "console.log(Buffer.from(process.argv[1].replace(/^SHA256:/,''),'base64').toString('hex'))" "$fingerprint")"
export SSH_INTEGRATION_HOST=127.0.0.1
export SSH_INTEGRATION_PORT=22222
export SSH_INTEGRATION_USER=mcp-test
export SSH_INTEGRATION_KEY="$fixture/client"
export SSH_INTEGRATION_HOST_KEY_HEX="$hex"
if ! node --test tests/ssh-integration.test.mjs; then
  cat "$fixture/sshd.log"
  exit 1
fi
