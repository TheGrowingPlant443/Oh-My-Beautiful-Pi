#!/bin/bash
# Idempotent provisioning of the launcher-owned Ubuntu 24.04 guest. Run as root through sudo by the host
# controller over its own SSH connection; changes only this dedicated guest, never the Mac host.
# Every application, agent and display dependency comes from the launcher's pinned Nix lock, not apt.
set -euo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

fail() { echo "ombp-provision: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "must run as root"
user="${SUDO_USER:-}"
[ -n "$user" ] && [ "$user" != root ] && id "$user" >/dev/null 2>&1 || fail "run through sudo as the guest user"
state=/var/lib/ombp
install -d -m 0755 "$state"

NIX_VERSION=2.35.4
case "$(uname -m)" in
  aarch64) system=aarch64-linux; nix_sha256=14a940a2d0ae5b2c623dc2ca168311c9367fd4bc416f6ded0c1087089d6de934 ;;
  x86_64) system=x86_64-linux; nix_sha256=ff66236d2f7e2a21f3350e73668e021ac6a8881ef277a38e16e952bfb22718c3 ;;
  *) fail "unsupported guest architecture $(uname -m)" ;;
esac

# 1. Bootstrap packages only (no application dependencies).
packages=(ca-certificates curl xz-utils uidmap fuse3 dbus-user-session slirp4netns fuse-overlayfs)
missing=()
for package in "${packages[@]}"; do
  if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != "install ok installed" ]; then
    missing+=("$package")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  apt-get update -q
  apt-get install -y -q --no-install-recommends "${missing[@]}"
fi

# 2. Subordinate IDs for rootless Podman: one 65536 range after every existing one, added once.
for file in /etc/subuid /etc/subgid; do
  touch "$file"
  if ! grep -q "^${user}:" "$file"; then
    start=$(awk -F: 'BEGIN { end = 100000 } { if ($2 + $3 > end) end = $2 + $3 } END { print end }' "$file")
    if [ "$file" = /etc/subuid ]; then usermod --add-subuids "${start}-$((start + 65535))" "$user"
    else usermod --add-subgids "${start}-$((start + 65535))" "$user"; fi
  fi
done

# 3. A persistent user session/runtime directory (/run/user/<uid>) for the supervisor and Podman.
loginctl enable-linger "$user"

# 4. A working /dev/fuse and the setuid fusermount3 helper the launcher's FUSE gateway uses.
[ -c /dev/fuse ] || modprobe fuse || true
[ -c /dev/fuse ] || fail "/dev/fuse is unavailable in the guest kernel"
[ -u /usr/bin/fusermount3 ] || fail "/usr/bin/fusermount3 is not setuid"

# 5. Kernel limits for OMBP, Chromium and SonarQube; never lower an existing larger value.
raise() {
  local key=$1 target=$2 current
  current=$(sysctl -n "$key")
  [ "$current" -ge "$target" ] && echo "$key = $current" || echo "$key = $target"
}
{ raise vm.max_map_count 524288; raise fs.file-max 131072; } > "$state/sysctl.tmp"
install -m 0644 "$state/sysctl.tmp" /etc/sysctl.d/90-ombp.conf
rm -f "$state/sysctl.tmp"
sysctl -q -p /etc/sysctl.d/90-ombp.conf

# 6. sshd: the host's reverse-forwarded gateway sockets replace stale ones and are owner-only.
cat > /etc/ssh/sshd_config.d/90-ombp.conf <<'EOF'
StreamLocalBindUnlink yes
StreamLocalBindMask 0177
AllowAgentForwarding no
X11Forwarding no
EOF
sshd -t
if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi

# 7. Container policy for the Nix Podman (it reads /etc/containers); engine images are digest-pinned.
install -d -m 0755 /etc/containers
if [ ! -e /etc/containers/policy.json ]; then
  printf '%s\n' '{"default":[{"type":"insecureAcceptAnything"}]}' > /etc/containers/policy.json
fi

# 8. Nix, from the pinned release tarball, verified before extraction or execution.
nix=/nix/var/nix/profiles/default/bin/nix
if [ -x "$nix" ]; then
  version=$("$nix" --version)
  [ "$version" = "nix (Nix) $NIX_VERSION" ] || fail "existing guest Nix is '$version', expected $NIX_VERSION; refusing to reinstall"
  systemctl is-active --quiet nix-daemon.socket || systemctl is-active --quiet nix-daemon.service \
    || systemctl start nix-daemon.socket || fail "existing guest Nix has no working nix-daemon"
elif [ -e /nix ] || [ -e /etc/nix ]; then
  fail "inconsistent partial Nix installation in the guest (/nix or /etc/nix exists without $nix); refusing to reinstall over it"
else
  work=$(mktemp -d /var/tmp/ombp-nix.XXXXXXXX)
  trap 'rm -rf "$work"' EXIT
  tarball="$work/nix-$NIX_VERSION-$system.tar.xz"
  curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
    --output "$tarball" "https://releases.nixos.org/nix/nix-$NIX_VERSION/nix-$NIX_VERSION-$system.tar.xz"
  echo "$nix_sha256  $tarball" | sha256sum --check --strict --quiet || fail "Nix tarball digest mismatch"
  tar -xJf "$tarball" -C "$work"
  "$work/nix-$NIX_VERSION-$system/install" --daemon --yes < /dev/null
  [ -x "$nix" ] || fail "Nix installer did not produce $nix"
  rm -rf "$work"
  trap - EXIT
fi

# 9. Ubuntu may forbid unprivileged user namespaces for unconfined programs such as the Nix Podman.
#    Test exactly that (an unconfined interpreter mapping itself); relax it only in this guest, only if needed.
userns_test='import os
pid = os.fork()
if pid == 0:
    try:
        uid, gid = os.getuid(), os.getgid()
        os.unshare(os.CLONE_NEWUSER)
        open("/proc/self/setgroups", "w").write("deny")
        open("/proc/self/uid_map", "w").write(f"0 {uid} 1")
        open("/proc/self/gid_map", "w").write(f"0 {gid} 1")
        os.setuid(0)
        os.mkdir("/proc/self/root/tmp/.ombp-userns-probe-" + str(os.getpid()))
        os.rmdir("/proc/self/root/tmp/.ombp-userns-probe-" + str(os.getpid()))
        os._exit(0)
    except OSError:
        os._exit(1)
os._exit(os.waitpid(pid, 0)[1] >> 8)'
userns_relaxed=false
if ! runuser -u "$user" -- /usr/bin/python3 -c "$userns_test"; then
  if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)" = 1 ]; then
    echo "kernel.apparmor_restrict_unprivileged_userns = 0" > /etc/sysctl.d/91-ombp-userns.conf
    sysctl -q -p /etc/sysctl.d/91-ombp-userns.conf
    userns_relaxed=true
    runuser -u "$user" -- /usr/bin/python3 -c "$userns_test" || fail "unprivileged user namespaces still fail"
  else
    fail "unprivileged user namespaces are unavailable in the guest"
  fi
elif [ -e /etc/sysctl.d/91-ombp-userns.conf ]; then
  userns_relaxed=true
fi

printf '{"nix":"%s","system":"%s","apparmor_userns_relaxed":%s}\n' "$NIX_VERSION" "$system" "$userns_relaxed" \
  > "$state/provisioned.json"
echo "ombp-provision: ok"
