FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nfs-kernel-server \
        nfs-common \
        rpcbind \
    && rm -rf /var/lib/apt/lists/*

RUN <<'EOF'
set -eu
cat > /usr/local/bin/nfs-entrypoint <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

: "${NFS_EXPORT_DIR:=/srv/nfs-rs/export}"
: "${NFS_EXPORT_OPTIONS:=*(rw,sync,no_subtree_check,no_root_squash,fsid=0,insecure)}"
: "${MOUNTD_PORT:=20048}"
: "${STATD_PORT:=32765}"
: "${STATD_OUTGOING_PORT:=32766}"
: "${NFSV4_GRACE_TIME:=1}"
: "${NFSV4_LEASE_TIME:=10}"
: "${NFSD_THREADS:=8}"

mountd_pid=""

cleanup() {
    if [ -n "$mountd_pid" ]; then
        kill "$mountd_pid" >/dev/null 2>&1 || true
        wait "$mountd_pid" >/dev/null 2>&1 || true
    fi
    exportfs -ua >/dev/null 2>&1 || true
    rpc.nfsd 0 >/dev/null 2>&1 || true
    pkill rpc.statd >/dev/null 2>&1 || true
    pkill rpcbind >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$NFS_EXPORT_DIR" /run/rpcbind /var/lib/nfs /var/lib/nfs/v4recovery /proc/fs/nfsd
chmod 0777 "$NFS_EXPORT_DIR"

if ! mountpoint -q /proc/fs/nfsd; then
    mount -t nfsd nfsd /proc/fs/nfsd
fi

printf '%s\n' "$NFSV4_GRACE_TIME" > /proc/fs/nfsd/nfsv4gracetime 2>/dev/null || true
printf '%s\n' "$NFSV4_LEASE_TIME" > /proc/fs/nfsd/nfsv4leasetime 2>/dev/null || true

printf '%s %s\n' "$NFS_EXPORT_DIR" "$NFS_EXPORT_OPTIONS" > /etc/exports

rpcbind -w
rpc.statd --port "$STATD_PORT" --outgoing-port "$STATD_OUTGOING_PORT" || true
rpc.nfsd "$NFSD_THREADS"
exportfs -rav
printf 'Y\n' > /proc/fs/nfsd/v4_end_grace 2>/dev/null || true

rpc.mountd --foreground --port "$MOUNTD_PORT" --manage-gids &
mountd_pid="$!"
wait "$mountd_pid"
SCRIPT
chmod +x /usr/local/bin/nfs-entrypoint
EOF

EXPOSE 111/tcp 111/udp 2049/tcp 2049/udp 20048/tcp 20048/udp 32765/tcp 32765/udp

ENTRYPOINT ["/usr/local/bin/nfs-entrypoint"]
