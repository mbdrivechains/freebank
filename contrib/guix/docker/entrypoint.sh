#!/bin/bash
# Start the Guix build daemon, then build. With no arguments: clone the mounted tree's HEAD into a root-owned directory
# inside the container, run contrib/guix/guix-build there, and copy guix-build-<version>/output back to the mounted tree
# (owned by HOST_UID). guix-build's container maps only root, so it cannot write to a tree owned by another uid; the
# clone avoids that, and it also means exactly the committed HEAD is built. With arguments: run them in the mounted tree.
set -euo pipefail
# One build at a time per store: two guix-daemons on one store database would corrupt it.
exec 9>/var/guix/freebank-guix.lock
flock -n 9 || { echo "ERR: another build is using the freebank-guix-var volume"; exit 1; }
# The build users the daemon needs (the distribution package's postinst may have made them already).
getent group guixbuild >/dev/null || groupadd --system guixbuild
for i in $(seq -w 1 10); do
    id "guixbuilder$i" >/dev/null 2>&1 || useradd -g guixbuild -G guixbuild -d /var/empty -s "$(command -v nologin)" \
        -c "Guix build user $i" --system "guixbuilder$i"
done
# ci first: a download from bordeaux with no size crashes guix's progress display (1.4.0 and 1.5.0, in time-machine's
# build-self); bordeaux still serves what ci has collected away.
guix-daemon --build-users-group=guixbuild \
            --substitute-urls="https://ci.guix.gnu.org https://bordeaux.guix.gnu.org" &
for i in $(seq 1 30); do [ -S /var/guix/daemon-socket/socket ] && break; sleep 1; done
[ -S /var/guix/daemon-socket/socket ] || { echo "guix-daemon did not start"; exit 1; }
echo "guix-daemon up: $(guix --version | sed -n 1p)"

if [ $# -gt 0 ]; then
    rc=0
    "$@" || rc=$?
    exit $rc
fi

SRC=$PWD
WORK=/build/freebank
HEAD_COMMIT=$(git -C "$SRC" rev-parse HEAD)
[ -z "$(git -C "$SRC" status --porcelain --untracked-files=no)" ] || \
    echo "WARNING: the tree has uncommitted changes; building the committed HEAD $HEAD_COMMIT only"
rm -rf "$WORK"
git clone --quiet --no-checkout "$SRC" "$WORK"
git -C "$WORK" checkout --quiet "$HEAD_COMMIT"
echo "building $HEAD_COMMIT in $WORK"
# Depends sources, built depends and guix's own git cache live on the freebank-guix-cache volume.
mkdir -p /cache/sources /cache/built /cache/xdg
cd "$WORK"
rc=0
env HOSTS="${HOSTS:-x86_64-linux-gnu}" JOBS="${JOBS:-2}" ${FORCE_VERSION:+FORCE_VERSION="$FORCE_VERSION"} \
    SOURCES_PATH=/cache/sources BASE_CACHE=/cache/built XDG_CACHE_HOME=/cache/xdg \
    ./contrib/guix/guix-build || rc=$?
# Hand the outputs back to the invoking user, even after a failure (partial outputs help).
for d in guix-build-*/; do
    [ -d "$d/output" ] || continue
    rm -rf "${SRC:?}/${d}output"
    mkdir -p "$SRC/$d"
    cp -a "$d/output" "$SRC/$d"
    [ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$SRC/$d"
done
echo "=== guix-build rc=$rc; outputs in $SRC/guix-build-*/output"
exit $rc
