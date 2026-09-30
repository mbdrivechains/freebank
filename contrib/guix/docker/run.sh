#!/bin/bash
# Reproducible FreeBank build in Docker: builds the guix image (once), then runs contrib/guix/guix-build on this
# checkout's committed HEAD inside it (see entrypoint.sh). The Guix store stays in the docker volumes
# freebank-guix-<guix version>-gnu and -var, and depends sources, built depends and guix's git cache in freebank-guix-cache, so later runs
# reuse them. Outputs: guix-build-<version>/output/<host>/ (tarball + SHA256SUMS.part). The version comes from
# configure.ac; FORCE_VERSION, if set, must match it.
#   contrib/guix/docker/run.sh                    # HOSTS=x86_64-linux-gnu JOBS=2 by default
#   JOBS=8 contrib/guix/docker/run.sh
set -euo pipefail
TOP=$(git rev-parse --show-toplevel)
cd "$TOP"
docker build -q -t freebank-guix contrib/guix/docker >/dev/null 2>&1 || DOCKER_BUILDKIT=0 docker build -q -t freebank-guix contrib/guix/docker >/dev/null
# A git worktree's .git is a file pointing into the main repository: mount that too, at the same path.
GITDIR=$(git rev-parse --git-common-dir)
GITDIR=$(cd "$GITDIR" && pwd)
# The store volumes are filled from the image on first use, so they are tied to the image's Guix version.
STORE_VOL=freebank-guix-$(sed -n 's/^ARG GUIX_VERSION=//p' contrib/guix/docker/Dockerfile)
exec docker run --rm --init --privileged \
    -v "$STORE_VOL-gnu:/gnu" -v "$STORE_VOL-var:/var/guix" -v freebank-guix-cache:/cache \
    -v "$TOP:$TOP" -v "$GITDIR:$GITDIR" -w "$TOP" \
    -e HOSTS="${HOSTS:-x86_64-linux-gnu}" -e JOBS="${JOBS:-2}" ${FORCE_VERSION:+-e FORCE_VERSION="$FORCE_VERSION"} \
    ${GUIX_URL:+-e GUIX_URL="$GUIX_URL"} ${SUBSTITUTE_URLS:+-e SUBSTITUTE_URLS="$SUBSTITUTE_URLS"} ${V:+-e V=1} \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    freebank-guix "$@"
