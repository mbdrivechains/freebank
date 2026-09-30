# A Guix environment for contrib/guix/guix-build, for machines without Guix (a developer box, GitHub Actions).
# Runs the Guix build daemon inside the container, so the container must be --privileged (guix-build uses
# `guix environment --container`, which needs namespaces). The store lives in /gnu and /var/guix: mount volumes there
# to keep it between runs (an empty named volume is filled from this image on first use). Usage:
# contrib/guix/docker/run.sh (see its header).
#
# Guix itself comes from the official binary release, checked against the sha256 below. That hash was taken from the
# tarball after verifying its signature (guix-binary-1.5.0.x86_64-linux.tar.xz.sig, good signature from Efraim Flashner,
# A28B F40C 3E55 1372 662D 14F7 41AA E7DC CA3D 8351, one of the release keys listed in Guix's etc/guix-install.sh).
# This Guix only runs the daemon and `guix time-machine`; the build itself uses the Guix commit pinned in
# contrib/guix/libexec/prelude.bash, so a newer host Guix does not change the output. (Ubuntu's packaged Guix 1.4.0
# crashed on several substitute downloads.)
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git make curl xz-utils patch bzip2 gzip tar coreutils findutils sed grep \
        util-linux procps netbase passwd \
 && rm -rf /var/lib/apt/lists/*

ARG GUIX_VERSION=1.5.0
ARG GUIX_SHA256=aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817
RUN curl -fsSL -o /tmp/guix.tar.xz "https://ftp.gnu.org/gnu/guix/guix-binary-${GUIX_VERSION}.x86_64-linux.tar.xz" \
 && echo "${GUIX_SHA256}  /tmp/guix.tar.xz" | sha256sum -c - \
 && tar --warning=no-timestamp -xJf /tmp/guix.tar.xz -C / \
 && rm /tmp/guix.tar.xz \
 && mkdir -p /root/.config/guix \
 && ln -sf /var/guix/profiles/per-user/root/current-guix /root/.config/guix/current \
 && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix /usr/local/bin/guix \
 && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix-daemon /usr/local/bin/guix-daemon

# Trust the official substitute servers (pre-built packages; guix still checks every hash). Without them guix would
# silently build everything from source (days), so fail if none were authorized.
RUN for k in /root/.config/guix/current/share/guix/bordeaux.guix.gnu.org.pub \
             /root/.config/guix/current/share/guix/ci.guix.gnu.org.pub; do \
        guix archive --authorize < "$k"; \
    done; test -s /etc/guix/acl

RUN git config --system safe.directory '*'

# Store paths can hold non-ASCII file names (libgit2's test fixtures): guile needs a UTF-8 locale to write them.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

COPY entrypoint.sh /usr/local/bin/guix-entrypoint
RUN chmod +x /usr/local/bin/guix-entrypoint
ENTRYPOINT ["/usr/local/bin/guix-entrypoint"]
