# syntax=docker/dockerfile:1
#
# Annuaire de clés publiques OpenPGP du relai : dépôt HTTPS, validation par un
# administrateur, publication WKD, révocations, journal d'audit (SQLite).
# Contexte de construction : racine du dépôt.
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
ARG UBUNTU_TAG

ARG VERSION=2.0.0
LABEL org.opencontainers.image.title="smtp-relay-keydir" \
      org.opencontainers.image.description="Annuaire de clés publiques OpenPGP (dépôt HTTPS, validation, WKD)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}" \
      org.opencontainers.image.licenses="MIT"

# python3 (serveur, SQLite) ; gpg seul (lecture des clés publiques, sans agent).
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 gpg; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt /var/log/dpkg.log; \
    useradd --system --no-create-home --home-dir /var/lib/keydir --shell /usr/sbin/nologin keydir; \
    install -d -o keydir -g keydir -m 0700 /var/lib/keydir; \
    mkdir -p /opt/keydir/lib

COPY common/pgpkeys/ /opt/keydir/lib/pgpkeys/
COPY keydir/keydir/ /opt/keydir/lib/keydir/
COPY --chmod=0755 keydir/bin/keydir-server keydir/bin/keydir-admin keydir/bin/keydir-healthcheck /usr/local/bin/
COPY --chmod=0755 keydir/entrypoint.sh /usr/local/bin/keydir-entrypoint

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
VOLUME ["/var/lib/keydir"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/keydir-healthcheck"]

ENTRYPOINT ["/usr/local/bin/keydir-entrypoint"]
CMD ["/usr/local/bin/keydir-server"]
