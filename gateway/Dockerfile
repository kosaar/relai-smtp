# syntax=docker/dockerfile:1
#
# Passerelle du relai SMTP : milter Python appelé par Postfix AVANT la mise en
# file : identité de l'application, clé OpenPGP de chaque destinataire (WKD de
# l'annuaire), chiffrement PGP/MIME. Contexte de construction : racine du dépôt.
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
ARG UBUNTU_TAG

ARG VERSION=2.0.0
LABEL org.opencontainers.image.title="smtp-relay-gateway" \
      org.opencontainers.image.description="Passerelle (milter) du relai SMTP applicatif" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}" \
      org.opencontainers.image.licenses="MIT"

ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 python3-milter gpg ca-certificates; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt /var/log/dpkg.log; \
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway; \
    mkdir -p /opt/relay/lib

COPY common/relaycfg/ /opt/relay/lib/relaycfg/
COPY common/pgpkeys/ /opt/relay/lib/pgpkeys/
COPY gateway/relaygw/ /opt/relay/lib/relaygw/
COPY --chmod=0755 gateway/bin/relay-gateway /usr/local/bin/relay-gateway
COPY --chmod=0755 gateway/bin/gateway-healthcheck /usr/local/bin/gateway-healthcheck

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PGP_TMPDIR=/tmp
USER gateway
EXPOSE 9900

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/gateway-healthcheck"]

ENTRYPOINT ["/usr/local/bin/relay-gateway"]
