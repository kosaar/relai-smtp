# syntax=docker/dockerfile:1
#
# Relai SMTP interne : Postfix (paquets Debian officiels) qui accepte les mails
# des applications CI/CD en liste blanche et les relaie, en TLS + SASL, vers le
# MTA d'un fournisseur cloud. Aucune configuration ni secret n'est figé dans
# l'image : tout est généré au démarrage par entrypoint.sh.

# Tag daté = build reproductible ; mettre à jour volontairement (cf. docs).
ARG DEBIAN_TAG=trixie-20261005-slim
FROM debian:${DEBIAN_TAG}

ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="smtp-relay" \
      org.opencontainers.image.description="Relai SMTP interne Postfix (liste blanche IP -> fournisseur cloud en TLS + SASL)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/debian:${DEBIAN_TAG}" \
      org.opencontainers.image.licenses="MIT"

# Paquets :
#  - postfix          : le MTA ;
#  - libsasl2-modules : mécanismes SASL client PLAIN/LOGIN (auth chez le fournisseur) ;
#  - ca-certificates  : autorités racines pour vérifier le certificat du fournisseur.
# La configuration Debian de /etc/postfix est sauvegardée pour être restaurée
# dans un tmpfs au démarrage (système de fichiers racine en lecture seule).
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends postfix libsasl2-modules ca-certificates; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt /var/log/dpkg.log; \
    rm -f /etc/postfix/main.cf /etc/postfix/sasl_passwd*; \
    cp -a /etc/postfix /usr/local/share/postfix-dist; \
    mkdir -p /usr/local/share/relay

COPY --chmod=0644 config/ /usr/local/share/relay/templates/
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0644 scripts/relay-lib.sh /usr/local/lib/relay-lib.sh
COPY --chmod=0755 scripts/relay-healthcheck.sh /usr/local/bin/relay-healthcheck
COPY --chmod=0755 scripts/relay-reload-allowlist.sh /usr/local/bin/relay-reload-allowlist

# File d'attente persistante (à monter sur un volume nommé).
VOLUME ["/var/spool/postfix"]
EXPOSE 25

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/relay-healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postfix", "start-fg"]
