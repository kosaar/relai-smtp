# syntax=docker/dockerfile:1
#
# Relai SMTP : Postfix (paquets Ubuntu officiels).
#  - soumission 587 seule : STARTTLS obligatoire (TLS >= 1.2) + SASL, un
#    identifiant par application (inventaire config/applications.toml) ;
#  - chaque login n'envoie qu'avec son adresse (enveloppe ici, From: dans la
#    passerelle appelée en milter avant la mise en file) ;
#  - sortie vers le smarthost du fournisseur en TLS vérifié + SASL.
# Aucune configuration ni secret n'est figé dans l'image : tout est généré au
# démarrage par entrypoint.sh. Contexte de construction : racine du dépôt.

# Ubuntu 26.04 LTS (resolute), tag daté = build reproductible.
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
# Un ARG déclaré avant FROM doit être redéclaré pour être visible ensuite.
ARG UBUNTU_TAG

ARG VERSION=2.0.0
LABEL org.opencontainers.image.title="smtp-relay" \
      org.opencontainers.image.description="Relai SMTP applicatif Postfix (587 STARTTLS + SASL par application -> fournisseur en TLS + SASL)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}" \
      org.opencontainers.image.licenses="MIT"

# Paquets :
#  - postfix             : le MTA ;
#  - libsasl2-modules    : mécanismes SASL PLAIN/LOGIN (client et serveur) ;
#  - libsasl2-modules-db : base sasldb des applications (auxprop) ;
#  - sasl2-bin           : saslpasswd2 (génération de la base au démarrage) ;
#  - python3             : relay-config (validation et rendu de l'inventaire) ;
#  - ca-certificates     : autorités racines pour vérifier le fournisseur.
# La configuration Ubuntu de /etc/postfix est sauvegardée pour être restaurée
# dans un tmpfs au démarrage (système de fichiers racine en lecture seule).
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends postfix libsasl2-modules libsasl2-modules-db \
        sasl2-bin python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt /var/log/dpkg.log; \
    rm -f /etc/postfix/main.cf /etc/postfix/sasl_passwd* /etc/sasldb2; \
    cp -a /etc/postfix /usr/local/share/postfix-dist; \
    mkdir -p /usr/local/share/relay /opt/relay/lib

COPY --chmod=0644 relay/config/ /usr/local/share/relay/templates/
COPY --chmod=0755 relay/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0644 relay/scripts/relay-lib.sh /usr/local/lib/relay-lib.sh
COPY --chmod=0755 relay/scripts/relay-healthcheck.sh /usr/local/bin/relay-healthcheck
COPY common/relaycfg/ /opt/relay/lib/relaycfg/
COPY --chmod=0755 common/bin/relay-config /usr/local/bin/relay-config

# File d'attente persistante (à monter sur un volume nommé).
VOLUME ["/var/spool/postfix"]
EXPOSE 587

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/relay-healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postfix", "start-fg"]
