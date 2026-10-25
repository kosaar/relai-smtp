# syntax=docker/dockerfile:1
#
# TEST UNIQUEMENT — simule le poste d'un destinataire (rôle de Thunderbird) :
#  - RNP (bibliothèque OpenPGP de Thunderbird) : génère la paire de clés,
#    déchiffre les messages ;
#  - GnuPG, gpg-wks-client, curl : clés invalides de test, URL WKD, dépôt de
#    clé sur l'annuaire en HTTPS (outil keys) ;
#  - Python (imaplib) : relève la BAL en IMAPS, certificat vérifié (outil mailbox).
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
# Un ARG déclaré avant FROM doit être redéclaré pour être visible ensuite.
ARG UBUNTU_TAG

LABEL org.opencontainers.image.title="smtp-relay-test-workstation" \
      org.opencontainers.image.description="Poste destinataire simulé (RNP, GnuPG, IMAPS) pour les tests du relai" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}"

ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends rnp gnupg gpg-wks-client curl ca-certificates openssl python3; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    useradd --create-home --shell /bin/bash user

COPY --chmod=0755 bin/ /usr/local/bin/
COPY lib/ /usr/local/lib/workstation/

USER user
WORKDIR /home/user
CMD ["sleep", "infinity"]
