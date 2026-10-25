# syntax=docker/dockerfile:1
#
# TEST UNIQUEMENT — simule le fournisseur de messagerie :
#  - smarthost : Postfix, port 587, STARTTLS (TLS >= 1.2) et SASL obligatoires ;
#  - BAL : Dovecot, livraison LMTP, consultation en IMAPS 993 ;
#  - outil gen-test-pki : PKI de test de toute la stack (service « pki »).
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
# Un ARG déclaré avant FROM doit être redéclaré pour être visible ensuite.
ARG UBUNTU_TAG

LABEL org.opencontainers.image.title="smtp-relay-test-provider" \
      org.opencontainers.image.description="Fournisseur de messagerie simulé (Postfix + Dovecot) pour les tests du relai" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}"

ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends postfix sasl2-bin libsasl2-modules openssl \
        dovecot-imapd dovecot-lmtpd; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/vmail vmail; \
    install -d -o vmail -g vmail -m 0750 /var/vmail; \
    rm -rf /etc/dovecot/conf.d /etc/dovecot/private

COPY --chmod=0644 main.cf master.cf /etc/postfix/
COPY --chmod=0644 smtpd.conf /etc/postfix/sasl/smtpd.conf
COPY --chmod=0644 dovecot.conf /etc/dovecot/dovecot.conf
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0755 healthcheck.sh /usr/local/bin/provider-healthcheck
COPY --chmod=0755 gen-test-pki.sh /usr/local/bin/gen-test-pki

VOLUME ["/var/vmail"]
EXPOSE 587 993

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD ["/usr/local/bin/provider-healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD []
