# syntax=docker/dockerfile:1
#
# TEST UNIQUEMENT — simule le MTA du fournisseur cloud :
#  - port 587, STARTTLS obligatoire (certificat signé par une AC de test
#    générée au démarrage), TLS >= 1.2 ;
#  - authentification SASL obligatoire (Cyrus SASL, base sasldb) ;
#  - chaque message accepté est stocké dans /var/mail/captured/*.eml.
ARG DEBIAN_TAG=trixie-20261005-slim
FROM debian:${DEBIAN_TAG}

LABEL org.opencontainers.image.title="smtp-relay-test-fake-mta" \
      org.opencontainers.image.description="Faux MTA fournisseur cloud (Postfix + TLS + SASL) pour les tests du relai" \
      org.opencontainers.image.base.name="docker.io/library/debian:${DEBIAN_TAG}"

# postfix + sasl2-bin (saslpasswd2) + libsasl2-modules (PLAIN/LOGIN) + openssl (PKI de test).
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends postfix sasl2-bin libsasl2-modules openssl; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    useradd --system --no-create-home --shell /usr/sbin/nologin capture; \
    install -d -o capture -g capture -m 0755 /var/mail/captured

COPY --chmod=0644 main.cf master.cf /etc/postfix/
COPY --chmod=0644 smtpd.conf /etc/postfix/sasl/smtpd.conf
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0755 capture-mail.sh /usr/local/bin/capture-mail

VOLUME ["/var/mail/captured", "/pki"]
EXPOSE 587

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/587 && IFS= read -r -t 3 l <&3 && [[ $l == 220* ]]"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["postfix", "start-fg"]
