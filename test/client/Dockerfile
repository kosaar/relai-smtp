# syntax=docker/dockerfile:1
#
# TEST UNIQUEMENT — simule une application (GitLab, Jenkins, GLPI, YouTrack,
# inconnue) qui envoie des notifications au relai avec swaks (STARTTLS + AUTH).
ARG UBUNTU_TAG=resolute-20260927
FROM ubuntu:${UBUNTU_TAG}
# Un ARG déclaré avant FROM doit être redéclaré pour être visible ensuite.
ARG UBUNTU_TAG

LABEL org.opencontainers.image.title="smtp-relay-test-client" \
      org.opencontainers.image.description="Client SMTP de test (swaks) pour le relai" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:${UBUNTU_TAG}"

# swaks + Net::SSLeay (STARTTLS) + Authen::SASL (AUTH) + openssl (tests de
# version TLS) + python3 (construction de messages MIME de test).
ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends swaks libnet-ssleay-perl libauthen-sasl-perl \
        openssl ca-certificates python3; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    useradd --system --create-home --shell /usr/sbin/nologin app

COPY --chmod=0755 bin/ /usr/local/bin/

USER app
WORKDIR /home/app
CMD ["sleep", "infinity"]
