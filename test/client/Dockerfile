# syntax=docker/dockerfile:1
#
# TEST UNIQUEMENT — simule une application (GitLab, Jenkins, inconnue) qui
# envoie des notifications au relai avec swaks.
ARG DEBIAN_TAG=trixie-20261005-slim
FROM debian:${DEBIAN_TAG}
# Un ARG déclaré avant FROM doit être redéclaré pour être visible ensuite.
ARG DEBIAN_TAG

LABEL org.opencontainers.image.title="smtp-relay-test-client" \
      org.opencontainers.image.description="Client SMTP de test (swaks) pour le relai" \
      org.opencontainers.image.base.name="docker.io/library/debian:${DEBIAN_TAG}"

ARG DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends swaks; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    useradd --system --create-home --shell /usr/sbin/nologin app

USER app
CMD ["sleep", "infinity"]
