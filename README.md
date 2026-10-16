# smtp-relay

Relai SMTP interne (Postfix sur Debian) pour les notifications CI/CD de GitLab CE
et Jenkins : liste blanche d'IP avec refus par défaut côté réseau privé, et
relais en **TLS ≥ 1.2 + SASL** vers le MTA d'un fournisseur cloud.

```bash
cp .env.example .env            # puis renseigner les valeurs <À PRÉCISER>
# créer secrets/relay_smtp_username et secrets/relay_smtp_password (voir secrets/README.md)
docker compose up -d --build    # production
tests/run-tests.sh              # tests d'intégration locaux
```

- Documentation : [docs/README.md](docs/README.md)
- Architecture : [docs/architecture.md](docs/architecture.md)
