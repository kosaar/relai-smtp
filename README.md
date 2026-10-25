# smtp-relay

Relai SMTP applicatif (Postfix sur Ubuntu 26.04 LTS) pour les notifications des
applications internes (GitLab CE, Jenkins, GLPI, YouTrack…) : soumission sur
**587 en STARTTLS obligatoire avec un identifiant par application**, liaison
identifiant ↔ IP ↔ adresse expéditrice contrôlée par une passerelle (milter)
avant la mise en file, puis relais en **TLS ≥ 1.2 vérifié + SASL** vers le MTA
d'un fournisseur cloud. Évolution en cours vers un relai chiffrant (OpenPGP) :
voir [docs/plan-implementation.md](docs/plan-implementation.md).

```bash
cp .env.example .env            # puis renseigner les valeurs <À PRÉCISER>
vi config/applications.toml     # applications autorisées (login, adresse, IP)
# créer les secrets (fournisseur, certificat, un mot de passe par application) : secrets/README.md
docker compose up -d --build    # production
tests/run-tests.sh              # tests d'intégration et de bout en bout locaux
```

- Documentation : [docs/README.md](docs/README.md)
- Architecture : [docs/architecture.md](docs/architecture.md)
- Plan d'implémentation : [docs/plan-implementation.md](docs/plan-implementation.md)
- Mise en production on-premise (Google Workspace / OVHcloud, version 1) : [docs/deploiement-production.md](docs/deploiement-production.md)
