# smtp-relay

Relai SMTP applicatif **chiffrant** (Postfix sur Ubuntu 26.04 LTS) pour les
notifications des applications internes (GitLab CE, Jenkins, GLPI, YouTrack…) :

- soumission sur **`smtp-relay:587` en STARTTLS obligatoire**, un identifiant
  par application, liaison identifiant ↔ IP ↔ adresse expéditrice ;
- **chiffrement OpenPGP pour chaque destinataire avant la mise en file**
  (passerelle), objet neutre, en-têtes internes retirés, contrôle du contenu
  sortant ; sans clé validée, le destinataire est refusé (rien ne part en clair) ;
- **annuaire de clés publiques** (dépôt HTTPS, validation de l'empreinte par
  un administrateur, WKD, expiration, révocation) ;
- relais en **TLS ≥ 1.2 vérifié + SASL** vers le MTA du fournisseur ; lecture
  dans Thunderbird avec la clé privée du destinataire ;
- **supervision** (exporteur Prometheus : file, refus, clés, authentification,
  smarthost), journaux sans contenu, et **test après déploiement**
  (`relay-smoke-test`).

```bash
cp .env.example .env            # puis renseigner les valeurs <À PRÉCISER>
vi config/applications.toml     # applications autorisées (login, adresse, IP)
# créer les secrets (fournisseur, certificats, un mot de passe par application) : secrets/README.md
docker compose up -d --build --wait            # production
docker compose exec relay relay-smoke-test     # message de contrôle accepté par le smarthost
tests/run-tests.sh                             # tests d'intégration et de bout en bout locaux
tests/ci/lint.sh                               # contrôles statiques et tests unitaires
```

- Documentation technique : [docs/README.md](docs/README.md)
- Architecture (5 zones, flux F1 à F10) : [docs/architecture.md](docs/architecture.md)
- Mise en production (pare-feu, fournisseur, DNS, annuaire, Thunderbird, recette, exploitation) : [docs/deploiement-production.md](docs/deploiement-production.md)
- Plan d'implémentation : [docs/plan-implementation.md](docs/plan-implementation.md)
