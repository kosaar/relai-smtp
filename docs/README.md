# Relai SMTP applicatif : notifications des applications vers un fournisseur cloud

Ce relai centralise l'envoi des emails des applications internes (GitLab CE,
Jenkins, GLPI, YouTrack…). Chaque application :

- se connecte sur **`smtp-relay:587`**, en **STARTTLS obligatoire (TLS ≥ 1.2)** ;
- s'authentifie avec **son propre identifiant** (SASL) ;
- n'envoie que depuis **ses IP** déclarées et avec **son adresse** expéditrice.

Les messages sont contrôlés par une passerelle (milter) **avant** d'être mis en
file, puis transmis au MTA d'un fournisseur cloud (AWS SES, SendGrid, Mailjet,
Brevo…) en **TLS ≥ 1.2 vérifié avec authentification SASL**.

```
GitLab / Jenkins / GLPI / YouTrack ──587 STARTTLS + AUTH──▶ relai Postfix ──587/465 TLS + SASL──▶ fournisseur cloud
                                                              │  ▲
                                                     milter   ▼  │  (avant mise en file)
                                                           passerelle
```

> **Version 2 (en cours) :** le relai évolue vers un relai **chiffrant** (OpenPGP,
> annuaire de clés, quotas, contrôle du contenu), lot par lot, selon
> [plan-implementation.md](plan-implementation.md). Ce document décrit l'état
> actuel. Le schéma détaillé se trouve dans [architecture.md](architecture.md).
> Le guide [deploiement-production.md](deploiement-production.md) décrit encore
> la version 1 (port 25, liste blanche seule) ; il sera réécrit au lot 8.

> **Valeurs d'exemple :** fournisseur `smtp.example-provider.com:587`, GitLab
> `10.0.1.10`, Jenkins `10.0.1.20`, domaine `example.com`. Elles sont à remplacer
> (`<À PRÉCISER>` dans `.env.example` et `config/applications.toml`).

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Contenu du dépôt et images](#2-contenu-du-dépôt-et-images)
3. [Inventaire, variables et secrets](#3-inventaire-variables-et-secrets)
4. [Déploiement](#4-déploiement)
5. [Ajouter ou retirer une application](#5-ajouter-ou-retirer-une-application)
6. [Exploitation](#6-exploitation)
7. [Configuration des applications](#7-configuration-des-applications)
8. [Tests locaux](#8-tests-locaux)
9. [Sécurité](#9-points-de-sécurité)
10. [Dépannage](#10-dépannage)

---

## 1. Prérequis

- Docker Engine 24 ou plus récent et Docker Compose v2.24 ou plus récent (syntaxe `!reset` / `!override` utilisée par la stack de test).
- Un hôte du VLAN Services, joignable par les applications sur le port **587**.
- Un certificat pour le nom utilisé par les applications (ex. `smtp-relay.example.com`), émis par une autorité qu'elles reconnaissent (AC interne par exemple).
- Une sortie Internet vers le fournisseur sur le port 587 ou 465.
- Chez le fournisseur :
  - un compte SMTP (identifiant et mot de passe ou clé) ;
  - le **domaine d'expédition vérifié**, avec SPF, DKIM et DMARC publiés ;
  - les adresses expéditrices des applications autorisées (`gitlab@`, `jenkins@`…).
- Pour les tests : bash, et un accès aux dépôts Ubuntu (`archive.ubuntu.com`, `security.ubuntu.com`) pendant la construction des images.

## 2. Contenu du dépôt et images

```
docker-compose.yml        stack de production (services relay et gateway)
docker-compose.test.yml   surcharge de test (fournisseur simulé, poste destinataire, clients, relai à mauvais identifiants)
config/applications.toml  inventaire versionné des applications (login, adresse, IP, quota)
common/relaycfg/          module Python partagé : lecture et validation de l'inventaire, CLI relay-config
relay/Dockerfile          image du relai (contexte de construction : racine du dépôt)
relay/entrypoint.sh       validation de la configuration, génération de /etc/postfix, lancement
relay/config/*.tmpl       templates de main.cf, master.cf et de la configuration SASL
relay/scripts/            bibliothèque commune, healthcheck
gateway/                  passerelle (milter Python) appelée par Postfix avant la mise en file
test/provider/            fournisseur simulé (Postfix 587 TLS + SASL -> Dovecot IMAPS) et PKI de test
test/workstation/         poste destinataire simulé (RNP, GnuPG, relève IMAPS), test uniquement
test/client/              client swaks, test uniquement
secrets/                  emplacement des secrets (ignoré par git)
tests/run-tests.sh        orchestrateur des tests d'intégration et de bout en bout
tests/lib.sh              fonctions communes aux suites
tests/suites/NN-*.sh      une suite de tests par lot
tests/fixtures/           inventaire de la stack de test
tests/unit/               tests unitaires des modules Python purs
tests/ci/lint.sh          contrôles statiques (shellcheck, Python, tests unitaires)
.gitlab-ci.yml            CI : lint, relay-config check, tests d'intégration, publication des images
```

### Images Docker

Toutes les images partent de `ubuntu:resolute-20260927` (Ubuntu 26.04 LTS, tag
daté et épinglé ; les images Ubuntu officielles sont déjà minimales, il n'existe
pas de variante « slim »). Le tag est surchargeable avec `--build-arg UBUNTU_TAG=…`.

| Image | Paquets Ubuntu | Rôle |
|-------|----------------|------|
| `relay` | `postfix`, `libsasl2-modules` (PLAIN/LOGIN), `libsasl2-modules-db` et `sasl2-bin` (base SASL des applications), `python3` (`relay-config`), `ca-certificates` | relai de production |
| `gateway` | `python3`, `python3-milter` | passerelle de production (milter), exécutée sous un utilisateur non privilégié |
| `test/provider` | `postfix`, `sasl2-bin`, `libsasl2-modules`, `openssl` (PKI de test), `dovecot-imapd`, `dovecot-lmtpd` | simule le fournisseur (smarthost + BAL) |
| `test/workstation` | `rnp`, `gnupg`, `curl`, `openssl`, `python3` | simule le poste d'un destinataire (rôle de Thunderbird) |
| `test/client` | `swaks`, `libnet-ssleay-perl`, `libauthen-sasl-perl`, `openssl`, `python3` | simule une application (déclarée ou non) |

Bonnes pratiques appliquées dans les Dockerfiles :

- `--no-install-recommends` ;
- une seule couche `RUN` par étape logique ;
- `apt-get update`, installation et purge de `/var/lib/apt/lists` dans la même couche ;
- `DEBIAN_FRONTEND` passé en `ARG`, donc non persisté dans l'image ;
- labels OCI ;
- `HEALTHCHECK` (et `VOLUME` pour la file du relai) déclarés ;
- contexte de construction filtré par `.dockerignore` (ni `.git`, ni `secrets`, ni tests).

**Aucune configuration ni aucun secret n'est figé dans les images.**

### Entrypoint du relai (`relay/entrypoint.sh`)

1. **Inventaire.** `relay-config check` valide `config/applications.toml` et les secrets des applications (voir section 3). La moindre erreur arrête le conteneur (code 1) avec des lignes `FATAL: …`, toutes les erreurs étant listées ensemble.
2. **Reste de la configuration.** Certificat de soumission (lisible, clé correspondante), passerelle, fournisseur, niveau TLS, taille maximale, durée de file. Le relai ne démarre jamais en mode dégradé ou ouvert.
3. **Génération de `/etc/postfix`** (tmpfs, le système de fichiers racine est en lecture seule) :
   - `main.cf` et `master.cf` à partir des templates ;
   - `relay-config postfix` génère `sender_login_maps` (adresse → login), `mynetworks` (IP de l'inventaire, en `/32` ou `/128`) et la base SASL `sasl/sasldb2` (`root:postfix 0640`), **reconstruite à chaque démarrage** ;
   - `tls/submission.pem` (clé + chaîne, `0600`) ;
   - `sasl_passwd` (`root:root 0600`), identifiants du fournisseur.
4. **Démarrage.** `postfix check`, puis `exec postfix start-fg`. Postfix tourne en PID 1 et ses logs partent sur stdout.

### Passerelle (`gateway/`)

Postfix appelle la passerelle (`smtpd_milters = inet:gateway:9900`) pour chaque
message, **avant** de répondre `250 queued`. Elle lit l'inventaire et vérifie :

| Étape | Contrôle | Refus |
|-------|----------|-------|
| `MAIL FROM` | login SASL connu (`{auth_authen}`) | `550 5.7.1` |
| `MAIL FROM` | IP du client déclarée pour **ce** login (`client_ips`) | `550 5.7.1` (`client-ip-mismatch`) |
| `MAIL FROM` | enveloppe = adresse du login, expéditeur nul refusé | `553 5.7.1` / `550 5.7.1` |
| fin du message | un seul en-tête `From:`, une seule adresse, égale à celle du login ; le nom affiché ne contient pas une autre adresse | `550 5.7.1` (`from-mismatch`, `from-multiple`, `from-invalid`, `from-display-spoof`) |

Si la passerelle est arrêtée ou en erreur, Postfix répond `451` (erreur
temporaire, l'application réessaie) : `milter_default_action = tempfail`.
Les journaux de la passerelle ne contiennent que des métadonnées
(identifiant de file, IP, login, motif), jamais le contenu ni les en-têtes.

Les lots suivants y ajoutent les quotas, le contrôle du contenu et le
chiffrement OpenPGP.

### Paramètres Postfix clés

| Paramètre | Valeur | Pourquoi |
|-----------|--------|----------|
| `master.cf` | service `submission` (587) seul | **pas de port 25** ; services minimaux, `chroot = n` |
| `smtpd_tls_security_level` | `encrypt` | STARTTLS obligatoire : `530 5.7.0 Must issue a STARTTLS command first` sinon |
| `smtpd_tls_protocols`, `smtpd_tls_mandatory_protocols`, `smtpd_tls_ciphers` | `>=TLSv1.2`, `high` | TLS 1.0 et 1.1 refusés dès la poignée de main |
| `smtpd_tls_auth_only` | `yes` | AUTH n'est proposé qu'après STARTTLS : aucun mot de passe en clair |
| `smtpd_sasl_type`, `cyrus_sasl_config_path` | `cyrus`, `/etc/postfix/sasl` | base `sasldb2` générée depuis l'inventaire, mécanismes PLAIN et LOGIN |
| `smtpd_client_auth_rate_limit` | `RELAY_AUTH_RATE_LIMIT` (30/min) | limite les essais de mots de passe par IP (anvil), sans exception (`smtpd_client_event_limit_exceptions` vide) |
| `mynetworks` + `smtpd_client_restrictions` | IP de l'inventaire ; `permit_mynetworks, reject` | liste blanche IP en défense en profondeur : toute autre IP est refusée dès la bannière (`smtpd_delay_reject = no`), avant même l'authentification |
| `smtpd_sender_login_maps` + `reject_sender_login_mismatch` | `texthash:sender_login_maps` | `553 5.7.1 … not owned by user gitlab` si un login utilise l'adresse d'un autre ; `not logged in` sans authentification |
| `smtpd_relay_restrictions`, `smtpd_recipient_restrictions` | `permit_sasl_authenticated, reject` | être dans `mynetworks` **ne suffit pas** pour relayer |
| `smtpd_milters`, `milter_default_action` | `inet:gateway:9900`, `tempfail` | passerelle obligatoire avant la mise en file |
| `mydestination`, `relay_domains`, `local_transport = error` | vides / `error` | aucune réception entrante ni livraison locale |
| `disable_vrfy_command`, `smtpd_helo_required`, `smtpd_banner` | `yes`, `yes`, `$myhostname ESMTP` | pas d'énumération d'adresses, pas de version du logiciel exposée |
| `relayhost` | `[RELAY_HOST]:RELAY_PORT` | les crochets désactivent la recherche MX : on contacte exactement l'hôte indiqué |
| `smtp_tls_security_level` | `secure` (défaut) ou `encrypt` | TLS obligatoire vers le fournisseur ; `secure` vérifie en plus le certificat et le nom d'hôte |
| `smtp_tls_mandatory_protocols`, `smtp_tls_protocols` | `>=TLSv1.2` | TLS 1.0 et 1.1 interdits |
| `smtp_tls_wrappermode` | `yes` si le port est 465 | TLS implicite (SMTPS) ; STARTTLS sinon |
| `smtp_sasl_password_maps` | `texthash:/etc/postfix/sasl_passwd` | authentification auprès du fournisseur |
| `smtp_sasl_auth_soft_bounce` | `yes` | un refus d'authentification chez le fournisseur produit un report (le message reste en file) |
| `message_size_limit`, `maximal_queue_lifetime` | `MESSAGE_SIZE_LIMIT`, `QUEUE_LIFETIME` | taille maximale, rétention d'un message non délivrable |
| `maillog_file` | `/dev/stdout` | logs disponibles via `docker logs` |

## 3. Inventaire, variables et secrets

### Inventaire des applications (`config/applications.toml`)

Versionné : toute modification passe par une revue et par `relay-config check`
en CI. Le nom de la table est le **login SMTP** de l'application.

```toml
sender_domain = "example.com"      # domaine d'envoi vérifié chez le fournisseur

[defaults]
quota_per_hour = 200               # messages par heure glissante (appliqué au lot 5)

[applications.gitlab]
description = "GitLab : notifications"
address = "gitlab@example.com"     # seule adresse utilisable par le login « gitlab »
client_ips = ["10.0.1.10"]         # IP d'hôte, sans CIDR (IPv4 ou IPv6)
quota_per_hour = 500               # optionnel
```

Règles vérifiées (toutes les erreurs sont listées ensemble) : clés connues
uniquement ; nom en minuscules (`[a-z][a-z0-9-]`, 32 caractères au plus) ;
adresse dans `sender_domain` et attribuée à une seule application ; au moins
une IP d'hôte, ni CIDR, ni `0.0.0.0`, ni boucle locale, ni multicast ; quota
entier de 1 à 100 000 ; au moins une application.

```bash
PYTHONPATH=common python3 -m relaycfg check --inventory config/applications.toml
PYTHONPATH=common python3 -m relaycfg check --inventory config/applications.toml --secrets-dir secrets/apps
```

### Variables d'environnement (`.env`)

| Variable | Rôle | Défaut | Obligatoire |
|----------|------|--------|:-----------:|
| `RELAY_BIND_ADDRESS` | IP **privée** de l'hôte sur laquelle publier le port 587 (compose) | — | **oui** |
| `RELAY_PUBLISHED_PORT` | port publié sur l'hôte | `587` | non |
| `RELAY_HOSTNAME` | FQDN annoncé (`myhostname`, EHLO, realm SASL) | `relay.<sender_domain>` | non |
| `RELAY_AUTH_RATE_LIMIT` | tentatives d'authentification par IP et par minute | `30` | non |
| `RELAY_HOST` | MTA du fournisseur | — | **oui** |
| `RELAY_PORT` | `587` (STARTTLS) ou `465` (TLS implicite) | `587` | non |
| `RELAY_TLS_WRAPPERMODE` | `auto` (`yes` si le port est 465), `yes` ou `no` | `auto` | non |
| `RELAY_TLS_SECURITY_LEVEL` | `secure` (certificat vérifié) ou `encrypt` ; `may` et `none` sont refusés | `secure` | non |
| `RELAY_TLS_CA_FILE` | bundle des autorités de confiance pour le fournisseur | `/etc/ssl/certs/ca-certificates.crt` | non |
| `RELAY_SASL_MECHANISMS` | mécanismes SASL autorisés vers le fournisseur | `plain, login` | non |
| `MESSAGE_SIZE_LIMIT` | taille maximale d'un message, en octets | `10240000` | non |
| `QUEUE_LIFETIME` | durée de vie en file (`5d`, `12h`…) | `5d` | non |
| `RELAY_INET_PROTOCOLS` | `ipv4`, `ipv6` ou `all` | `ipv4` | non |
| `TZ` | fuseau horaire des logs | `UTC` | non |
| `RELAY_IMAGE_TAG` | tag des images construites | `2.0.0` | non |

Fixées dans `docker-compose.yml` : `RELAY_INVENTORY_FILE=/etc/relay/applications.toml`
(répertoire `config/` monté en lecture seule), `RELAY_APP_SECRETS_DIR=/run/secrets/apps`
(répertoire `secrets/apps/` monté en lecture seule), `RELAY_MILTER=inet:gateway:9900`.

### Secrets (`secrets/`, voir [secrets/README.md](../secrets/README.md))

| Secret | Fichier hôte | Rôle |
|--------|--------------|------|
| `relay_smtp_username`, `relay_smtp_password` | `secrets/relay_smtp_*` | identifiants chez le fournisseur |
| `relay_tls_cert`, `relay_tls_key` | `secrets/relay_tls_*` | certificat et clé de `smtp-relay` (port 587) |
| — | `secrets/apps/<application>` | mot de passe SMTP de chaque application (16 caractères minimum, une ligne) |

Ordre de lecture d'un secret `X` : le chemin indiqué par `X_FILE`, sinon
`/run/secrets/x`, sinon (identifiants du fournisseur seulement) la variable `X`
(repli `.env` déconseillé, signalé par un `WARNING`).

## 4. Déploiement

```bash
cp .env.example .env                    # renseigner les valeurs <À PRÉCISER>
vi config/applications.toml             # applications, adresses, IP
# secrets : voir secrets/README.md (fournisseur, certificat, un fichier par application)
PYTHONPATH=common python3 -m relaycfg check --secrets-dir secrets/apps --inventory config/applications.toml

docker compose up -d --build
docker compose ps                       # relay et gateway doivent afficher (healthy)
docker compose logs relay               # résumé de la configuration au démarrage
```

Les services sont configurés pour la production avec :

- `restart: unless-stopped` ;
- un système de fichiers racine en lecture seule, avec des tmpfs ;
- `cap_drop: ALL` ; le relai récupère les seules capacités nécessaires au processus maître Postfix (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `KILL`) ; la passerelle tourne sans aucune capacité, sous un utilisateur non privilégié ;
- `no-new-privileges`, des limites de CPU, de mémoire et de processus ;
- des logs en rotation (5 × 10 Mo) ;
- la file d'attente dans le volume nommé `relay-queue` ;
- relai et passerelle reliés par le réseau `backend` (`internal`, sans accès extérieur).

Test de bout en bout depuis le serveur d'une application déclarée :

```bash
swaks --server smtp-relay.example.com --port 587 --tls --tls-verify \
      --auth PLAIN --auth-user gitlab --auth-password "$(cat mot-de-passe-gitlab)" \
      --from gitlab@example.com --to vous@domaine.tld
```

**Mise à jour des images** (par exemple vers un nouveau tag Ubuntu daté) :
modifier `UBUNTU_TAG`, puis lancer `docker compose up -d --build`. La file
d'attente est conservée dans le volume.

## 5. Ajouter ou retirer une application

1. Ajoutez une table `[applications.<nom>]` dans `config/applications.toml`
   (adresse, IP, quota) et faites-la valider en revue (la CI exécute `relay-config check`).
2. Créez le secret `secrets/apps/<nom>` (voir [secrets/README.md](../secrets/README.md)).
3. Redémarrez : `docker compose restart gateway relay`.
4. Vérifiez : `docker compose logs relay | grep 'inventaire valide'`, puis
   configurez l'application (section 7).

Pendant le redémarrage (quelques secondes), les applications reçoivent une
erreur temporaire et réessaient. Les mails déjà en file sont conservés.

Pour **retirer** une application, supprimez sa table et son secret, puis
redémarrez : la base SASL étant reconstruite à chaque démarrage, son
identifiant cesse immédiatement de fonctionner, et son IP n'est plus admise.

**Rotation d'un mot de passe** : remplacez `secrets/apps/<nom>`, redémarrez le
relai (`docker compose restart relay`), puis mettez à jour l'application.

## 6. Exploitation

| Action | Commande |
|--------|----------|
| État et santé | `docker compose ps` |
| Logs en direct | `docker compose logs -f relay gateway` |
| Connexions refusées (IP non déclarées) | `docker compose logs relay \| grep 'Client host rejected'` |
| Échecs d'authentification | `docker compose logs relay \| grep 'authentication failed'` |
| Usurpations d'expéditeur | `docker compose logs relay \| grep 'not owned by user'` et `docker compose logs gateway \| grep reject` |
| Mails remis au fournisseur | `docker compose logs relay \| grep 'status=sent'` |
| Mails reportés (et la raison) | `docker compose logs relay \| grep 'status=deferred'` |
| Contenu de la file | `docker compose exec relay postqueue -p`, ou `postqueue -j` pour du JSON |
| Forcer un nouvel essai | `docker compose exec relay postqueue -f` |
| Supprimer un message | `docker compose exec relay postsuper -d <QUEUE_ID>` |
| Configuration effective | `docker compose exec relay postconf -n` |
| Vérifier l'inventaire dans le conteneur | `docker compose exec relay relay-config check` |

Exemples de lignes de log :

```
postfix/smtpd[12]: NOQUEUE: reject: CONNECT from unknown[10.0.1.30]: 554 5.7.1 <unknown[10.0.1.30]>: Client host rejected: Access denied; proto=SMTP
postfix/smtpd[12]: warning: gitlab[10.0.1.10]: SASL PLAIN authentication failed: authentication failure, sasl_username=gitlab
postfix/smtpd[12]: 3ED5FD2247: client=gitlab[10.0.1.10], sasl_method=PLAIN, sasl_username=gitlab
relay-gateway: reject cid=65 qid=A73FDD20E2 stage=data client=10.0.1.10 login=gitlab reason=from-mismatch code=550
postfix/smtp[45]: Verified TLS connection established to smtp.example-provider.com[x.x.x.x]:587: TLSv1.3 ...
postfix/smtp[45]: 3ED5FD2247: to=<dev@customer.test>, relay=smtp.example-provider.com[x.x.x.x]:587, ..., status=sent (250 Ok queued)
```

Pour la supervision (en attendant l'exporteur de métriques du lot 7), une
alerte peut se déclencher sur l'état `unhealthy` d'un conteneur, la croissance
de la file, ou des occurrences de `status=deferred`, `authentication failed`,
`Client host rejected`.

## 7. Configuration des applications

Chaque application parle au relai en **STARTTLS sur le port 587, avec son
identifiant**. Elle doit faire confiance à l'autorité qui a émis le certificat
de `smtp-relay` (AC interne). L'adresse expéditrice doit être exactement celle
de l'inventaire.

### GitLab CE (`/etc/gitlab/gitlab.rb`)

```ruby
gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "smtp-relay.example.com"
gitlab_rails['smtp_port'] = 587
gitlab_rails['smtp_domain'] = "example.com"
gitlab_rails['smtp_authentication'] = "plain"
gitlab_rails['smtp_user_name'] = "gitlab"
gitlab_rails['smtp_password'] = "<mot de passe de secrets/apps/gitlab>"
gitlab_rails['smtp_enable_starttls_auto'] = true
gitlab_rails['smtp_tls'] = false
gitlab_rails['smtp_openssl_verify_mode'] = 'peer'

gitlab_rails['gitlab_email_from'] = 'gitlab@example.com'
gitlab_rails['gitlab_email_display_name'] = 'GitLab'
gitlab_rails['gitlab_email_reply_to'] = 'gitlab@example.com'
```

Si l'AC interne n'est pas dans le magasin système du serveur GitLab, ajoutez
son certificat dans `/etc/gitlab/trusted-certs/`. Puis :

```bash
sudo gitlab-ctl reconfigure
sudo gitlab-rails runner "Notify.test_email('vous@domaine.tld', 'Test relai', 'OK').deliver_now"
```

### Jenkins

**Plugin Mailer** (*Administrer Jenkins → System → Notification par email*) :

- Serveur SMTP : `smtp-relay.example.com`, port `587` ;
- *Utiliser TLS* coché (STARTTLS), *Utiliser SSL* décoché ;
- authentification : utilisateur `jenkins`, mot de passe de `secrets/apps/jenkins` ;
- *Jenkins Location → Adresse email de l'administrateur système* : `Jenkins <jenkins@example.com>`.

**Plugin Email Extension** : mêmes valeurs (identifiants stockés dans un
*credential* Jenkins).

```yaml
unclassified:
  location:
    adminAddress: "Jenkins <jenkins@example.com>"
  mailer:
    smtpHost: "smtp-relay.example.com"
    smtpPort: "587"
    useSsl: false
    useTls: true
    authentication:
      username: "jenkins"
      password: "${JENKINS_SMTP_PASSWORD}"
```

L'AC interne doit être dans le magasin de confiance Java de Jenkins.

### GLPI, YouTrack et autres

Même principe : SMTP avec STARTTLS (« TLS », pas « SSL »), port 587,
authentification avec le login de l'inventaire, expéditeur égal à l'adresse
de l'inventaire.

## 8. Tests locaux

```bash
tests/run-tests.sh                # construit, démarre, teste, puis nettoie (docker compose down -v)
SUITES="00 01" tests/run-tests.sh # n'exécute que les suites choisies (préfixes numériques)
KEEP=1 tests/run-tests.sh         # conserve la stack pour l'inspecter
SKIP_BUILD=1 tests/run-tests.sh   # réutilise des images déjà construites (CI, registre interne)
tests/ci/lint.sh                  # contrôles statiques et tests unitaires (aussi exécutés par la CI)
```

Les suites `tests/suites/NN-*.sh` s'exécutent dans l'ordre sur une seule stack.
En cas d'échec, les journaux de tous les conteneurs sont copiés dans
`tests/.logs/` (conservés comme artefact par la CI).

Si Docker Hub limite le débit (HTTP 429) pendant la construction, le script
réessaie. L'image de base peut aussi être récupérée depuis un miroir puis
retaguée : `docker pull mirror.gcr.io/library/ubuntu:resolute-20260927 &&
docker tag mirror.gcr.io/library/ubuntu:resolute-20260927 ubuntu:resolute-20260927`.

Le script lance `docker compose -p smtp-relay-test --env-file tests/test.env
-f docker-compose.yml -f docker-compose.test.yml`. Le relai et la passerelle
testés sont donc **ceux de production**, surchargés uniquement par les
paramètres de test.

À chaque exécution, il génère dans `tests/.work/` (ignoré par git) des mots de
passe aléatoires (fournisseur, BAL, un par application) et une copie de
l'inventaire de test `tests/fixtures/applications.toml`. Le service one-shot
`pki` génère une AC de test et les certificats `provider`, `smtp-relay` et
`keydir` dans le volume `test-pki`. Aucun composant n'est simulé par un mock :
les messages sont soumis en STARTTLS (certificat vérifié) par swaks, livrés
par un vrai Postfix dans de vraies BAL Dovecot, et relus en IMAPS (certificat
vérifié) depuis le poste de travail.

| Composant | IP | Rôle |
|-----------|----|------|
| `client-gitlab`, `client-jenkins`, `client-glpi`, `client-youtrack` | 10.0.1.10, .20, .40, .45 | applications déclarées |
| `client-unknown` | 10.0.1.30 | IP **non** déclarée |
| `client-new` | 10.0.1.50 | application ajoutée en cours de test (IT1.10) |
| `relay` | 10.0.1.5 (alias `smtp-relay`) / 10.0.2.5 / 10.0.3.5 | relai avec identifiants valides |
| `relay-badcreds` | 10.0.1.6 / 10.0.2.6 / 10.0.3.6 | même image, mot de passe erroné chez le fournisseur |
| `gateway` | 10.0.3.20:9900 | passerelle (milter) |
| `provider` | 10.0.2.10:587 et :993 | fournisseur simulé : Postfix (STARTTLS obligatoire, SASL) qui livre en LMTP à Dovecot ; BAL `alice@`, `bob@`, `carol@example.com` et `ext@partner.test`, consultables en IMAPS |
| `workstation` | 10.0.2.50 | poste destinataire : relève les BAL en IMAPS (outil `mailbox`), RNP et GnuPG |

Les réseaux Docker de test (`private`, `internet`, `backend`) sont `internal`,
sans accès à Internet.

Vérifications automatiques (une ligne PASS/FAIL par test) :

| Test | Attendu |
|------|---------|
| T1/T2 | un message soumis par GitLab, puis par Jenkins, est **livré** dans la BAL d'alice et relu en IMAPS |
| T3a/b/c | depuis l'IP inconnue : connexion refusée `554 5.7.1`, rejet **tracé dans les logs** (IP + motif), aucun message en BAL |
| T4 | `Return-Path` et `From:` du message reçu valent l'adresse de l'application (plus de réécriture) |
| T5a–e | logs du relai : `Verified TLS connection established … TLSv1.x` et `status=sent` ; logs du fournisseur : `sasl_username=relay-test` ; en-tête `Received` : `using TLSv1.x` et `Authenticated sender` ; livraison LMTP tracée par Dovecot |
| T6a–d | avec de mauvais identifiants chez le fournisseur : `SASL authentication failed`, message **en file `deferred`**, non délivré, toujours présent après redémarrage |
| T8 | le healthcheck du relai est `healthy` |
| IT1.1 | GitLab, Jenkins, GLPI et YouTrack s'authentifient en STARTTLS (certificat vérifié) ; chaque message arrive dans la BAL |
| IT1.2 | sans STARTTLS : AUTH non proposé, `530 5.7.0`, aucun mot de passe envoyé en clair |
| IT1.3 | TLS 1.1 refusé à la poignée de main ; TLS 1.2 et 1.3 acceptés avec certificat vérifié |
| IT1.4 | mauvais mot de passe : `535 5.7.8`, échec journalisé (IP, login) |
| IT1.5 | sans authentification : refusé (`553`/`554 5.7.1`) |
| IT1.6 | `MAIL FROM` d'une autre application : `553 5.7.1` ; `From:` usurpé, doublé ou nom affiché trompeur : `550 5.7.1` ; rien de livré ; journaux sans contenu |
| IT1.7 | port 25 du relai : connexion refusée |
| IT1.8 | identifiants valides depuis une IP non déclarée (`554`) ou depuis l'IP d'une autre application (`550`) : refusé |
| IT1.9 | inventaire invalide (adresse en double, secret absent, adresse hors domaine, quota invalide) : relai et passerelle refusent de démarrer (`FATAL`) |
| IT1.10 | ajout d'une application (entrée + secret) puis redémarrage : elle envoie, les autres ne sont pas affectées |

**Nettoyage.** Il est automatique à la fin du script. Pour une stack conservée avec `KEEP=1` :

```bash
docker compose -p smtp-relay-test --env-file tests/test.env \
  -f docker-compose.yml -f docker-compose.test.yml down -v
rm -rf tests/.work
```

Les réseaux de test utilisent `10.0.1.0/24`, `10.0.2.0/24` et `10.0.3.0/24`.
En cas de conflit avec un réseau existant sur l'hôte, adaptez les
sous-réseaux et les IP dans `docker-compose.test.yml`, `tests/fixtures/` et
`tests/suites/`.

## 9. Points de sécurité

- **Pas d'open relay.** Relayer exige une authentification SASL ; aucun domaine local n'existe ; un inventaire vide ou invalide empêche le démarrage.
- **Trois verrous par application** : son mot de passe, ses IP (liste blanche globale dès la connexion, puis liaison login ↔ IP dans la passerelle) et son adresse (enveloppe dans Postfix, `From:` dans la passerelle). Un identifiant volé ne sert ni depuis une autre machine, ni pour usurper une autre application.
- **Aucun mot de passe en clair** : STARTTLS obligatoire avant AUTH, TLS ≥ 1.2. Essais limités par IP (`RELAY_AUTH_RATE_LIMIT`).
- **L'IP source doit être la vraie.** Le filtrage repose sur l'IP vue par Postfix.
  - Avec la publication de ports Docker standard (NAT iptables), l'IP du client est conservée.
  - Ne placez **pas** le relai derrière un proxy TCP ou un load balancer en mode proxy : Postfix verrait l'IP du proxy.
- **Exposition réseau.** Publiez le port 587 uniquement sur l'IP privée (`RELAY_BIND_ADDRESS`) et doublez ce filtrage d'un pare-feu (VLAN Applications → 587 uniquement ; sortie vers le fournisseur uniquement).
- **Secrets.** Fichiers montés en lecture seule, jamais dans l'image ni dans `docker inspect` ; `.env` et `secrets/*` sont ignorés par git ; dans le conteneur, base SASL `0640 root:postfix`, identifiants et clé TLS `0600 root`, sur tmpfs.
- **TLS vers le fournisseur.** `secure` vérifie la chaîne et le nom de l'hôte ; TLS 1.0 et 1.1 interdits, suites `high` uniquement.
- **Durcissement des conteneurs** : système de fichiers racine en lecture seule, capacités minimales (aucune pour la passerelle), `no-new-privileges`, limites de ressources, bannière sans version, `VRFY` désactivé.
- **Côté fournisseur** : domaine vérifié, SPF, DKIM et DMARC publiés, quotas et alertes de réputation surveillés.

## 10. Dépannage

| Symptôme | Cause probable / action |
|----------|-------------------------|
| Le relai ou la passerelle redémarre en boucle, `FATAL: …` dans les logs | Inventaire ou secret invalide (adresse en double ou hors domaine, secret absent ou trop court…), certificat illisible, variable manquante. Le message indique l'élément fautif ; `PYTHONPATH=common python3 -m relaycfg check --secrets-dir secrets/apps` le reproduit hors conteneur. |
| `554 5.7.1 … Client host rejected: Access denied` dès la connexion | L'IP source de l'application n'est pas dans l'inventaire. Comparez avec `connect from …[IP]` dans les logs (attention au NAT). |
| `530 5.7.0 Must issue a STARTTLS command first` | L'application n'active pas STARTTLS (cocher « TLS », pas « SSL »). |
| Échec de poignée de main TLS côté application | Le client ne fait pas confiance à l'AC du certificat de `smtp-relay`, utilise un autre nom que celui du certificat, ou est limité à TLS < 1.2. |
| `535 5.7.8 Error: authentication failed` | Mauvais login ou mot de passe ; le login est le nom de l'application dans l'inventaire. |
| `553 5.7.1 … not owned by user …` | L'application utilise une autre adresse que celle de l'inventaire (`MAIL FROM`). |
| `550 5.7.1 From: header must be …` | L'en-tête `From:` diffère de l'adresse de l'inventaire. |
| `550 5.7.1 This login is not allowed from this host` | Le login est utilisé depuis l'IP d'une autre application. |
| `451 4.7.1` ou `4.3.5` à la fin du message | Passerelle arrêtée ou injoignable : `docker compose ps gateway`, `docker compose logs gateway`. |
| `status=deferred … SASL authentication failed` | Identifiants du fournisseur erronés ou expirés. Vérifiez les secrets, puis `docker compose up -d` et `docker compose exec relay postqueue -f`. |
| `Server certificate not verified` | Nom de `RELAY_HOST` différent de celui du certificat du fournisseur, ou autorité absente du bundle (`RELAY_TLS_CA_FILE`). |
| `connect to …:587: Connection timed out` | Sortie bloquée par un pare-feu, ou DNS. Testez depuis l'hôte avec `nc -vz <RELAY_HOST> 587`. |
| `554 Message rejected: Email address is not verified` (fournisseur) | L'adresse de l'application ou le domaine n'est pas vérifié chez le fournisseur. |
| `552 5.3.4 Message size exceeds fixed limit` | Augmentez `MESSAGE_SIZE_LIMIT`, en respectant la limite du fournisseur. |
| `unhealthy` | `docker compose exec relay relay-healthcheck` ou `docker compose exec gateway gateway-healthcheck` affiche la cause. |
