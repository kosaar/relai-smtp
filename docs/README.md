# Relai SMTP applicatif : notifications des applications vers un fournisseur cloud

Ce relai centralise l'envoi des emails des applications internes (GitLab CE,
Jenkins, GLPI, YouTrack…). Chaque application :

- se connecte sur **`smtp-relay:587`**, en **STARTTLS obligatoire (TLS ≥ 1.2)** ;
- s'authentifie avec **son propre identifiant** (SASL) ;
- n'envoie que depuis **ses IP** déclarées et avec **son adresse** expéditrice.

Les messages sont contrôlés puis **chiffrés en OpenPGP pour leurs
destinataires** par une passerelle **avant** d'être mis en file : Postfix lui
relaie chaque transaction en temps réel (filtre avant file), et seul le message
chiffré revient dans la file. Rien n'est jamais écrit ni transmis en clair, et
les en-têtes extérieurs sont réduits au strict nécessaire. Un destinataire sans clé validée dans
l'annuaire est refusé. Les messages chiffrés sont transmis au MTA d'un
fournisseur cloud (AWS SES, SendGrid, Mailjet, Brevo…) en **TLS ≥ 1.2 vérifié
avec authentification SASL**, et lus dans Thunderbird avec la clé privée du
destinataire.

```
GitLab / Jenkins / GLPI / YouTrack ──587 STARTTLS + AUTH──▶ relai Postfix ──587/465 TLS + SASL──▶ fournisseur ──▶ BAL ──IMAPS──▶ Thunderbird
                                                              │  ▲                                                       (clé privée)
                                   milter + filtre avant file ▼  │  (réinjection du message chiffré)
                                                           passerelle ──HTTPS (WKD)──▶ annuaire de clés ◀──HTTPS (dépôt)── Thunderbird
```

> **Version 2 :** relai **chiffrant** (OpenPGP, annuaire de clés, contrôle du
> contenu, nettoyage des en-têtes, supervision, test après déploiement), réalisé
> lot par lot selon [plan-implementation.md](plan-implementation.md) ; les
> quotas par application (lot 5) ne sont pas réalisés. Ce document est la
> référence technique ; le schéma détaillé (5 zones, flux F1 à F10) se trouve
> dans [architecture.md](architecture.md) et la mise en production (réseau,
> fournisseur, annuaire, Thunderbird, recette, exploitation) dans
> [deploiement-production.md](deploiement-production.md).

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
docker-compose.yml        stack de production (services relay, gateway et keydir)
docker-compose.test.yml   surcharge de test (fournisseur simulé, poste destinataire, clients, relai à mauvais identifiants)
config/applications.toml  inventaire versionné des applications (login, adresse, IP, quota)
config/content-rules.toml règles versionnées du contrôle du contenu sortant (passerelle)
common/relaycfg/          module Python partagé : lecture et validation de l'inventaire, CLI relay-config
relay/Dockerfile          image du relai (contexte de construction : racine du dépôt)
relay/entrypoint.sh       validation de la configuration, génération de /etc/postfix, lancement
relay/config/*.tmpl       templates de main.cf, master.cf et de la configuration SASL
relay/scripts/            bibliothèque commune, healthcheck
relay/exporter/relayexp/  processus principal relay-run (Postfix + journaux), exporteur Prometheus, relay-smoke-test
gateway/                  passerelle Python appelée par Postfix avant la mise en file (milter + filtre SMTP)
keydir/                   annuaire de clés publiques OpenPGP (dépôt HTTPS, validation, WKD, révocations)
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
.gitlab-ci.yml            CI/CD : lint, inventaire et règles, tests d'intégration, images, déploiement + relay-smoke-test
```

### Images Docker

Toutes les images partent de `ubuntu:resolute-20260927` (Ubuntu 26.04 LTS, tag
daté et épinglé ; les images Ubuntu officielles sont déjà minimales, il n'existe
pas de variante « slim »). Le tag est surchargeable avec `--build-arg UBUNTU_TAG=…`.

| Image | Paquets Ubuntu | Rôle |
|-------|----------------|------|
| `relay` | `postfix`, `libsasl2-modules` (PLAIN/LOGIN), `libsasl2-modules-db` et `sasl2-bin` (base SASL des applications), `python3` (`relay-config`, `relay-run`, exporteur de métriques), `ca-certificates` | relai de production |
| `gateway` | `python3`, `python3-milter`, `gpg` (chiffrement, clés publiques seulement), `ca-certificates` | passerelle de production (milter et filtre avant file), exécutée sous un utilisateur non privilégié |
| `keydir` | `python3` (serveur HTTPS, SQLite), `gpg` (lecture des clés publiques) | annuaire de clés de production, exécuté sous un utilisateur non privilégié |
| `test/provider` | `postfix`, `sasl2-bin`, `libsasl2-modules`, `openssl` (PKI de test), `dovecot-imapd`, `dovecot-lmtpd` | simule le fournisseur (smarthost + BAL) |
| `test/workstation` | `rnp`, `gnupg`, `gpg-wks-client`, `curl`, `openssl`, `python3` | simule le poste d'un destinataire (rôle de Thunderbird) : outils `mailbox` (IMAPS) et `keys` (clés RNP, annuaire) |
| `test/client` | `swaks`, `libnet-ssleay-perl`, `libauthen-sasl-perl`, `openssl`, `python3` | simule une application (déclarée ou non) ; outil `mkmsg` (messages MIME avec pièces jointes binaires et manifeste SHA-256) |

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
2. **Reste de la configuration.** Certificat de soumission (lisible, clé correspondante), passerelle (son adresse est résolue au démarrage : le port de réinjection n'accepte qu'elle), fournisseur, niveau TLS, taille maximale, durée de file, exporteur de métriques. Le relai ne démarre jamais en mode dégradé ou ouvert.
3. **Génération de `/etc/postfix`** (tmpfs, le système de fichiers racine est en lecture seule) :
   - `main.cf` et `master.cf` à partir des templates ;
   - `relay-config postfix` génère `sender_login_maps` (adresse → login), `mynetworks` (IP de l'inventaire, en `/32` ou `/128`) et la base SASL `sasl/sasldb2` (`root:postfix 0640`), **reconstruite à chaque démarrage** ;
   - `tls/submission.pem` (clé + chaîne, `0600`) ;
   - `sasl_passwd` (`root:root 0600`), identifiants du fournisseur.
4. **Démarrage.** `postfix check`, puis `exec relay-run -- postfix start-fg`. `relay-run` (PID 1) lance Postfix au premier plan, recopie ses logs sur stdout (inchangés, `docker logs`) et en transmet une copie à l'exporteur de métriques, qu'il lance sous `nobody` et relance s'il s'arrête. La copie est non bloquante : un exporteur lent ou arrêté ne retarde jamais les logs ni le courrier. `relay-run` relaie `SIGTERM` au processus maître Postfix et se termine avec son code.

### Passerelle (`gateway/`)

La passerelle est appelée par Postfix de deux façons, **avant** toute écriture
dans la file :

- **milter** (`smtpd_milters = inet:gateway:9900`) : contrôles de l'enveloppe,
  au `MAIL FROM` et à chaque `RCPT TO` ;
- **filtre avant file** (`smtpd_proxy_filter = gateway:10025`) : Postfix lui
  relaie la transaction en temps réel, sans rien écrire ; la passerelle chiffre
  le message et le **réinjecte** dans le relai (port `10026`, sur le réseau
  backend, ouvert à la seule IP de la passerelle), puis rend à l'application
  la réponse de la réinjection (`250 … queued as …`).

Un milter ne suffit pas pour le chiffrement : Postfix écrit le message dans la
file pendant la réception et, quand un milter remplace le corps ou supprime un
en-tête, l'ancien enregistrement n'est qu'en partie écrasé (des fragments en
clair restent dans le fichier ; vérifié par IT3.11c).

| Étape | Contrôle | Refus |
|-------|----------|-------|
| `MAIL FROM` (milter) | login SASL connu (`{auth_authen}`) | `550 5.7.1` |
| `MAIL FROM` (milter) | IP du client déclarée pour **ce** login (`client_ips`) | `550 5.7.1` (`client-ip-mismatch`) |
| `MAIL FROM` (milter) | enveloppe = adresse du login, expéditeur nul refusé | `553 5.7.1` / `550 5.7.1` |
| `RCPT TO` (milter) | clé OpenPGP **valide** du destinataire, lue dans le WKD de l'annuaire (HTTPS vérifié, cache `GATEWAY_KEY_CACHE_TTL`) : ni absente, ni expirée, ni révoquée, avec une sous-clé de chiffrement | `550 5.7.1 No valid OpenPGP key` **pour ce destinataire** (`no-key`, `key-expired`, `key-revoked`, `key-unusable`) ; annuaire injoignable : `451 4.7.1` |
| fin du message (filtre) | IP du client (transmise par `XFORWARD`) déclarée pour l'application de l'enveloppe | `550 5.7.1` |
| fin du message (filtre) | un seul en-tête `From:`, une seule adresse, égale à celle de l'application ; le nom affiché ne contient pas une autre adresse | `550 5.7.1` (`from-mismatch`, `from-multiple`, `from-invalid`, `from-display-spoof`) |
| fin du message (filtre) | **contrôle du contenu** décodé (voir ci-dessous) | `550 5.7.1 Message blocked by content policy (rule <id>)` |
| fin du message (filtre) | **chiffrement** PGP/MIME pour tous les destinataires acceptés, en-têtes extérieurs nettoyés (voir ci-dessous), réinjection | erreur interne : `451 4.7.1` ; réinjection impossible : `451 4.3.0` |

La file de Postfix ne contient que du chiffré, y compris octet par octet dans
le fichier brut. Chaque refus est un échec fermé : jamais d'envoi en clair,
jamais d'entrée de cache expirée réutilisée quand l'annuaire est injoignable.
Si la passerelle est arrêtée, Postfix répond par une erreur temporaire
(`454 4.3.0`, `milter_default_action = tempfail`) et l'application réessaie.
Les journaux de la passerelle ne contiennent que des métadonnées (identifiant
de file, IP, login, destinataire, motif, tailles), jamais le contenu ni les
en-têtes.

La passerelle démarre en root le temps de copier `gateway_hmac_key` dans un
tmpfs lisible par son seul utilisateur, puis s'exécute sous l'utilisateur
`gateway`, sans aucune capacité. Elle refuse de démarrer (`FATAL`) si
l'inventaire, l'annuaire, la clé HMAC (32 caractères minimum) ou un port sont
invalides.

**Format chiffré** (PGP/MIME, RFC 3156, lu par Thunderbird) :

```
Subject: Message chiffré                      <- objet extérieur neutre (GATEWAY_NEUTRAL_SUBJECT)
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"
  ├─ application/pgp-encrypted                (Version: 1)
  └─ application/octet-stream (encrypted.asc) <- message OpenPGP (GnuPG)
       └─ multipart/mixed; protected-headers="v1"
            Subject / From / To / Message-ID / X-GitLab-* / Received…  <- TOUS les en-têtes d'origine (protégés)
            └─ entité MIME d'origine, intacte (texte, pièces jointes)
```

- un seul message chiffré par transaction, pour tous ses destinataires ;
- identifiants de clés **masqués** (`--throw-keyids`) quand il n'y a qu'un
  destinataire ; **visibles** quand il y en a plusieurs, car RNP (la
  bibliothèque OpenPGP de Thunderbird) n'essaie que le premier destinataire
  masqué : chaque destinataire voit alors l'identifiant des sous-clés des
  autres, y compris d'un destinataire en copie cachée ;
- la limite annoncée aux applications reste `MESSAGE_SIZE_LIMIT` ; le chiffré
  peut atteindre 1,5 × cette taille en file (armure ASCII) : la limite du
  fournisseur doit le permettre.

**En-têtes extérieurs** (D9), seuls visibles du fournisseur et des serveurs
intermédiaires : une liste blanche, `From`, `To`, `Cc`, `Date`, `Subject`
(neutre), `MIME-Version`, `Content-Type`, `Message-ID`, `In-Reply-To`,
`References`, `Reply-To`, `Auto-Submitted`. Tous les autres (`X-GitLab-*`,
`X-Jenkins-*`, `X-Mailer`, `User-Agent`, `Received` d'origine…) n'existent plus
que dans la partie chiffrée.

- `Message-ID`, `In-Reply-To` et `References` sont **pseudonymisés** :
  `<HMAC-SHA256(clé, identifiant)[:32]@sender_domain>`, avec la clé secrète
  `gateway_hmac_key`. Le nom d'hôte interne disparaît ; un même identifiant
  donne toujours le même pseudonyme, donc les fils de discussion restent
  regroupés dans Thunderbird (au-delà de 10 références : la première et les
  9 dernières). Un `Message-ID` absent ou invalide est remplacé par un
  identifiant aléatoire.
- Le `Received` ajouté par le relai (nom et IP de l'application) est retiré
  en sortie (`smtp_header_checks`).

Changer `gateway_hmac_key` change tous les pseudonymes : les fils en cours
sont alors coupés en deux dans Thunderbird.

**Contrôle du contenu** (D8), avant chiffrement, selon les règles versionnées
`config/content-rules.toml` (modifiées par revue de code, comme l'inventaire).
Elles s'appliquent au texte **décodé** : en-têtes (RFC 2047), corps et
pièces jointes (base64 et quoted-printable décodés), messages attachés. Les
archives (zip…) ne sont pas ouvertes.

| Règle | Bloque |
|-------|--------|
| `private-key` | bloc `-----BEGIN … PRIVATE KEY-----` (PEM, OpenSSH, `PGP PRIVATE KEY BLOCK`) |
| `gitlab-token`, `github-token`, `aws-access-key`, `slack-token` | jetons reconnaissables (`glpat-…`, `ghp_…`, `AKIA…`, `xoxb-…`) |
| `forbidden-extension` | pièce jointe exécutable ou script (`.exe`, `.bat`, `.js`, `.ps1`, `.jar`…, dernière extension du nom) |
| `attachment-too-big` | pièce jointe décodée plus grande que `max_size` (désactivé par défaut) |

Le refus (`550 5.7.1`) et le journal (`reason=content:<règle>`) ne portent
que l'identifiant de la règle, jamais le contenu trouvé. Un fichier de règles
absent ou invalide (regex incorrecte, identifiant en double, clé inconnue)
empêche la passerelle de démarrer ; les tests unitaires (CI) valident le
fichier de production.

Les quotas par application (lot 5) n'ont pas été réalisés : `quota_per_hour`
est validé dans l'inventaire mais n'est pas appliqué.

### Annuaire de clés (`keydir/`)

Service HTTPS (TLS ≥ 1.2 uniquement ; seul le port interne des métriques, non
publié, est en HTTP) qui conserve les clés
publiques des destinataires (SQLite, volume `keydir-data`) :

| Requête | Rôle |
|---------|------|
| `POST /api/v1/keys?email=<adresse>` | dépôt d'une clé publique (armure ASCII ou binaire) : `202`, état **en attente** ; ou d'un certificat de révocation : appliqué **immédiatement** (`200`) ; refus motivé : `422` |
| `GET /api/v1/keys/<adresse>` | état : `none`, `pending`, `approved`, `revoked` (JSON) |
| `GET /.well-known/openpgpkey/<domaine>/hu/<hachage>` | **WKD** (méthode avancée) : clé validée, réduite à l'identité de l'adresse, lue par GnuPG, Thunderbird et la passerelle |
| `GET /.well-known/openpgpkey/<domaine>/policy` | fichier de politique WKD |

Contrôles au dépôt : un seul certificat ; non expiré, non révoqué ; une identité
(UID) portant exactement l'adresse ; domaine géré (`KEYDIR_DOMAINS`) ; une
sous-clé de chiffrement valide ; algorithmes RSA ≥ 3072 ou Ed25519/Cv25519
(X25519 en clé v6). La clé RSA 2048 générée par défaut par RNP est refusée :
générer une clé Ed25519/Cv25519 (choix par défaut de Thunderbird) ou RSA 3072.

Une clé n'est publiée qu'après validation par un administrateur, qui compare
l'empreinte **hors bande** avec le destinataire (téléphone, en personne) :

```bash
docker compose exec keydir keydir-admin list --state pending
docker compose exec keydir keydir-admin show alice@example.com
docker compose exec keydir keydir-admin approve alice@example.com <EMPREINTE>   # refusé si l'empreinte diffère
docker compose exec keydir keydir-admin reject alice@example.com <EMPREINTE>
docker compose exec keydir keydir-admin revoke alice@example.com    # révocation administrative (clé dépubliée)
docker compose exec keydir keydir-admin remove alice@example.com    # suppression (RGPD)
docker compose exec keydir keydir-admin audit
```

- **Rotation** : la nouvelle clé déposée reste en attente, l'ancienne est servie
  jusqu'à la validation de la nouvelle, qui la remplace (état `superseded`).
- **Révocation** par certificat (exporté depuis Thunderbird ou RNP) : appliquée
  sans validation, la clé révoquée restant publiée pour que les clients
  l'apprennent ; elle ne peut plus être utilisée pour chiffrer.
- **Journal d'audit** (dépôts, refus, validations, révocations, suppressions) :
  métadonnées seulement, purgé au-delà de `KEYDIR_AUDIT_RETENTION_DAYS` jours.

### Supervision (exporteur Prometheus)

Le relai expose ses métriques sur `http://<hôte>:9154/metrics` (publié par
défaut sur `127.0.0.1` de l'hôte ; `RELAY_METRICS_BIND_ADDRESS` pour un
Prometheus du VLAN de supervision). L'exporteur s'exécute sous `nobody`, sans
capacité, et ne lit que des métadonnées :

- les **logs Postfix**, que `relay-run` lui transmet ;
- la **file**, avec `postqueue -j` (groupe `postdrop`) ;
- le **smarthost**, par une connexion TLS périodique : EHLO, STARTTLS et QUIT, sans authentification ni message ;
- les **métriques de l'annuaire**, lues sur son port interne 9155 (réseau `backend`, non publié) et recopiées : Prometheus n'a qu'une cible.

| Métrique | Signification |
|----------|---------------|
| `relay_queue_messages{queue}` | messages en file (`active`, `deferred`, `hold`, `incoming`, `maildrop`) |
| `relay_queue_oldest_message_age_seconds` | âge du plus ancien message en file (0 si vide) |
| `relay_rejects_total{app,reason,class}` | refus par application (login SASL, sinon adresse, sinon IP) et motif : `no_key`, `keydir_unavailable`, `content`, `client_host`, `client_ip_mismatch`, `envelope_sender`, `header_from`, `auth_required`, `size`, `gateway_unavailable`, `encryption_error`… ; `class` = `permanent` (5xx) ou `temporary` (4xx) |
| `relay_nokey_rejects_total{recipient}` | destinataires refusés faute de clé valide (1000 adresses au plus, au-delà `other`) |
| `relay_auth_failures_total{app}` | échecs d'authentification SASL, par application d'après l'IP du client |
| `relay_content_blocks_total{app,rule}` | messages bloqués par le contrôle du contenu, par règle |
| `relay_deliveries_total{app,status}` | tentatives de livraison au smarthost : `sent`, `deferred`, `bounced`, `expired` |
| `relay_deferrals_total{app,reason}` | différés par motif : `auth`, `tls`, `dns`, `connection`, `remote_temporary`, `other` |
| `relay_smarthost_up`, `relay_smarthost_tls_verified` | smarthost joignable en TLS ; certificat valide pour l'AC (`RELAY_TLS_CA_FILE`) et le nom configurés |
| `relay_smarthost_certificate_expiry_timestamp_seconds` | expiration du certificat du smarthost (lue même si le certificat est refusé) |
| `keydir_keys_expiring_soon`, `keydir_key_expiring_soon{email}` | clés publiées expirant dans `KEYDIR_EXPIRY_WARNING_DAYS` jours (30) |
| `keydir_keys_expired`, `keydir_key_expired{email}` | clés publiées expirées (destinataires refusés) |
| `keydir_keys_revoked`, `keydir_key_revoked{email}` | adresses dont la clé est révoquée, sans clé de remplacement validée |
| `keydir_keys{state}`, `keydir_key_expiry_timestamp_seconds{email}` | clés par état (dont `pending` : en attente de validation) ; expiration de chaque clé publiée |
| `relay_queue_scrape_ok`, `relay_keydir_metrics_up` | lecture de la file et de l'annuaire réussie |

L'exporteur sert aussi `GET /delivery?qid=<QUEUE_ID>` : dernier résultat de
livraison connu du message (`{"qid", "status", "reason"}`, sans adresse ;
`404` si inconnu), conservé pour les 5000 derniers messages ; il est utilisé
par `relay-smoke-test`.

Exemples d'alertes (PromQL) :

```
relay_queue_oldest_message_age_seconds > 3600          # messages bloqués depuis plus d'une heure
relay_smarthost_up == 0 or relay_smarthost_tls_verified == 0
relay_smarthost_certificate_expiry_timestamp_seconds - time() < 14 * 86400
increase(relay_auth_failures_total[15m]) > 10          # essais de mots de passe
increase(relay_content_blocks_total[1h]) > 0           # une application tente d'envoyer un secret
keydir_keys_expiring_soon > 0 or keydir_keys_expired > 0
keydir_keys{state="pending"} > 0                       # clé à valider
relay_keydir_metrics_up == 0
```

Les métriques ne contiennent ni objet ni corps. Elles portent les adresses
des destinataires refusés et des clés à surveiller (données personnelles des
destinataires internes) : n'ouvrir le port qu'au serveur Prometheus et aligner
sa rétention sur celle des logs.

### Paramètres Postfix clés

| Paramètre | Valeur | Pourquoi |
|-----------|--------|----------|
| `master.cf` | service `submission` (587) pour les applications, port de réinjection (`RELAY_REINJECT_PORT`, 10026) sur l'adresse backend | **pas de port 25** ; services minimaux, `chroot = n` |
| `smtpd_tls_security_level` | `encrypt` | STARTTLS obligatoire : `530 5.7.0 Must issue a STARTTLS command first` sinon |
| `smtpd_tls_protocols`, `smtpd_tls_mandatory_protocols`, `smtpd_tls_ciphers` | `>=TLSv1.2`, `high` | TLS 1.0 et 1.1 refusés dès la poignée de main |
| `smtpd_tls_auth_only` | `yes` | AUTH n'est proposé qu'après STARTTLS : aucun mot de passe en clair |
| `smtpd_sasl_type`, `cyrus_sasl_config_path` | `cyrus`, `/etc/postfix/sasl` | base `sasldb2` générée depuis l'inventaire, mécanismes PLAIN et LOGIN |
| `smtpd_client_auth_rate_limit` | `RELAY_AUTH_RATE_LIMIT` (30/min) | limite les essais de mots de passe par IP (anvil), sans exception (`smtpd_client_event_limit_exceptions` vide) |
| `mynetworks` + `smtpd_client_restrictions` | IP de l'inventaire ; `permit_mynetworks, reject` | liste blanche IP en défense en profondeur : toute autre IP est refusée dès la bannière (`smtpd_delay_reject = no`), avant même l'authentification |
| `smtpd_sender_login_maps` + `reject_sender_login_mismatch` | `texthash:sender_login_maps` | `553 5.7.1 … not owned by user gitlab` si un login utilise l'adresse d'un autre ; `not logged in` sans authentification |
| `smtpd_relay_restrictions`, `smtpd_recipient_restrictions` | `permit_sasl_authenticated, reject` | être dans `mynetworks` **ne suffit pas** pour relayer |
| `smtpd_milters`, `milter_default_action` | `inet:gateway:9900`, `tempfail` | contrôles d'enveloppe de la passerelle obligatoires |
| `smtpd_proxy_filter` (service 587) | `gateway:10025` | contenu relayé en temps réel à la passerelle, qui chiffre puis réinjecte : rien n'est écrit en clair |
| port de réinjection | `mynetworks` = IP de la passerelle, sans milter ni filtre, `message_size_limit` = 1,5 × `MESSAGE_SIZE_LIMIT` | seuls les messages chiffrés de la passerelle entrent dans la file |
| `smtp_header_checks` | `/^Received:/ IGNORE` | le `Received` ajouté par le relai ne sort pas |
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
quota_per_hour = 200               # messages par heure (validé, non appliqué : lot 5 non réalisé)

[applications.gitlab]
description = "GitLab : notifications"
address = "gitlab@example.com"     # seule adresse utilisable par le login « gitlab »
client_ips = ["10.0.1.10"]         # IP d'hôte, sans CIDR (IPv4 ou IPv6)
quota_per_hour = 500               # optionnel
```

Règles vérifiées (toutes les erreurs sont listées ensemble) : clés connues
uniquement ; nom en minuscules (`[a-z][a-z0-9-]`, 32 caractères au plus) ;
adresse dans `sender_domain` et attribuée à une seule application ; au moins
une IP d'hôte, ni CIDR, ni `0.0.0.0`, ni multicast ; quota entier de 1 à
100 000 ; au moins une application. Une adresse de bouclage n'est admise que
sous la forme `127.0.0.1` (ou `::1`) et comme **seule** IP d'une application :
celle-ci est alors locale au conteneur du relai, son login n'étant utilisable
que depuis le relai lui-même (application `supervision` de `relay-smoke-test`).

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
| `GATEWAY_KEYDIR_CA_FILE` | autorité(s) de confiance pour le certificat de l'annuaire, vue de la passerelle | `/etc/ssl/certs/ca-certificates.crt` | non |
| `GATEWAY_KEY_CACHE_TTL` | durée de cache des clés (et des absences de clé) dans la passerelle, en secondes ; délai maximal de prise en compte d'une révocation | `300` | non |
| `GATEWAY_NEUTRAL_SUBJECT` | objet extérieur des messages chiffrés | `Message chiffré` | non |
| `BACKEND_SUBNET`, `GATEWAY_BACKEND_IP` | sous-réseau interne relai ↔ passerelle ↔ annuaire, et adresse fixe de la passerelle (seule autorisée à réinjecter) | `172.30.53.0/24`, `172.30.53.20` | non |
| `KEYDIR_BIND_ADDRESS` | IP **privée** de l'hôte sur laquelle publier l'annuaire (compose) | — | **oui** |
| `KEYDIR_PUBLISHED_PORT` | port HTTPS publié sur l'hôte | `443` | non |
| `KEYDIR_DOMAINS` | domaines dont l'annuaire publie les clés (séparés par des espaces) | — | **oui** |
| `KEYDIR_AUDIT_RETENTION_DAYS` | durée de conservation du journal d'audit de l'annuaire, en jours | `365` | non |
| `KEYDIR_EXPIRY_WARNING_DAYS` | seuil « proche de l'expiration » des clés (métriques), en jours | `30` | non |
| `RELAY_METRICS_BIND_ADDRESS` | IP de l'hôte sur laquelle publier les métriques (compose) | `127.0.0.1` | non |
| `RELAY_METRICS_PUBLISHED_PORT` | port des métriques publié sur l'hôte | `9154` | non |
| `RELAY_METRICS_PROBE_INTERVAL` | intervalle de la sonde TLS du smarthost, en secondes (5 à 86400) | `300` | non |
| `RELAY_SMOKE_TO` | BAL de supervision, destinataire du message de contrôle de `relay-smoke-test` (clé validée sur l'annuaire) | — | pour `relay-smoke-test` |

Fixées dans `docker-compose.yml` : `RELAY_INVENTORY_FILE=/etc/relay/applications.toml`,
`GATEWAY_CONTENT_RULES_FILE=/etc/relay/content-rules.toml`
(répertoire `config/` monté en lecture seule), `RELAY_APP_SECRETS_DIR=/run/secrets/apps`
(répertoire `secrets/apps/` monté en lecture seule), `RELAY_MILTER=inet:gateway:9900`,
`RELAY_PROXY_FILTER=gateway:10025`, `RELAY_REINJECT_PORT=10026` (relai),
`GATEWAY_PROXY_LISTEN=0.0.0.0:10025`, `GATEWAY_REINJECT_PORT=10026` (passerelle),
`RELAY_KEYDIR_METRICS_URL=http://keydir:9155/metrics` (relai, vide = désactivé),
`KEYDIR_METRICS_LISTEN=0.0.0.0:9155` (annuaire, vide = désactivé). Valeurs par
défaut dans l'image : `RELAY_METRICS_ENABLED=yes`, `RELAY_METRICS_LISTEN=0.0.0.0:9154`.

### Secrets (`secrets/`, voir [secrets/README.md](../secrets/README.md))

| Secret | Fichier hôte | Rôle |
|--------|--------------|------|
| `relay_smtp_username`, `relay_smtp_password` | `secrets/relay_smtp_*` | identifiants chez le fournisseur |
| `relay_tls_cert`, `relay_tls_key` | `secrets/relay_tls_*` | certificat et clé de `smtp-relay` (port 587) |
| `keydir_tls_cert`, `keydir_tls_key` | `secrets/keydir_tls_*` | certificat et clé de l'annuaire : SAN `openpgpkey.<domaine>` (postes, WKD) et `keydir` (nom interne vérifié par la passerelle, AC désignée par `GATEWAY_KEYDIR_CA_FILE`, par exemple `config/ca-interne.pem` vu en `/etc/relay/ca-interne.pem`) |
| `gateway_hmac_key` | `secrets/gateway_hmac_key` | clé de pseudonymisation des identifiants de message (32 caractères minimum) |
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
docker compose ps                       # relay, gateway et keydir doivent afficher (healthy)
docker compose logs relay               # résumé de la configuration au démarrage
docker compose exec relay relay-smoke-test   # message de contrôle accepté par le smarthost (code 0)
```

`relay-smoke-test` est le test après déploiement (exécuté aussi par le job
`deploy` de la CI) : il soumet, depuis le conteneur du relai, un message de
contrôle de l'application locale `supervision` vers `RELAY_SMOKE_TO`, par le
chemin réel (587 en STARTTLS, passerelle, annuaire, chiffrement, file), puis
attend que l'exporteur ait vu sa livraison au smarthost
(`GET /delivery?qid=…`). Le message arrive chiffré dans la BAL de
supervision, dont la clé est validée sur l'annuaire comme celle de tout
destinataire.

| Code | Signification |
|:----:|---------------|
| 0 | message accepté par le smarthost (`status=sent`) |
| 1 | échec : refus à la soumission (réponse SMTP affichée), livraison différée (motif : `auth`, `tls`, `dns`, `connection`…), rejetée ou expirée |
| 2 | configuration invalide : application absente ou non locale, secret illisible, `RELAY_SMOKE_TO` vide |
| 3 | non confirmé dans le délai (`--timeout`, 60 s) : exporteur injoignable ou file lente ; l'état du message en file est affiché |

```
relay-smoke-test : supervision@example.com -> supervision@example.com (application supervision, 127.0.0.1:587), objet « Contrôle du relai SMTP 24723027a6af »
  soumis et chiffré : 250 2.0.0 Ok: queued as E16D9A4054
OK : message de contrôle E16D9A4054 : accepté par le smarthost (status=sent)
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
| Métriques (depuis l'hôte) | `curl -s http://127.0.0.1:9154/metrics` |
| Test de bout en bout (message de contrôle) | `docker compose exec relay relay-smoke-test` |
| Résultat de livraison d'un message | `curl -s 'http://127.0.0.1:9154/delivery?qid=<QUEUE_ID>'` |

Exemples de lignes de log :

```
postfix/smtpd[12]: NOQUEUE: reject: CONNECT from unknown[10.0.1.30]: 554 5.7.1 <unknown[10.0.1.30]>: Client host rejected: Access denied; proto=SMTP
postfix/smtpd[12]: warning: gitlab[10.0.1.10]: SASL PLAIN authentication failed: authentication failure, sasl_username=gitlab
postfix/smtpd[12]: 3ED5FD2247: client=gitlab[10.0.1.10], sasl_method=PLAIN, sasl_username=gitlab
relay-gateway: reject cid=65 qid=A73FDD20E2 stage=data client=10.0.1.10 login=gitlab reason=from-mismatch code=550
postfix/smtp[45]: Verified TLS connection established to smtp.example-provider.com[x.x.x.x]:587: TLSv1.3 ...
postfix/smtp[45]: 3ED5FD2247: to=<dev@customer.test>, relay=smtp.example-provider.com[x.x.x.x]:587, ..., status=sent (250 Ok queued)
```

La supervision repose sur l'exporteur Prometheus (section 2, « Supervision »),
complété par une alerte sur l'état `unhealthy` d'un conteneur.

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
l'inventaire de test `tests/fixtures/applications.toml`. Une fois la stack
démarrée, le poste génère les paires de clés d'alice@, bob@ et
ext@partner.test (RNP), les dépose sur l'annuaire, et l'administrateur les
valide ; carol@ reste volontairement sans clé. Le service one-shot
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
| `gateway` | 10.0.3.20:9900 et :10025 | passerelle (milter, filtre avant file) |
| `keydir` | 10.0.2.30:8443 (alias `openpgpkey.example.com`) / 10.0.3.30 | annuaire de clés (HTTPS, WKD), domaines `example.com` et `partner.test` |
| `provider` | 10.0.2.10:587 et :993 | fournisseur simulé : Postfix (STARTTLS obligatoire, SASL) qui livre en LMTP à Dovecot ; BAL `alice@`, `bob@`, `carol@`, `supervision@example.com` et `ext@partner.test`, consultables en IMAPS |
| `workstation` | 10.0.2.50 | poste destinataire : génère ses clés avec RNP et les dépose sur l'annuaire (outil `keys`), relève les BAL en IMAPS et déchiffre avec RNP (outils `mailbox`, `pgpmime`) |

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
| IT2.1 | clé générée par RNP sur le poste, déposée en HTTPS (certificat vérifié) : en attente, absente du WKD (404) |
| IT2.2 | validation refusée si l'empreinte diffère ; après validation, le WKD (URL calculée par `gpg-wks-client`) sert la clé, empreinte identique à celle du poste ; second domaine (`partner.test`) |
| IT2.3 | refus motivés (`422`) : sans sous-clé de chiffrement, expirée, RSA 1024, RSA 2048, UID différent, contenu invalide, domaine non géré ; RSA 3072 accepté |
| IT2.4 | rotation : ancienne clé servie jusqu'à la validation de la nouvelle, puis seule la nouvelle |
| IT2.5 | certificat de révocation (RNP) appliqué immédiatement, clé servie marquée révoquée ; certificat d'une autre clé refusé |
| IT2.6 | HTTP en clair sans réponse (et journalisé), TLS 1.1 refusé, TLS 1.2 et 1.3 acceptés (certificat vérifié) |
| IT2.7 | état conservé après redémarrage ; journal d'audit sans contenu de clé |
| IT3.1 | **E2E** GitLab → alice : message brut `multipart/encrypted`, objet neutre, aucun fragment de l'objet, du corps ni des pièces jointes ; déchiffré par RNP : en-têtes protégés v1, objet, texte et pièces jointes identiques (SHA-256) |
| IT3.2 | la clé de bob ne déchiffre pas le message d'alice |
| IT3.3 | carol (sans clé) : `550 5.7.1` au `RCPT TO`, rien en file ni en BAL |
| IT3.4 | alice + carol : carol refusée, alice livrée chiffrée |
| IT3.5 | alice + bob : un seul message, déchiffrable par chacun ; identifiants de clés masqués pour un destinataire unique, visibles à plusieurs |
| IT3.6 | clé révoquée (certificat déposé) ou expirée : refusée après expiration du cache ; nouvelle clé validée : envoi de nouveau possible |
| IT3.7 | passerelle arrêtée : erreur temporaire, rien de livré ; relancée : le renvoi réussit |
| IT3.8 | annuaire arrêté, cache expiré : `451 4.7.1`, rien de livré |
| IT3.9 | après rotation, seul le nouveau trousseau déchiffre |
| IT3.10 | destinataire externe avec clé validée : livré chiffré ; sans clé : refusé |
| IT3.11 | fournisseur arrêté : le message en file (`postcat`) ne contient que du chiffré, et le fichier brut de la file aucun fragment de l'objet, du corps ni des en-têtes d'origine ; livré après relance |
| IT3.12 | objet UTF-8 (RFC 2047), pièces jointes binaires (dont vide), message proche de la taille maximale : aller-retour exact |
| IT3.13 | port de réinjection : fermé côté VLAN Applications, refusé (`554`) depuis une autre machine du réseau backend que la passerelle |
| IT4.1 | notification avec `X-GitLab-*`, `X-Mailer`, `Received` interne : en-têtes extérieurs ⊆ liste blanche, aucune IP ni nom interne, `Message-ID` pseudonymisé ; ces en-têtes sont présents dans la partie déchiffrée |
| IT4.2 | réponse dans un fil (après redémarrage de la passerelle) : `In-Reply-To` et `References` = `Message-ID` pseudonymisé du premier message ; identifiants d'origine dans la partie déchiffrée |
| IT4.3 | aucun `Received` transmis par le relai ; seuls ceux du fournisseur, sans topologie interne |
| IT4.4 | secret `gateway_hmac_key` absent ou trop court : la passerelle refuse de démarrer |
| IT6.1 | bloc de clé privée OpenSSH dans le corps : `550 5.7.1 … (rule private-key)`, rien de livré, ni la clé ni le corps dans les journaux |
| IT6.2 | jeton GitLab dans une pièce jointe encodée en base64 (absent du message brut) : détecté après décodage, refusé |
| IT6.3 | pièce jointe `.exe` : refusée (`forbidden-extension`) |
| IT6.4 | message sain (texte, PDF joint) : livré ; règles invalides ou absentes : la passerelle refuse de démarrer |
| IT7.1 | après un refus faute de clé (carol), un échec d'authentification (jenkins) et un blocage de contenu (clé privée) : réponses SMTP attendues et compteurs correspondants incrémentés |
| IT7.2 | fournisseur arrêté : au moins un message en file, plus ancien d'âge > 0, `relay_smarthost_up` = 0 ; relancé : message livré, file vide, smarthost joignable |
| IT7.3 | date d'expiration du certificat du smarthost (sonde TLS) = celle du certificat de test (`openssl`), certificat vérifié |
| IT7.4 | clé expirant dans 10 jours (GnuPG) déposée et validée : signalée « proche de l'expiration » ; révoquée par l'administrateur : signalée révoquée |
| IT7.5 | aucun objet ni corps de message de test (marqueurs de toutes les suites) dans les journaux d'aucun conteneur ; témoin : le marqueur est bien dans le message déchiffré |
| IT8.1 | `relay-smoke-test` (application locale `supervision` → BAL de supervision, clé publiée comme en production) : code 0 sur la stack de test, message livré chiffré et déchiffré ; fournisseur arrêté : code 1 (livraison différée), message livré après la relance ; identifiants du relai refusés (`relay-badcreds`) : code 1, motif `auth` ; application non locale : code 2 |

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
- **Chiffrement de bout en bout** : le message est chiffré pour ses destinataires avant la mise en file (filtre avant file, rien n'est écrit en clair) ; ni la file, ni le fournisseur, ni la BAL ne voient le contenu ou l'objet réel. Destinataire sans clé validée : refus, jamais d'envoi en clair.
- **Pas de secret en clair qui sorte** : clés privées, jetons d'accès et exécutables sont bloqués avant chiffrement (`config/content-rules.toml`).
- **Métadonnées minimales** : en-têtes extérieurs en liste blanche, identifiants de message pseudonymisés, aucun `Received` interne.
- **Trois verrous par application** : son mot de passe, ses IP (liste blanche globale dès la connexion, puis liaison login ↔ IP dans la passerelle) et son adresse (enveloppe dans Postfix, `From:` dans la passerelle). Un identifiant volé ne sert ni depuis une autre machine, ni pour usurper une autre application.
- **Aucun mot de passe en clair** : STARTTLS obligatoire avant AUTH, TLS ≥ 1.2. Essais limités par IP (`RELAY_AUTH_RATE_LIMIT`).
- **L'IP source doit être la vraie.** Le filtrage repose sur l'IP vue par Postfix.
  - Avec la publication de ports Docker standard (NAT iptables), l'IP du client est conservée.
  - Ne placez **pas** le relai derrière un proxy TCP ou un load balancer en mode proxy : Postfix verrait l'IP du proxy.
- **Exposition réseau.** Publiez le port 587 uniquement sur l'IP privée (`RELAY_BIND_ADDRESS`) et doublez ce filtrage d'un pare-feu (VLAN Applications → 587 uniquement ; sortie vers le fournisseur uniquement).
- **Supervision.** Métriques publiées sur la boucle locale par défaut ; exporteur non privilégié (`nobody`) ; métriques de l'annuaire sur un port interne non publié ; ni objet ni corps, mais des adresses de destinataires (accès à restreindre au serveur Prometheus).
- **Journaux (RGPD).** Métadonnées seulement (enveloppe, codes, identifiant de règle), vérifié par un test sur tous les conteneurs (IT7.5) ; aucun journal persistant dans les conteneurs (logs Docker en rotation, 5 × 10 Mo) ; audit de l'annuaire purgé après `KEYDIR_AUDIT_RETENTION_DAYS`.
- **Annuaire.** Aucune clé publiée sans validation humaine de l'empreinte ; dépôts limités en taille et contrôlés (algorithmes, expiration, identité) ; HTTPS uniquement ; service non privilégié.
- **Secrets.** Fichiers montés en lecture seule, jamais dans l'image ni dans `docker inspect` ; `.env` et `secrets/*` sont ignorés par git ; dans le conteneur, base SASL `0640 root:postfix`, identifiants et clé TLS `0600 root`, sur tmpfs.
- **TLS vers le fournisseur.** `secure` vérifie la chaîne et le nom de l'hôte ; TLS 1.0 et 1.1 interdits, suites `high` uniquement.
- **Durcissement des conteneurs** : système de fichiers racine en lecture seule, capacités minimales (passerelle et annuaire : abandon de root et de toute capacité après la lecture des secrets), `no-new-privileges`, limites de ressources, bannière sans version, `VRFY` désactivé.
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
| `454 4.3.0 Try again later` | Passerelle arrêtée ou injoignable : `docker compose ps gateway`, `docker compose logs gateway`. |
| `451 4.3.0 Reinjection failed` | La passerelle ne peut pas réinjecter dans le relai : logs du relai (`postfix/reinject`) ; adresse de la passerelle différente de celle vue au démarrage du relai (healthcheck `gateway IP changed`) : `docker compose restart relay`. |
| `550 5.7.1 Message blocked by content policy (rule …)` | Le message contient ce que la règle indiquée interdit (clé privée, jeton, exécutable) : corriger le contenu côté application ; ne pas affaiblir la règle sans revue. |
| `550 5.7.1 No valid OpenPGP key for <adresse>` | Le destinataire n'a pas de clé validée dans l'annuaire (ou elle est expirée, révoquée) : `docker compose exec keydir keydir-admin show <adresse>` ; le motif exact est dans les logs de la passerelle (`reason=`). |
| `451 4.7.1 Key directory unavailable` | La passerelle ne joint pas l'annuaire (arrêté, certificat non reconnu : `GATEWAY_KEYDIR_CA_FILE`). |
| Le destinataire ne peut pas déchiffrer dans Thunderbird | Sa clé privée ne correspond pas à la clé validée (rotation non faite côté annuaire) : comparer les empreintes. |
| `status=deferred … SASL authentication failed` | Identifiants du fournisseur erronés ou expirés. Vérifiez les secrets, puis `docker compose up -d` et `docker compose exec relay postqueue -f`. |
| `Server certificate not verified` | Nom de `RELAY_HOST` différent de celui du certificat du fournisseur, ou autorité absente du bundle (`RELAY_TLS_CA_FILE`). |
| `connect to …:587: Connection timed out` | Sortie bloquée par un pare-feu, ou DNS. Testez depuis l'hôte avec `nc -vz <RELAY_HOST> 587`. |
| `554 Message rejected: Email address is not verified` (fournisseur) | L'adresse de l'application ou le domaine n'est pas vérifié chez le fournisseur. |
| `552 5.3.4 Message size exceeds fixed limit` | Augmentez `MESSAGE_SIZE_LIMIT`, en respectant la limite du fournisseur. |
| `unhealthy` | `docker compose exec relay relay-healthcheck` ou `docker compose exec gateway gateway-healthcheck` affiche la cause. |
| Métriques absentes (`curl` sans réponse sur 9154) | `RELAY_METRICS_BIND_ADDRESS` ou pare-feu ; dans les logs du relai, `relay-exporter: métriques sur …` au démarrage, `relay-run: exporteur de métriques arrêté` en cas d'arrêt (il est relancé). |
| `relay_keydir_metrics_up 0` | Annuaire arrêté, ou `KEYDIR_METRICS_LISTEN` vide. |
| `relay_smarthost_up 0` alors que les mails partent | Sortie filtrée pour les connexions de sonde, ou intervalle trop long : la dernière sonde date de `relay_smarthost_last_probe_timestamp_seconds`. |
| `relay-smoke-test` : `ÉCHEC : … RCPT TO refusé : 550 5.7.1 No valid OpenPGP key` | La clé de la BAL de supervision (`RELAY_SMOKE_TO`) n'est pas validée sur l'annuaire (ou a expiré) : la déposer et la valider (`keydir-admin approve`). |
| `relay-smoke-test` : `ÉCHEC : … This login is not allowed from this host` ou code 2 « doit être locale » | L'application `supervision` n'a pas `client_ips = ["127.0.0.1"]` dans l'inventaire. |
| `relay-smoke-test` : `livraison différée (motif : …)` | Le message est accepté et chiffré mais le smarthost ne le prend pas : `auth` (identifiants du fournisseur), `tls` (certificat), `dns`/`connection` (sortie, pare-feu). Il reste en file et repart seul une fois la cause corrigée (`postqueue -f`). |
| `relay-smoke-test` : `NON CONFIRMÉ : exporteur injoignable` (code 3) | `RELAY_METRICS_ENABLED=no` ou exporteur arrêté : le résultat de livraison n'est lu que par l'exporteur ; contrôler `status=sent` dans les logs du relai. |
