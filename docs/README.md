# Relai SMTP interne : notifications CI/CD vers un fournisseur cloud

Ce relai centralise l'envoi des emails de GitLab CE et de Jenkins. Il accepte
uniquement les applications déclarées (liste blanche d'IP), réécrit
l'expéditeur, puis transmet les messages au MTA d'un fournisseur cloud
(AWS SES, SendGrid, Mailjet, Brevo…) en **TLS ≥ 1.2 avec authentification SASL**.

```
GitLab / Jenkins ──SMTP :25, clair, sans auth──▶ relai Postfix ──:587/465, TLS + SASL──▶ fournisseur cloud
                    (liste blanche d'IP, refus par défaut)
```

Le schéma détaillé (zones, flux, contrôles) se trouve dans [architecture.md](architecture.md).
Le guide de mise en production on-premise, avec Google Workspace ou OVHcloud comme
fournisseur, se trouve dans [deploiement-production.md](deploiement-production.md).

> **Valeurs d'exemple :** fournisseur `smtp.example-provider.com:587`, GitLab
> `10.0.1.10`, Jenkins `10.0.1.20`, domaine `example.com`, expéditeur
> `noreply@example.com`. Elles sont à remplacer (`<À PRÉCISER>` dans `.env.example`).

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Contenu du dépôt et images](#2-contenu-du-dépôt-et-images)
3. [Variables d'environnement et secrets](#3-variables-denvironnement-et-secrets)
4. [Déploiement](#4-déploiement)
5. [Ajouter ou retirer une application autorisée](#5-ajouter-ou-retirer-une-application-autorisée)
6. [Exploitation](#6-exploitation)
7. [Configuration de GitLab CE et de Jenkins](#7-configuration-des-applications)
8. [Tests locaux](#8-tests-locaux)
9. [Sécurité](#9-points-de-sécurité)
10. [Dépannage](#10-dépannage)

---

## 1. Prérequis

- Docker Engine 24 ou plus récent et Docker Compose v2.24 ou plus récent (syntaxe `!reset` / `!override` utilisée par la stack de test).
- Un hôte situé dans le réseau privé, joignable par GitLab et Jenkins sur le port 25.
- Une sortie Internet vers le fournisseur sur le port 587 ou 465. Beaucoup de clouds bloquent le port 25 sortant, il n'est donc pas utilisé.
- Chez le fournisseur :
  - un compte SMTP (identifiant et mot de passe ou clé) ;
  - le **domaine d'expédition vérifié**, avec SPF, DKIM et DMARC publiés ;
  - l'adresse d'expédition autorisée.
- Pour les tests : bash, et un accès aux dépôts `deb.debian.org` pendant la construction des images.

## 2. Contenu du dépôt et images

```
docker-compose.yml        stack de production (service relay)
docker-compose.test.yml   surcharge de test (faux MTA, 3 clients, relai à mauvais identifiants)
relay/Dockerfile          image du relai
relay/entrypoint.sh       validation de la configuration, génération de /etc/postfix, lancement
relay/config/*.tmpl       templates de main.cf et master.cf
relay/scripts/            bibliothèque commune, healthcheck, rechargement de la liste blanche
test/fake-mta/            faux MTA fournisseur (Postfix + TLS + SASL), test uniquement
test/client/              client swaks, test uniquement
secrets/                  emplacement des Docker secrets (ignoré par git)
tests/run-tests.sh        tests d'intégration automatisés
```

### Images Docker

Les trois images partent de `debian:trixie-20261005-slim` (Debian 13, tag
daté et épinglé). Le tag est surchargeable avec `--build-arg DEBIAN_TAG=…`.

| Image | Paquets Debian | Rôle |
|-------|----------------|------|
| `relay` | `postfix`, `libsasl2-modules` (mécanismes client PLAIN/LOGIN), `ca-certificates` (vérification du certificat du fournisseur) | relai de production |
| `test/fake-mta` | `postfix`, `sasl2-bin` (`saslpasswd2`), `libsasl2-modules`, `openssl` (PKI de test) | simule le fournisseur |
| `test/client` | `swaks` | simule GitLab, Jenkins ou une application inconnue |

Bonnes pratiques appliquées dans les Dockerfiles :

- `--no-install-recommends` ;
- une seule couche `RUN` par étape logique ;
- `apt-get update`, installation et purge de `/var/lib/apt/lists` dans la même couche ;
- `DEBIAN_FRONTEND` passé en `ARG`, donc non persisté dans l'image ;
- labels OCI ;
- `HEALTHCHECK` et `VOLUME` déclarés.

**Aucune configuration ni aucun secret n'est figé dans l'image.**

### Entrypoint (`relay/entrypoint.sh`)

L'entrypoint enchaîne quatre étapes :

1. **Validation.** Toutes les variables sont contrôlées : IP, domaine, adresse, port, niveau TLS, taille maximale, durée de file. À la moindre erreur, le conteneur s'arrête avec un code 1 et un message `FATAL: …`. Il ne démarre jamais en mode dégradé ou ouvert.
2. **Liste blanche.** `ALLOWED_CLIENT_IPS` et `ALLOWED_CLIENT_IPS_FILE` sont fusionnés.
   - Chaque IP devient `a.b.c.d/32` ou `[v6]/128`.
   - Les notations CIDR, `0.0.0.0` et `::` sont refusées, et une liste vide aussi.
3. **Génération de `/etc/postfix`.** `/etc/postfix` est un tmpfs (le système de fichiers racine est en lecture seule). L'entrypoint y restaure les fichiers Debian, puis génère :
   - `main.cf` et `master.cf` à partir des templates ;
   - `sender_canonical.regexp` ;
   - `sasl_passwd` (`root:root 0600`), construit à partir des Docker secrets.
4. **Démarrage.** `postfix check`, puis `exec postfix start-fg`. Postfix tourne en PID 1 et ses logs partent sur stdout.

### Paramètres Postfix clés

| Paramètre | Valeur | Pourquoi |
|-----------|--------|----------|
| `mynetworks` | `127.0.0.1/32` + IP déclarées en `/32` ou `/128` | seules les applications déclarées peuvent relayer ; la boucle locale sert au healthcheck et aux tests via `docker exec` |
| `smtpd_client_restrictions`, `smtpd_relay_restrictions`, `smtpd_recipient_restrictions` | `permit_mynetworks, reject` | **refus par défaut** : tout client hors liste est rejeté |
| `smtpd_delay_reject` | `yes` | le rejet se produit au `RCPT TO`, et la ligne de log contient alors l'IP, l'expéditeur, le destinataire et le motif |
| `mydestination`, `relay_domains`, `local_transport = error` | vides / `error` | aucune réception entrante ni livraison locale : impossible d'être un open relay |
| `smtpd_tls_security_level`, `smtpd_sasl_auth_enable` | `none`, `no` | côté réseau privé, ni TLS ni authentification (exigence) |
| `disable_vrfy_command`, `smtpd_helo_required`, `smtpd_banner` | `yes`, `yes`, `$myhostname ESMTP` | pas d'énumération d'adresses, pas de version du logiciel exposée |
| `relayhost` | `[RELAY_HOST]:RELAY_PORT` | les crochets désactivent la recherche MX : on contacte exactement l'hôte indiqué |
| `smtp_tls_security_level` | `secure` (défaut) ou `encrypt` | TLS obligatoire ; `secure` vérifie en plus le certificat et le nom d'hôte (`nexthop, dot-nexthop`) |
| `smtp_tls_mandatory_protocols`, `smtp_tls_protocols` | `>=TLSv1.2` | TLS 1.0 et 1.1 interdits |
| `smtp_tls_wrappermode` | `yes` si le port est 465 | TLS implicite (SMTPS) ; STARTTLS sinon |
| `smtp_sasl_auth_enable`, `smtp_sasl_password_maps` | `yes`, `texthash:/etc/postfix/sasl_passwd` | authentification auprès du fournisseur ; `texthash` évite `postmap` et toute base binaire |
| `smtp_sasl_security_options` | `noanonymous` | interdit les mécanismes anonymes |
| `smtp_sasl_auth_soft_bounce` | `yes` | un refus d'authentification produit un report (le message reste en file) et non un rejet définitif |
| `sender_canonical_maps` + `sender_canonical_classes` | `regexp:…`, `envelope_sender, header_sender` | réécrit le `MAIL FROM` et les en-têtes `From:` et `Sender:` |
| `local_header_rewrite_clients` | `permit_mynetworks` | sans ce réglage, Postfix ne réécrit **pas** les en-têtes des clients distants |
| `message_size_limit` | `MESSAGE_SIZE_LIMIT` | taille maximale des messages |
| `maximal_queue_lifetime` | `QUEUE_LIFETIME` (5d) | durée de rétention d'un message non délivrable |
| `maillog_file` | `/dev/stdout` | logs disponibles via `docker logs` |
| `master.cf` | services minimaux, `chroot = n` | surface réduite ; le chroot est inutile dans un conteneur isolé et casse souvent DNS et TLS |

### Réécriture de l'expéditeur

Deux modes sont disponibles :

- **`SENDER_REWRITE_MODE=always` (défaut, recommandé).** Tout message sort avec `SENDER_ADDRESS`, à la fois dans l'enveloppe et dans l'en-tête `From:`. Le nom affiché est conservé : `From: "GitLab" <gitlab@ci.internal>` devient `From: "GitLab" <noreply@example.com>`. Le fournisseur n'accepte que des expéditeurs vérifiés, et SPF et DMARC sont alignés.
- **`SENDER_REWRITE_MODE=foreign`.** Seuls les expéditeurs qui n'appartiennent pas à `SENDER_DOMAIN` (ni à l'un de ses sous-domaines) sont réécrits. Une application qui émet déjà `ci@example.com` garde son adresse : elle doit alors aussi être vérifiée chez le fournisseur.

Dans les deux modes :

- l'en-tête `Reply-To:` éventuel n'est pas modifié ;
- les rapports de non-remise (expéditeur vide `<>`) ne sont pas réécrits ;
- `myorigin = SENDER_DOMAIN` complète les adresses non qualifiées (`jenkins` devient `jenkins@example.com`) ;
- `myhostname` vaut `relay.SENDER_DOMAIN`, sauf si `RELAY_HOSTNAME` est défini.

## 3. Variables d'environnement et secrets

| Variable | Rôle | Défaut | Obligatoire |
|----------|------|--------|:-----------:|
| `ALLOWED_CLIENT_IPS` | IP des applications autorisées, séparées par des virgules (`10.0.1.10,10.0.1.20`). IPv4 ou IPv6, **sans CIDR** | — | **oui**¹ |
| `ALLOWED_CLIENT_IPS_FILE` | chemin, dans le conteneur, d'un fichier monté (une IP par ligne, `#` pour les commentaires), réunie avec la variable précédente ; rechargeable à chaud | — | non¹ |
| `RELAY_BIND_ADDRESS` | IP **privée** de l'hôte sur laquelle publier le port (compose) | — | **oui** |
| `RELAY_PUBLISHED_PORT` | port publié sur l'hôte : 25 ou 587 (compose) | `25` | non |
| `SENDER_DOMAIN` | domaine d'expédition vérifié chez le fournisseur ; sert aussi à dériver `myorigin` et `myhostname` | — | **oui** |
| `SENDER_ADDRESS` | adresse d'expédition ; doit appartenir à `SENDER_DOMAIN` | `noreply@SENDER_DOMAIN` | non |
| `SENDER_REWRITE_MODE` | `always` ou `foreign` | `always` | non |
| `RELAY_HOSTNAME` | FQDN annoncé (`myhostname`, EHLO vers le fournisseur) | `relay.SENDER_DOMAIN` | non |
| `RELAY_HOST` | MTA du fournisseur | — | **oui** |
| `RELAY_PORT` | `587` (STARTTLS) ou `465` (TLS implicite) | `587` | non |
| `RELAY_TLS_WRAPPERMODE` | `auto` (`yes` si le port est 465), `yes` ou `no` | `auto` | non |
| `RELAY_TLS_SECURITY_LEVEL` | `secure` (certificat vérifié) ou `encrypt` ; `may` et `none` sont refusés | `secure` | non |
| `RELAY_TLS_CA_FILE` | bundle des autorités de confiance | `/etc/ssl/certs/ca-certificates.crt` | non |
| `RELAY_SASL_MECHANISMS` | mécanismes SASL autorisés | `plain, login` | non |
| `MESSAGE_SIZE_LIMIT` | taille maximale d'un message, en octets | `10240000` | non |
| `QUEUE_LIFETIME` | durée de vie en file (`5d`, `12h`…) | `5d` | non |
| `RELAY_LISTEN_PORT` | port d'écoute **dans** le conteneur | `25` | non |
| `RELAY_INET_PROTOCOLS` | `ipv4`, `ipv6` ou `all` | déduit de la liste | non |
| `TZ` | fuseau horaire des logs | `UTC` | non |
| `RELAY_IMAGE_TAG` | tag de l'image construite | `1.0.0` | non |

¹ Au moins une des deux sources doit fournir une IP valide, sinon le conteneur refuse de démarrer.

| Secret (Docker) | Fichier hôte | Rôle | Obligatoire |
|-----------------|--------------|------|:-----------:|
| `relay_smtp_username` | `secrets/relay_smtp_username` | identifiant SMTP du fournisseur | **oui** |
| `relay_smtp_password` | `secrets/relay_smtp_password` | mot de passe ou clé SMTP | **oui** |

Ordre de lecture des identifiants :

1. le chemin indiqué par `RELAY_SMTP_USERNAME_FILE` ou `RELAY_SMTP_PASSWORD_FILE` ;
2. sinon le secret monté dans `/run/secrets/relay_smtp_*` ;
3. en dernier recours, les variables `RELAY_SMTP_USERNAME` et `RELAY_SMTP_PASSWORD` (repli `.env`, déconseillé, signalé par un `WARNING` dans les logs).

## 4. Déploiement

```bash
cp .env.example .env                    # renseigner les valeurs <À PRÉCISER>
install -m 600 /dev/null secrets/relay_smtp_username
install -m 600 /dev/null secrets/relay_smtp_password
printf '%s' 'IDENTIFIANT' > secrets/relay_smtp_username
printf '%s' 'MOT_DE_PASSE' > secrets/relay_smtp_password

docker compose up -d --build
docker compose ps                       # STATUS doit afficher (healthy)
docker compose logs -f relay            # résumé de la configuration au démarrage
```

Le service est configuré pour la production avec :

- `restart: unless-stopped` ;
- un système de fichiers racine en lecture seule, avec des tmpfs pour `/etc/postfix`, `/var/lib/postfix`, `/run` et `/tmp` ;
- `cap_drop: ALL`, puis les seules capacités nécessaires au processus maître Postfix (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `KILL`) ;
- `no-new-privileges`, des limites de 0,5 CPU, 256 Mo de mémoire et 200 processus ;
- des logs en rotation (5 × 10 Mo) ;
- la file d'attente dans le volume nommé `relay-queue`.

> Postfix exige que son processus maître démarre en root : il ouvre le port 25
> et lit les secrets, puis tous les démons qui traitent les messages (smtpd,
> cleanup, qmgr, smtp) tournent sous l'utilisateur non privilégié `postfix`.

Test de bout en bout depuis une machine autorisée :

```bash
swaks --server <RELAY_BIND_ADDRESS> --port 25 --from gitlab@ci.internal --to vous@domaine.tld
```

**Mise à jour de l'image** (par exemple vers un nouveau tag Debian daté) :
modifier `DEBIAN_TAG`, puis lancer `docker compose up -d --build`. La file
d'attente est conservée dans le volume.

## 5. Ajouter ou retirer une application autorisée

**Méthode A : variable `ALLOWED_CLIENT_IPS` (par défaut).**

```bash
# Dans .env :
ALLOWED_CLIENT_IPS=10.0.1.10,10.0.1.20,10.0.1.40   # ajout de 10.0.1.40

docker compose up -d                    # recrée le conteneur (quelques secondes)
docker compose logs relay | grep "Clients autorisés"
```

Pendant la recréation, les applications reçoivent une erreur temporaire et
réessaient. Les mails déjà en file sont conservés dans le volume.

**Méthode B : fichier monté, rechargeable sans interruption.**

1. Créez `config/allowed_clients.txt` (ignoré par git), avec une IP par ligne :

   ```
   10.0.1.10   # GitLab
   10.0.1.20   # Jenkins
   ```

2. Dans `docker-compose.yml`, décommentez le volume `./config/allowed_clients.txt:/etc/relay/allowed_clients.txt:ro`.
3. Dans `.env`, ajoutez `ALLOWED_CLIENT_IPS_FILE=/etc/relay/allowed_clients.txt`. La variable `ALLOWED_CLIENT_IPS` peut alors rester vide.
4. Lancez `docker compose up -d` une première fois.

Ensuite, pour chaque modification :

```bash
vi config/allowed_clients.txt
docker compose exec relay relay-reload-allowlist   # puis postfix reload, sans coupure
```

Si la nouvelle liste est vide ou invalide, le rechargement est refusé et
l'ancienne liste reste en vigueur.

> Pour **retirer** une application, procédez de la même façon en supprimant son
> IP. Les connexions SMTP déjà ouvertes se terminent normalement ; toute
> nouvelle connexion est rejetée.

## 6. Exploitation

| Action | Commande |
|--------|----------|
| État et santé | `docker compose ps`, ou `docker inspect -f '{{.State.Health.Status}}' $(docker compose ps -q relay)` |
| Logs en direct | `docker compose logs -f relay` |
| Repérer les **rejets** (IP non autorisées) | `docker compose logs relay \| grep 'Client host rejected'` |
| Mails remis au fournisseur | `docker compose logs relay \| grep 'status=sent'` |
| Mails reportés (et la raison) | `docker compose logs relay \| grep 'status=deferred'` |
| Contenu de la file | `docker compose exec relay postqueue -p`, ou `postqueue -j` pour du JSON |
| Forcer un nouvel essai | `docker compose exec relay postqueue -f` |
| Lire un message en file | `docker compose exec relay postcat -vq <QUEUE_ID>` |
| Supprimer un message | `docker compose exec relay postsuper -d <QUEUE_ID>` |
| **Vider** la file (tous les messages) | `docker compose exec relay postsuper -d ALL` |
| Vider seulement les reportés | `docker compose exec relay postsuper -d ALL deferred` |
| Recharger la configuration | `docker compose exec relay postfix reload` |
| Configuration effective | `docker compose exec relay postconf -n` |

Exemple de **rejet** dans les logs : l'IP source et le motif y figurent.

```
postfix/smtpd[123]: NOQUEUE: reject: RCPT from unknown[10.0.1.30]: 554 5.7.1 <dev@customer.test>: Client host rejected: Access denied; from=<app@unknown.internal> to=<dev@customer.test> proto=ESMTP helo=<unknown.ci.internal>
```

Exemple de **livraison** réussie :

```
postfix/smtp[456]: Verified TLS connection established to smtp.example-provider.com[x.x.x.x]:587: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 ...
postfix/smtp[456]: 4Zxyz...: to=<dev@customer.test>, relay=smtp.example-provider.com[x.x.x.x]:587, ..., status=sent (250 Ok queued)
```

Pour la supervision, une alerte peut se déclencher sur :

- l'état `unhealthy` du conteneur ;
- une croissance de la file (`postqueue -j | wc -l`) ;
- des occurrences de `status=deferred`, `SASL authentication failed` ou `Client host rejected`.

## 7. Configuration des applications

Dans les deux cas, l'application parle au relai **sans TLS et sans
authentification**, sur le port 25 de `RELAY_BIND_ADDRESS`. La valeur
`relay.internal` utilisée ci-dessous est un exemple : remplacez-la par cette
adresse ou par son nom DNS.

### GitLab CE (`/etc/gitlab/gitlab.rb`)

```ruby
gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "relay.internal"
gitlab_rails['smtp_port'] = 25
gitlab_rails['smtp_domain'] = "example.com"
gitlab_rails['smtp_authentication'] = false
gitlab_rails['smtp_enable_starttls_auto'] = false
gitlab_rails['smtp_tls'] = false
gitlab_rails['smtp_openssl_verify_mode'] = 'none'

gitlab_rails['gitlab_email_from'] = 'noreply@example.com'
gitlab_rails['gitlab_email_display_name'] = 'GitLab'
gitlab_rails['gitlab_email_reply_to'] = 'noreply@example.com'
```

Appliquez la configuration, puis envoyez un mail de test :

```bash
sudo gitlab-ctl reconfigure
sudo gitlab-rails runner "Notify.test_email('vous@domaine.tld', 'Test relai', 'OK').deliver_now"
```

L'IP **source** de GitLab (par exemple `10.0.1.10`) doit figurer dans
`ALLOWED_CLIENT_IPS`. Si GitLab tourne lui-même dans Docker, c'est l'IP vue
par le relai qui compte : vérifiez-la dans les logs du relai.

### Jenkins

**Plugin Mailer** (*Administrer Jenkins → System → Notification par email*) :

- Serveur SMTP : `relay.internal`, port `25` ;
- *Utiliser SSL* et *Utiliser TLS* décochés, aucune authentification ;
- *Jenkins Location → Adresse email de l'administrateur système* : `Jenkins <noreply@example.com>`.

**Plugin Email Extension** (*Extended E-mail Notification*) : mêmes valeurs
(SMTP server, port 25, sans SSL/TLS ni credentials), et *Default user email
suffix* : `@example.com`.

Équivalent en Configuration as Code (JCasC), à adapter selon les versions des plugins :

```yaml
unclassified:
  location:
    adminAddress: "Jenkins <noreply@example.com>"
  mailer:
    smtpHost: "relay.internal"
    smtpPort: "25"
    useSsl: false
    useTls: false
  email-ext:
    mailAccount:
      smtpHost: "relay.internal"
      smtpPort: "25"
      useSsl: false
      useTls: false
    defaultSuffix: "@example.com"
```

Pour vérifier, utilisez *Tester la configuration en envoyant un email*.

## 8. Tests locaux

```bash
tests/run-tests.sh          # construit, démarre, teste, puis nettoie (docker compose down -v)
KEEP=1 tests/run-tests.sh   # conserve la stack pour l'inspecter
```

Le script lance `docker compose -p smtp-relay-test --env-file tests/test.env
-f docker-compose.yml -f docker-compose.test.yml`. Le relai testé est donc
**celui de production**, surchargé uniquement par les paramètres de test.

Il génère à chaque exécution des identifiants SASL aléatoires dans
`tests/.work/` (ignoré par git).

| Composant | IP | Rôle |
|-----------|----|------|
| `client-gitlab` | 10.0.1.10 | IP déclarée |
| `client-jenkins` | 10.0.1.20 | IP déclarée |
| `client-unknown` | 10.0.1.30 | IP **non** déclarée |
| `relay` | 10.0.1.5 / 10.0.2.5 | relai avec identifiants valides |
| `relay-badcreds` | 10.0.1.6 / 10.0.2.6 | même image, mot de passe erroné |
| `fake-mta` | 10.0.2.10:587 | Postfix avec STARTTLS obligatoire, SASL (sasldb), certificat signé par une AC de test, capture des mails dans des fichiers `*.eml` |

Les deux réseaux Docker sont `internal`, sans accès à Internet.

Vérifications automatiques (une ligne PASS/FAIL par test) :

| Test | Attendu |
|------|---------|
| T1/T2 | un mail envoyé depuis GitLab, puis depuis Jenkins, est **reçu** par le faux MTA |
| T3a/b/c | depuis l'IP inconnue : rejet `554 5.7.1`, rejet **tracé dans les logs** (IP + motif), aucun mail reçu |
| T4a/b | `Return-Path` et `From:` du mail reçu valent `noreply@example.com` (nom affiché conservé) |
| T5a–d | logs du relai : `Verified TLS connection established … TLSv1.x` et `status=sent` ; logs du faux MTA : `sasl_username=relay-test` ; en-tête `Received` du mail : `using TLSv1.x` et `Authenticated sender` |
| T6a–d | avec de mauvais identifiants : `SASL authentication failed`, message **en file `deferred`**, non délivré, toujours présent après redémarrage (persistance du volume) |
| T7 | le conteneur **refuse de démarrer** si la liste est vide, contient un CIDR ou une IP invalide |
| T8 | le healthcheck du relai est `healthy` |

**Nettoyage.** Il est automatique à la fin du script. Pour une stack conservée avec `KEEP=1` :

```bash
docker compose -p smtp-relay-test --env-file tests/test.env \
  -f docker-compose.yml -f docker-compose.test.yml down -v
rm -rf tests/.work
```

Les réseaux de test utilisent `10.0.1.0/24` et `10.0.2.0/24`. En cas de
conflit avec un réseau existant sur l'hôte, adaptez les sous-réseaux et les
IP dans `docker-compose.test.yml` et dans `tests/run-tests.sh`.

## 9. Points de sécurité

- **Pas d'open relay.** Le refus par défaut s'applique dès qu'une IP n'est pas listée. Aucun domaine local n'existe, et une liste vide ou invalide empêche le démarrage. Pour le vérifier depuis une IP non autorisée : `swaks --server <relai> --to test@gmail.com` doit renvoyer `554 5.7.1`.
- **L'IP source doit être la vraie.** Le filtrage repose sur l'IP vue par Postfix.
  - Avec la publication de ports Docker standard (NAT iptables), l'IP du client est conservée.
  - Ne placez **pas** le relai derrière un proxy TCP, un load balancer en mode proxy ou un `userland-proxy` : Postfix verrait alors l'IP du proxy, et autoriser cette IP reviendrait à ouvrir le relai à tous les clients du proxy.
  - En cas de doute, regardez les IP qui apparaissent dans `connect from …` dans les logs.
  - `network_mode: host` ou un réseau macvlan sont des alternatives.
- **Exposition réseau.**
  - Publiez le port uniquement sur l'IP privée (`RELAY_BIND_ADDRESS`).
  - Doublez ce filtrage d'un pare-feu ou d'un security group : le port 25 entrant n'est ouvert qu'aux IP de GitLab et Jenkins, et seul le port 587 ou 465 vers le fournisseur est autorisé en sortie.
- **Secrets.**
  - Les identifiants passent par des Docker secrets, jamais par l'image ni par `docker inspect`.
  - `.env` et `secrets/*` sont ignorés par git.
  - Dans le conteneur, les identifiants sont écrits dans un fichier `0600 root` sur un tmpfs.
  - Faites tourner régulièrement les clés SMTP du fournisseur.
- **TLS.**
  - `secure` vérifie la chaîne de certificats et le nom de l'hôte, ce qui protège contre l'interception. N'utilisez `encrypt` que si le fournisseur présente un certificat non vérifiable, et documentez-le.
  - TLS 1.0 et 1.1 sont interdits, avec des suites de chiffrement `high` uniquement.
- **Le trafic réseau privé circule en clair** (exigence). Réservez ce segment aux serveurs CI/CD.
- **Durcissement du conteneur** : système de fichiers racine en lecture seule, capacités minimales, `no-new-privileges`, limites de ressources, bannière sans version, `VRFY` désactivé.
- **Côté fournisseur** : domaine vérifié, SPF, DKIM et DMARC publiés, quotas et alertes de réputation (bounces, plaintes) surveillés.

## 10. Dépannage

| Symptôme | Cause probable / action |
|----------|-------------------------|
| Le conteneur redémarre en boucle, `FATAL: …` dans les logs | Variable invalide ou manquante (liste d'IP vide, `SENDER_ADDRESS` hors domaine, secret absent…). Le message indique la variable fautive. |
| `554 5.7.1 … Client host rejected: Access denied` pour une application légitime | Son IP source n'est pas dans la liste. Comparez avec `connect from …[IP]` dans les logs (attention au NAT ou à un proxy), puis ajoutez l'IP (section 5). |
| `status=deferred … SASL authentication failed` | Identifiants erronés ou expirés, ou mécanisme refusé. Vérifiez les secrets, puis lancez `docker compose up -d` et `docker compose exec relay postqueue -f`. |
| `Server certificate not verified` ou `certificate verification failed` | Nom de `RELAY_HOST` différent de celui du certificat, ou autorité absente du bundle. Utilisez le nom officiel du fournisseur ou `RELAY_TLS_CA_FILE`. |
| `TLS is required, but was not offered by host` | Mauvais port, ou port 465 sans `wrappermode`. Avec `RELAY_PORT=465`, le mode `auto` active le TLS implicite. |
| `connect to …:587: Connection timed out` | Sortie bloquée par un pare-feu ou un security group, ou DNS. Testez depuis l'hôte avec `nc -vz <RELAY_HOST> 587`. |
| `554 Message rejected: Email address is not verified` (fournisseur) | `SENDER_ADDRESS` ou `SENDER_DOMAIN` n'est pas vérifié chez le fournisseur. |
| `552 5.3.4 Message size exceeds fixed limit` | Augmentez `MESSAGE_SIZE_LIMIT`, en respectant la limite du fournisseur (10 Mo chez SES par exemple). |
| `unhealthy` | `docker compose exec relay relay-healthcheck` affiche la cause (processus maître arrêté, port fermé). |
| La file grossit | `postqueue -p` pour lire la raison des reports, corrigez, puis `postqueue -f`. |
