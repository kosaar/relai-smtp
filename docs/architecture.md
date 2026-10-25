# Architecture du relai SMTP

> État actuel : lots 1 à 4, 6 et 7 du [plan d'implémentation](plan-implementation.md)
> (soumission 587 authentifiée, identité par application, annuaire de clés,
> chiffrement OpenPGP dans la passerelle avant la mise en file, nettoyage des
> en-têtes, contrôle du contenu, supervision). Les quotas (lot 5) ne sont pas
> réalisés ; le lot 8 finalise l'exploitation et la documentation.

## Vue d'ensemble

```mermaid
flowchart LR
    subgraph APPS["🔒 VLAN Applications"]
        direction TB
        GL["GitLab<br/>10.0.1.10"]
        JK["Jenkins<br/>10.0.1.20"]
        GP["GLPI · YouTrack"]
        UNK["Hôte non déclaré"]
    end

    subgraph SVC["🔒 VLAN Services"]
        subgraph RELAY["Conteneur relay — Postfix (Ubuntu 26.04 LTS)"]
            direction TB
            SMTPD["submission :587<br/>STARTTLS ≥ 1.2 obligatoire<br/>AUTH (sasldb par application)"]
            ACL[/"1. IP ∈ inventaire (mynetworks)<br/>2. AUTH réussie<br/>3. MAIL FROM = adresse du login"/]
            RI["réinjection :10026<br/>(IP de la passerelle seule)"]
            Q[("Volume relay-queue<br/>(chiffré uniquement)")]
            SMTP["client smtp<br/>relayhost = [fournisseur]:587<br/>Received du relai retiré"]
            INV{{"config/applications.toml<br/>secrets/apps/&lt;nom&gt;"}}
            EXP["exporteur :9154 (nobody)<br/>journaux (relay-run), postqueue -j,<br/>sonde TLS du smarthost"]
            SMTPD --> ACL
            RI --> Q --> SMTP
            INV -. "relay-config<br/>(au démarrage)" .-> ACL
            Q -.-> EXP
        end
        GW["Conteneur gateway (Python)<br/>milter :9900 : login ↔ IP, clé du destinataire (WKD)<br/>filtre avant file :10025 : From:, contrôle du contenu, chiffrement PGP/MIME,<br/>en-têtes en liste blanche, Message-ID pseudonymisés"]
        KD["Conteneur keydir<br/>HTTPS :8443 (TLS ≥ 1.2)<br/>dépôt · validation admin<br/>WKD · révocations · audit<br/>métriques :9155 (interne)"]
    end
    PROM["Prometheus<br/>(VLAN supervision)"]

    TB["Poste (Thunderbird)<br/>clé privée locale"]

    subgraph NET["🌐 Internet"]
        MTA["Smarthost du fournisseur"]
    end

    GL & JK & GP -- "587 STARTTLS + AUTH" --> SMTPD
    UNK -- "587" --x SMTPD
    ACL <-- "milter + filtre avant file<br/>(réseau backend interne)" --> GW
    GW -- "message chiffré" --> RI
    SMTP == "587/465 TLS ≥ 1.2 vérifié<br/>AUTH SASL" ==> MTA
    TB -- "HTTPS : dépôt de clé,<br/>WKD (openpgpkey.example.com)" --> KD
    GW -- "HTTPS : WKD (cache)" --> KD
    EXP -. "HTTP :9155 (backend)" .-> KD
    PROM -- "HTTP :9154 /metrics" --> EXP

    classDef deny fill:#fde2e2,stroke:#c0392b,color:#7b1d1d;
    classDef ok fill:#e3f4e8,stroke:#2e8b57,color:#1b4d2e;
    classDef sec fill:#fff4d6,stroke:#b8860b,color:#5c4300;
    class UNK deny;
    class GL,JK,GP ok;
    class INV,ACL sec;
```

Le flux est **strictement sortant** : le relai n'a aucun domaine local
(`mydestination`, `relay_domains` vides, `local_transport = error`), n'écoute
que sur le port 587 et n'est pas joignable depuis Internet.

## Flux

| # | Source → destination | Port | Chiffrement | Authentification | Contrôles |
|---|----------------------|------|-------------|------------------|-----------|
| 1 | Application déclarée → relai | 587/tcp | **STARTTLS obligatoire**, TLS ≥ 1.2, certificat `smtp-relay` | **SASL** PLAIN/LOGIN, un identifiant par application, après STARTTLS uniquement | IP dans l'inventaire ; login ↔ IP ; `MAIL FROM` et `From:` = adresse du login |
| 2 | Hôte non déclaré → relai | 587/tcp | — | — | **refus** `554 5.7.1` dès la connexion + log |
| 3 | Relai ↔ passerelle | 9900/tcp (milter), 10025/tcp (filtre avant file) (réseau `backend` interne) | — (réseau Docker interne) | — | `milter_default_action = tempfail` : passerelle absente ⇒ erreur temporaire |
| 3a | Passerelle → relai (réinjection) | 10026/tcp sur l'adresse backend du relai | — (réseau Docker interne) | IP de la passerelle seule (`mynetworks`) | message déjà chiffré ; aucun milter ni filtre |
| 3b | Passerelle → annuaire | 8443/tcp (réseau `backend` interne) | HTTPS, TLS ≥ 1.2, certificat vérifié | — | WKD ; annuaire injoignable ⇒ `451 4.7.1` (échec fermé) |
| 4 | Relai → smarthost | 587/tcp (STARTTLS) ou 465/tcp | **TLS ≥ 1.2**, certificat vérifié (`secure`) | **SASL** (secrets) | `smtp_tls_security_level` |
| 5 | Poste → annuaire | 443/tcp (8443 dans le conteneur) | **HTTPS**, TLS ≥ 1.2, aucun port en clair | aucune (dépôt public) | clé publiée seulement après validation de l'empreinte par un administrateur ; révocation par certificat signé |
| 6 | Prometheus → relai (F4) | 9154/tcp (publié sur `RELAY_METRICS_BIND_ADDRESS`, `127.0.0.1` par défaut) | — (métadonnées) | — (filtrage réseau) | port à n'ouvrir qu'au serveur Prometheus |
| 6a | Relai (exporteur) → annuaire | 9155/tcp (réseau `backend` interne, non publié) | — (réseau Docker interne) | — | état des clés seulement (expiration, révocation), aucune donnée de clé |
| 6b | Relai (exporteur) → smarthost | comme le flux 4 | TLS ≥ 1.2, certificat vérifié | aucune (EHLO, STARTTLS, QUIT) | sonde périodique (`RELAY_METRICS_PROBE_INTERVAL`) : joignabilité et expiration du certificat |

## Traitement d'un message

```mermaid
sequenceDiagram
    autonumber
    participant App as Application (gitlab)
    participant S as relai smtpd :587
    participant G as passerelle (milter)
    participant Q as file (volume)
    participant M as smarthost

    App->>S: connexion
    alt IP hors inventaire
        S-->>App: 554 5.7.1 Client host rejected (log : IP)
    end
    App->>S: EHLO / STARTTLS (TLS ≥ 1.2)
    App->>S: AUTH PLAIN gitlab
    alt mauvais mot de passe
        S-->>App: 535 5.7.8 (log : IP + login)
    end
    App->>S: MAIL FROM:<gitlab@example.com>
    Note over S: sender_login_maps : sinon 553 5.7.1 not owned by user
    S->>G: MAIL FROM + {auth_authen}
    Note over G: login connu, IP liée au login, enveloppe = adresse
    App->>S: RCPT TO:<alice@example.com>
    S->>G: RCPT
    Note over G: clé d'alice : WKD de l'annuaire (cache)<br/>absente / expirée / révoquée ⇒ 550 5.7.1 pour ce destinataire<br/>annuaire injoignable ⇒ 451 4.7.1
    App->>S: DATA
    S->>G: transaction relayée en temps réel (filtre avant file :10025, rien n'est écrit)
    alt From: ≠ gitlab@example.com, ou contenu interdit (clé privée, jeton, .exe)
        G-->>S: 550 5.7.1 (log : motif / identifiant de règle seulement)
        S-->>App: 550 5.7.1
    else conforme
        Note over G: chiffrement PGP/MIME pour les destinataires acceptés<br/>(en-têtes protégés, objet neutre, en-têtes extérieurs<br/>en liste blanche, Message-ID pseudonymisés)
        G->>S: réinjection du message chiffré (:10026)
        S->>Q: mise en file (chiffré uniquement)
        S-->>G: 250 queued as …
        G-->>S: 250 queued as …
        S-->>App: 250 queued as …
        Q->>M: STARTTLS vérifié + AUTH (Received du relai retiré)
        M-->>Q: 250 → status=sent (sinon deferred, message conservé)
    end
```

## Environnement de test

```mermaid
flowchart LR
    subgraph P["réseau « private » 10.0.1.0/24 (internal)"]
        C1["client-gitlab .10 · jenkins .20<br/>glpi .40 · youtrack .45 · new .50"]
        CU["client-unknown .30<br/>(non déclaré)"]
    end
    R["relay (alias smtp-relay)<br/>10.0.1.5 / 10.0.2.5 / 10.0.3.5"]
    RB["relay-badcreds<br/>mot de passe fournisseur erroné"]
    subgraph B["réseau « backend » 10.0.3.0/24 (internal)"]
        G["gateway .20:9900 (milter), :10025 (filtre)"]
    end
    subgraph I["réseau « internet » 10.0.2.0/24 (internal)"]
        F["provider .10<br/>Postfix :587 STARTTLS + SASL<br/>→ LMTP → Dovecot (BAL)"]
        W["workstation .50<br/>relève IMAPS · clés RNP · GnuPG"]
        K["keydir .30 (aussi backend .30)<br/>alias openpgpkey.example.com"]
    end
    C1 -- "587 STARTTLS vérifié + AUTH" --> R
    CU -- "587" --x R
    C1 -- "587" --> RB
    R <--> G
    RB <--> G
    R == "587 TLS vérifié + SASL" ==> F
    RB -. "SASL refusé → file deferred" .-> F
    W -- "IMAPS 993 (certificat vérifié)" --> F
    W -- "HTTPS 8443 : dépôt, WKD" --> K
```

La PKI de test (AC + certificats `provider`, `smtp-relay`, `keydir`) est
générée par le service one-shot `pki` dans le volume `test-pki`, monté en
lecture seule dans les autres conteneurs. Les clients vérifient le certificat
de `smtp-relay`, le relai vérifie celui du fournisseur (`secure`), le poste de
travail celui de l'IMAPS : toutes les vérifications TLS sont réellement exercées.

## Supervision et journaux

```mermaid
flowchart LR
    subgraph RELAY["Conteneur relay"]
        RUN["relay-run (PID 1, root)"]
        PF["Postfix (master -s)<br/>maillog_file = /dev/stdout"]
        EX["relay-exporter (nobody, groupe postdrop)<br/>HTTP :9154"]
        PF -- "journaux (tube)" --> RUN
        RUN -- "copie non bloquante" --> EX
        EX -- "postqueue -j" --> PF
    end
    RUN -- "stdout (inchangé)" --> DL["logs Docker<br/>(rotation 5 × 10 Mo)"]
    EX -- "HTTP :9155" --> KD["keydir (métriques des clés)"]
    EX -- "TLS : EHLO, STARTTLS, QUIT" --> SH["smarthost"]
    P["Prometheus"] -- "GET /metrics" --> EX
```

- **Aucun contenu dans les journaux** : Postfix, la passerelle et l'annuaire ne
  journalisent que des métadonnées (enveloppe, codes, identifiant de règle) ;
  IT7.5 le vérifie sur tous les conteneurs de la stack de test.
- **Aucun journal persistant dans les conteneurs** : tout part sur la sortie
  standard (rotation Docker) ; l'export syslog TLS (F5) se configure au niveau
  du démon Docker ou d'un collecteur, hors du dépôt.
- **L'exporteur ne bloque jamais le courrier** : `relay-run` lui donne une
  copie non bloquante des journaux (lignes perdues pour les métriques seulement
  en cas de retard) et le relance s'il s'arrête.
