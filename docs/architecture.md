# Architecture du relai SMTP

> État actuel : lot 1 du [plan d'implémentation](plan-implementation.md)
> (soumission 587 authentifiée, identité par application, passerelle milter).
> Les lots suivants ajoutent l'annuaire de clés, le chiffrement OpenPGP, les
> quotas, le contrôle du contenu et la supervision.

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
            Q[("Volume relay-queue")]
            SMTP["client smtp<br/>relayhost = [fournisseur]:587"]
            INV{{"config/applications.toml<br/>secrets/apps/&lt;nom&gt;"}}
            SMTPD --> ACL --> Q --> SMTP
            INV -. "relay-config<br/>(au démarrage)" .-> ACL
        end
        GW["Conteneur gateway<br/>milter Python :9900<br/>login ↔ IP ↔ From:"]
    end

    subgraph NET["🌐 Internet"]
        MTA["Smarthost du fournisseur"]
    end

    GL & JK & GP -- "587 STARTTLS + AUTH" --> SMTPD
    UNK -- "587" --x SMTPD
    ACL <-- "milter, avant la mise en file<br/>(réseau backend interne)" --> GW
    SMTP == "587/465 TLS ≥ 1.2 vérifié<br/>AUTH SASL" ==> MTA

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
| 3 | Relai ↔ passerelle | 9900/tcp (réseau `backend` interne) | — (réseau Docker interne) | — | `milter_default_action = tempfail` : passerelle absente ⇒ `451` |
| 4 | Relai → smarthost | 587/tcp (STARTTLS) ou 465/tcp | **TLS ≥ 1.2**, certificat vérifié (`secure`) | **SASL** (secrets) | `smtp_tls_security_level` |

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
    App->>S: RCPT TO / DATA
    S->>G: en-têtes + fin du message
    alt From: ≠ gitlab@example.com
        G-->>S: 550 5.7.1 (log : motif seulement)
        S-->>App: 550 5.7.1
    else conforme
        G-->>S: accept
        S->>Q: 250 queued
        Q->>M: STARTTLS vérifié + AUTH
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
        G["gateway .20:9900"]
    end
    subgraph I["réseau « internet » 10.0.2.0/24 (internal)"]
        F["provider .10<br/>Postfix :587 STARTTLS + SASL<br/>→ LMTP → Dovecot (BAL)"]
        W["workstation .50<br/>relève IMAPS · RNP · GnuPG"]
    end
    C1 -- "587 STARTTLS vérifié + AUTH" --> R
    CU -- "587" --x R
    C1 -- "587" --> RB
    R <--> G
    RB <--> G
    R == "587 TLS vérifié + SASL" ==> F
    RB -. "SASL refusé → file deferred" .-> F
    W -- "IMAPS 993 (certificat vérifié)" --> F
```

La PKI de test (AC + certificats `provider`, `smtp-relay`, `keydir`) est
générée par le service one-shot `pki` dans le volume `test-pki`, monté en
lecture seule dans les autres conteneurs. Les clients vérifient le certificat
de `smtp-relay`, le relai vérifie celui du fournisseur (`secure`), le poste de
travail celui de l'IMAPS : toutes les vérifications TLS sont réellement exercées.
