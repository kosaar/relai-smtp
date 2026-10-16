# Architecture du relai SMTP

## Vue d'ensemble

```mermaid
flowchart LR
    subgraph PRIV["🔒 Réseau privé (LAN / VPC)"]
        direction TB
        GL["GitLab CE<br/>10.0.1.10"]
        JK["Jenkins<br/>10.0.1.20"]
        UNK["Application inconnue<br/>10.0.1.30 (non déclarée)"]

        subgraph RELAY["Conteneur relay — Postfix (Debian trixie-slim)"]
            direction TB
            SMTPD["smtpd :25<br/>smtpd_client_restrictions =<br/>permit_mynetworks, reject"]
            WL[/"Liste blanche mynetworks<br/>10.0.1.10/32, 10.0.1.20/32<br/>(ALLOWED_CLIENT_IPS)<br/>tout le reste : REFUS"/]
            RW[["cleanup : réécriture expéditeur<br/>sender_canonical_maps<br/>MAIL FROM + From: → noreply@example.com"]]
            Q[("Volume relay-queue<br/>/var/spool/postfix")]
            SMTP["smtp client<br/>relayhost = [provider]:587"]
            SEC{{"Docker secrets<br/>relay_smtp_username<br/>relay_smtp_password"}}
            SMTPD --> WL
            WL -- autorisé --> RW --> Q --> SMTP
            SEC -. "sasl_passwd (tmpfs, 0600)" .-> SMTP
        end
    end

    subgraph NET["🌐 Internet"]
        MTA["MTA fournisseur cloud<br/>smtp.example-provider.com<br/>(SES / SendGrid / Mailjet / Brevo)"]
    end

    GL -- "SMTP :25<br/>clair · sans auth" --> SMTPD
    JK -- "SMTP :25<br/>clair · sans auth" --> SMTPD
    UNK -- "SMTP :25" --x SMTPD
    WL -. "554 5.7.1 Client host rejected:<br/>Access denied (+ log IP source)" .-> UNK
    SMTP == "SMTP :587 STARTTLS (ou :465 TLS)<br/>TLS ≥ 1.2 · certificat vérifié<br/>AUTH SASL PLAIN/LOGIN" ==> MTA

    classDef deny fill:#fde2e2,stroke:#c0392b,color:#7b1d1d;
    classDef ok fill:#e3f4e8,stroke:#2e8b57,color:#1b4d2e;
    classDef sec fill:#fff4d6,stroke:#b8860b,color:#5c4300;
    class UNK deny;
    class GL,JK ok;
    class SEC,WL sec;
```

Le flux est **strictement sortant** : le relai n'a aucun domaine local
(`mydestination`, `relay_domains` vides, `local_transport = error`) et n'est
pas joignable depuis Internet.

## Flux

| # | Source → destination | Port | Protocole | Chiffrement | Authentification | Contrôle |
|---|----------------------|------|-----------|-------------|------------------|----------|
| 1 | GitLab (10.0.1.10) → relai | 25/tcp | SMTP | aucun (réseau privé) | aucune | IP en liste blanche `/32` |
| 2 | Jenkins (10.0.1.20) → relai | 25/tcp | SMTP | aucun (réseau privé) | aucune | IP en liste blanche `/32` |
| 3 | Application inconnue → relai | 25/tcp | SMTP | — | — | **rejet** `554 5.7.1` à RCPT TO + log |
| 4 | Relai → MTA fournisseur | 587/tcp (STARTTLS) ou 465/tcp (TLS implicite) | ESMTP | **TLS ≥ 1.2 obligatoire**, certificat vérifié (`secure`) | **SASL** user/password (Docker secrets) | `smtp_tls_security_level` |

## Traitement d'un message

```mermaid
sequenceDiagram
    autonumber
    participant App as GitLab / Jenkins
    participant S as relai smtpd :25
    participant C as cleanup (réécriture)
    participant Q as file (volume)
    participant M as MTA fournisseur

    App->>S: EHLO / MAIL FROM:<gitlab@ci.internal> / RCPT TO
    alt IP ∈ mynetworks (liste blanche)
        S-->>App: 250 OK
        App->>S: DATA (From: "GitLab" <gitlab@ci.internal>)
        S->>C: message
        C->>Q: MAIL FROM + From: réécrits en noreply@example.com
        Q->>M: STARTTLS (TLS ≥ 1.2, certificat vérifié) puis AUTH PLAIN
        alt identifiants valides
            M-->>Q: 250 queued → status=sent, message retiré de la file
        else identifiants refusés / MTA injoignable
            M-->>Q: 535 / timeout → status=deferred, message conservé et réessayé
        end
    else IP inconnue
        S-->>App: 554 5.7.1 Client host rejected: Access denied
        Note over S: log : NOQUEUE: reject: RCPT from ?[IP] ... Access denied
    end
```

## Environnement de test

```mermaid
flowchart LR
    subgraph P["réseau docker « private » 10.0.1.0/24 (internal)"]
        CG["client-gitlab<br/>10.0.1.10 · swaks"]
        CJ["client-jenkins<br/>10.0.1.20 · swaks"]
        CU["client-unknown<br/>10.0.1.30 · swaks"]
    end
    R["relay<br/>10.0.1.5 / 10.0.2.5<br/>identifiants valides"]
    RB["relay-badcreds<br/>10.0.1.6 / 10.0.2.6<br/>mot de passe erroné"]
    subgraph I["réseau docker « internet » 10.0.2.0/24 (internal)"]
        F["fake-mta 10.0.2.10:587<br/>Postfix + STARTTLS obligatoire<br/>+ SASL (sasldb) → *.eml"]
    end
    CG -- ":25 clair" --> R
    CJ -- ":25 clair" --> R
    CU -- ":25" --x R
    CG -- ":25" --> RB
    R == "587 TLS + SASL OK" ==> F
    RB -. "587 TLS, SASL refusé → file deferred" .-> F
```

La PKI de test (AC + certificat `fake-mta`) est générée par le faux MTA dans
le volume `test-pki`, monté en lecture seule dans le relai
(`RELAY_TLS_CA_FILE`) : le mode `secure` (vérification du certificat et du nom)
est donc réellement exercé.
