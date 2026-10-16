# secrets/

Ce dossier reçoit les **Docker secrets** du relai. Son contenu est ignoré par git
(seuls ce README et les fichiers `*.example` sont versionnés).

| Fichier               | Contenu                                         |
|-----------------------|-------------------------------------------------|
| `relay_smtp_username` | identifiant SMTP fourni par le fournisseur cloud |
| `relay_smtp_password` | mot de passe / clé SMTP du fournisseur cloud     |

```bash
install -m 600 /dev/null secrets/relay_smtp_username
install -m 600 /dev/null secrets/relay_smtp_password
printf '%s' 'AKIA...'      > secrets/relay_smtp_username   # sans saut de ligne
printf '%s' 'mot-de-passe' > secrets/relay_smtp_password
```

Les secrets sont montés en lecture seule dans `/run/secrets/` du conteneur ;
l'entrypoint les copie dans `/etc/postfix/sasl_passwd` (tmpfs, `root:root 0600`).
