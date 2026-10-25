# secrets/

Ce dossier reçoit les **secrets** du relai. Son contenu est ignoré par git
(seuls ce README et les fichiers `*.example` sont versionnés). Les valeurs
viennent du coffre-fort de l'équipe, jamais d'un fichier versionné.

| Fichier                 | Contenu                                                     |
|-------------------------|-------------------------------------------------------------|
| `relay_smtp_username`   | identifiant SMTP fourni par le fournisseur cloud             |
| `relay_smtp_password`   | mot de passe / clé SMTP du fournisseur cloud                 |
| `relay_tls_cert`        | certificat (et chaîne) de `smtp-relay`, présenté sur le 587  |
| `relay_tls_key`         | clé privée correspondante                                    |
| `keydir_tls_cert`       | certificat (et chaîne) de l'annuaire, pour `openpgpkey.<domaine>` (WKD) et le nom utilisé par les postes |
| `keydir_tls_key`        | clé privée correspondante                                    |
| `apps/<application>`    | mot de passe SMTP de chaque application de `config/applications.toml` (16 caractères minimum, une ligne) |

```bash
install -d -m 700 secrets/apps
install -m 600 /dev/null secrets/relay_smtp_username
install -m 600 /dev/null secrets/relay_smtp_password
printf '%s' 'AKIA...'      > secrets/relay_smtp_username   # sans saut de ligne
printf '%s' 'mot-de-passe' > secrets/relay_smtp_password
install -m 600 smtp-relay.crt secrets/relay_tls_cert
install -m 600 smtp-relay.key secrets/relay_tls_key
install -m 600 keydir.crt secrets/keydir_tls_cert
install -m 600 keydir.key secrets/keydir_tls_key
# Un mot de passe par application (le nom du fichier = login SMTP = nom dans l'inventaire)
for app in gitlab jenkins glpi youtrack; do
    install -m 600 /dev/null "secrets/apps/$app"
    openssl rand -base64 32 | tr -d '\n' > "secrets/apps/$app"
done
```

Au démarrage, le relai :
- refuse de démarrer si un secret d'application manque ou fait moins de
  16 caractères (`relay-config check`) ;
- construit la base SASL des applications dans un tmpfs (`/etc/postfix/sasl`,
  `root:postfix 0640`), reconstruite à chaque démarrage ;
- copie les identifiants du fournisseur dans `/etc/postfix/sasl_passwd`
  (tmpfs, `root:root 0600`) et le certificat dans `/etc/postfix/tls`
  (tmpfs, `0600`).

L'annuaire (`keydir`) copie son certificat et sa clé dans un tmpfs lisible par
son seul utilisateur (`keydir`, `0600`), puis abandonne les privilèges root.

Rotation d'un mot de passe d'application : remplacer le fichier, puis
`docker compose restart relay` (et mettre à jour l'application).
