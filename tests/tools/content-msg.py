#!/usr/bin/env python3
"""Message de test pour le contrôle du contenu (suite 06), sur stdout.

Usage : content-msg.py <cas> <identifiant> [secret]
  privkey  bloc de clé privée OpenSSH dans le corps (secret = corps de la clé)
  token    jeton GitLab dans une pièce jointe encodée en base64 (secret = jeton)
  exe      pièce jointe outil.exe
  clean    message sain : texte et pièce jointe PDF
"""
import sys
from email.message import EmailMessage
from email.policy import SMTP

case, ident = sys.argv[1], sys.argv[2]
secret = sys.argv[3] if len(sys.argv) > 3 else ""
m = EmailMessage(policy=SMTP)
m["From"] = "GitLab <gitlab@example.com>"
m["To"] = "alice@example.com"
m["Subject"] = f"{ident} contrôle du contenu ({case})"
if case == "privkey":
    m.set_content(f"Clé de déploiement ci-dessous.\n\n-----BEGIN OPENSSH PRIVATE KEY-----\n{secret}\n"
                  "-----END OPENSSH PRIVATE KEY-----\n")
elif case == "token":
    m.set_content("Configuration du runner en pièce jointe.")
    m.add_attachment(f"url: https://gitlab.example.com\ntoken: {secret}\n".encode(), maintype="application",
                     subtype="octet-stream", filename="runner-config.yml")
elif case == "exe":
    m.set_content("Outil en pièce jointe.")
    m.add_attachment(b"MZ\x90\x00" + bytes(range(256)) * 4, maintype="application", subtype="octet-stream",
                     filename="outil.exe")
elif case == "clean":
    m.set_content("Rapport hebdomadaire. La clé publique (PUBLIC KEY) est publiée sur l'annuaire.")
    m.add_attachment(b"%PDF-1.7\n" + bytes(range(256)) * 8, maintype="application", subtype="pdf",
                     filename="rapport.pdf")
else:
    sys.exit(f"cas inconnu : {case}")
sys.stdout.buffer.write(m.as_bytes())
