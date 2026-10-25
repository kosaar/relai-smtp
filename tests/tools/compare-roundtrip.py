#!/usr/bin/env python3
"""Compare le résumé d'un message reçu (pgpmime summary, poste de travail) au
manifeste du message envoyé (mkmsg, client).

  compare-roundtrip.py <summary.json> <manifest.json> <objet extérieur attendu>

Vérifie : structure PGP/MIME extérieure, objet extérieur neutre, déchiffrement,
en-têtes protégés v1, objet réel, texte et pièces jointes (nom, taille, SHA-256).
Code 0 si tout est identique ; sinon, les écarts sur stdout et code 1.
"""
import json
import sys


def main() -> int:
    summary = json.load(open(sys.argv[1]))
    manifest = json.load(open(sys.argv[2]))
    neutral = sys.argv[3]
    errors = []
    outer = summary.get("outer", {})
    if outer.get("content_type") != "multipart/encrypted" or outer.get("protocol") != "application/pgp-encrypted":
        errors.append(f"structure extérieure : {outer.get('content_type')} / {outer.get('protocol')}")
    if outer.get("parts") != ["application/pgp-encrypted", "application/octet-stream"]:
        errors.append(f"parties extérieures : {outer.get('parts')}")
    if outer.get("subject") != neutral:
        errors.append(f"objet extérieur : {outer.get('subject')!r} (attendu {neutral!r})")
    if not summary.get("decrypted"):
        errors.append("message indéchiffrable")
    else:
        inner = summary["inner"]
        if inner.get("protected_headers") != "v1":
            errors.append(f"protected-headers : {inner.get('protected_headers')!r}")
        if inner.get("subject") != manifest["subject"]:
            errors.append(f"objet réel : {inner.get('subject')!r} (attendu {manifest['subject']!r})")
        if manifest["text"].strip() not in inner.get("text", ""):
            errors.append("texte du message différent")
        got = sorted((a["name"], a["size"], a["sha256"]) for a in inner.get("attachments", []))
        want = sorted((a["name"], a["size"], a["sha256"]) for a in manifest["attachments"])
        if got != want:
            errors.append(f"pièces jointes : {got} (attendu {want})")
    for e in errors:
        print(e)
    if not errors:
        n = len(manifest["attachments"])
        print(f"identique : objet, texte et {n} pièce(s) jointe(s) (SHA-256)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
