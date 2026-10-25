"""Chiffrement OpenPGP (GnuPG) d'un message pour tous ses destinataires.

Un seul message chiffré par transaction. Identifiants de clés masqués
(--throw-keyids) lorsqu'il n'y a qu'un destinataire ; avec plusieurs
destinataires, ils restent visibles : RNP (bibliothèque OpenPGP de
Thunderbird, 0.18) n'essaie que le PREMIER destinataire masqué, les suivants
ne pourraient pas déchiffrer. Conséquence documentée : dans un message à
plusieurs destinataires, chacun voit l'identifiant des sous-clés des autres
(y compris d'un destinataire en copie cachée).
La confiance repose sur la validation des clés par l'annuaire
(--trust-model always). Trousseau jetable, clés publiques seulement.
"""
from __future__ import annotations

from pgpkeys import openpgp


def encrypt(data: bytes, recipients: list[tuple[str, bytes]]) -> bytes:
    """Message chiffré (armure ASCII) pour les (empreinte, clé) donnés."""
    if not recipients:
        raise openpgp.GpgError("aucun destinataire")
    with openpgp.temp_home() as home:
        for _, key in recipients:
            openpgp._gpg(home, ["--import"], key)
        args = ["--encrypt", "--armor", "--trust-model", "always", "--no-encrypt-to", "--output", "-"]
        if len(recipients) == 1:
            args.append("--throw-keyids")
        for fpr, _ in recipients:
            args += ["--recipient", fpr]
        out = openpgp._gpg(home, args, data).stdout
    if b"-----BEGIN PGP MESSAGE-----" not in out:
        raise openpgp.GpgError("sortie de chiffrement inattendue")
    return out
