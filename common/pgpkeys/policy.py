"""Règles d'acceptation d'une clé déposée (fonctions pures, testées unitairement).

  - un seul certificat (clé primaire) par dépôt ;
  - non révoqué, non expiré ;
  - une identité (UID) non révoquée portant exactement l'adresse demandée ;
  - adresse dans un domaine géré par l'annuaire ;
  - au moins une SOUS-CLÉ de chiffrement valide (ni expirée ni révoquée) ;
  - algorithmes acceptés : RSA >= 3072 bits, Ed25519 (signature), Cv25519 /
    X25519 (chiffrement), en clés v4 ou v6.
"""
from __future__ import annotations

import re

from pgpkeys.openpgp import KeyInfo, SubKey

EMAIL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RSA_ALGOS = {1, 2, 3}
MIN_RSA_BITS = 3072
ED25519 = {"ed25519"}
CV25519 = {"cv25519", "curve25519", "x25519"}


def normalize_email(email: str | None) -> str | None:
    email = (email or "").strip().lower()
    return email if EMAIL_RE.match(email) else None


def _algo_ok(algo: int, bits: int, curve: str, usage: str) -> bool:
    curve = curve.lower()
    if algo in RSA_ALGOS:
        return bits >= MIN_RSA_BITS
    if usage == "sign":
        return (algo == 22 and curve in ED25519) or algo == 27
    return (algo == 18 and curve in CV25519) or algo == 25


def algo_name(algo: int, bits: int, curve: str) -> str:
    if algo in RSA_ALGOS:
        return f"RSA {bits}"
    return {22: "EdDSA", 27: "Ed25519", 18: "ECDH", 25: "X25519", 19: "ECDSA", 17: "DSA", 16: "ElGamal"}.get(
        algo, f"algo {algo}") + (f" {curve}" if curve else "")


def _expired(expires: int | None, now: int) -> bool:
    return expires is not None and expires <= now


def usable_encryption_subkeys(info: KeyInfo, now: int) -> list[SubKey]:
    return [s for s in info.subkeys
            if "e" in s.caps.lower() and not s.revoked and not _expired(s.expires, now)
            and _algo_ok(s.algo, s.bits, s.curve, "encrypt")]


def check_key(keys: list[KeyInfo], email: str, domains: set[str], now: int) -> list[str]:
    """Liste des motifs de refus (vide si la clé est acceptable pour `email`)."""
    if not keys:
        return ["contenu illisible : aucune clé publique OpenPGP trouvée"]
    if len(keys) > 1:
        return [f"un seul certificat par dépôt ({len(keys)} trouvés)"]
    info = keys[0]
    errors = []
    domain = email.rpartition("@")[2]
    if domains and domain not in domains:
        errors.append(f"domaine '{domain}' non géré par l'annuaire")
    if info.revoked:
        errors.append("clé révoquée")
    if _expired(info.expires, now):
        errors.append("clé expirée")
    if not _algo_ok(info.algo, info.bits, info.curve, "sign"):
        errors.append(f"algorithme de la clé primaire refusé ({algo_name(info.algo, info.bits, info.curve)} ; "
                      f"acceptés : RSA >= {MIN_RSA_BITS}, Ed25519)")
    if email not in info.emails():
        found = ", ".join(sorted(info.emails())) or "aucune"
        errors.append(f"aucune identité (UID) valide pour {email} (trouvées : {found})")
    if not usable_encryption_subkeys(info, now):
        subs = [s for s in info.subkeys if "e" in s.caps.lower()]
        if not subs:
            errors.append("aucune sous-clé de chiffrement")
        else:
            details = ", ".join(
                algo_name(s.algo, s.bits, s.curve) + (" révoquée" if s.revoked else "")
                + (" expirée" if _expired(s.expires, now) else "") for s in subs)
            errors.append(f"aucune sous-clé de chiffrement valide ({details} ; acceptées : RSA >= {MIN_RSA_BITS}, Cv25519/X25519)")
    return errors
