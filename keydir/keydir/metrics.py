"""Métriques Prometheus de l'annuaire (F4) : état des clés, sans aucune donnée de clé.

Servies en HTTP sur un port interne (KEYDIR_METRICS_LISTEN, 9155 par défaut),
non publié : l'exporteur du relai les lit par le réseau backend et les
recopie dans ses propres métriques.

  keydir_keys{state}                        lignes de l'annuaire par état
  keydir_expiry_warning_days                seuil « proche de l'expiration »
  keydir_keys_expiring_soon                 clés publiées expirant dans le seuil
  keydir_key_expiring_soon{email}           1 pour chacune de ces adresses
  keydir_keys_expired                       clés publiées déjà expirées
  keydir_key_expired{email}                 1 pour chacune (la passerelle les refuse)
  keydir_keys_revoked                       adresses dont la clé est révoquée, sans remplaçante
  keydir_key_revoked{email}                 1 pour chacune
  keydir_key_expiry_timestamp_seconds{email}  expiration de chaque clé publiée (si elle expire)
"""
from __future__ import annotations

from collections import defaultdict

STATES = ("pending", "approved", "rejected", "superseded", "revoked")


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(rows, now: int, warning_days: int) -> str:
    """rows : lignes de Store.keys() (email, state, expires…)."""
    counts = {s: 0 for s in STATES}
    by_email = defaultdict(list)
    for r in rows:
        counts[r.state] = counts.get(r.state, 0) + 1
        by_email[r.email].append(r)
    limit = now + warning_days * 86400
    expiring, expired, revoked, expiry = [], [], [], []
    for email in sorted(by_email):
        approved = [r for r in by_email[email] if r.state == "approved"]
        if approved:
            r = approved[-1]
            if r.expires is not None:
                expiry.append((email, r.expires))
                if r.expires <= now:
                    expired.append(email)
                elif r.expires <= limit:
                    expiring.append(email)
        elif any(r.state == "revoked" for r in by_email[email]):
            revoked.append(email)

    out = ["# HELP keydir_keys Clés de l'annuaire par état", "# TYPE keydir_keys gauge"]
    out += [f'keydir_keys{{state="{s}"}} {n}' for s, n in sorted(counts.items())]
    out += ["# HELP keydir_expiry_warning_days Seuil « proche de l'expiration » (jours)",
            "# TYPE keydir_expiry_warning_days gauge", f"keydir_expiry_warning_days {warning_days}"]
    for name, help_text, emails in (
            ("expiring_soon", "Clés publiées expirant dans le seuil d'alerte", expiring),
            ("expired", "Clés publiées expirées (destinataires refusés par la passerelle)", expired),
            ("revoked", "Adresses dont la clé est révoquée, sans clé de remplacement validée", revoked)):
        out += [f"# HELP keydir_keys_{name} {help_text}", f"# TYPE keydir_keys_{name} gauge",
                f"keydir_keys_{name} {len(emails)}",
                f"# HELP keydir_key_{name} {help_text} (1 par adresse)", f"# TYPE keydir_key_{name} gauge"]
        out += [f'keydir_key_{name}{{email="{_esc(e)}"}} 1' for e in emails]
    out += ["# HELP keydir_key_expiry_timestamp_seconds Expiration de la clé publiée de chaque adresse (epoch)",
            "# TYPE keydir_key_expiry_timestamp_seconds gauge"]
    out += [f'keydir_key_expiry_timestamp_seconds{{email="{_esc(e)}"}} {ts}' for e, ts in expiry]
    return "\n".join(out) + "\n"
