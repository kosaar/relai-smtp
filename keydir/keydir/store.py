"""Stockage SQLite de l'annuaire (clés et journal d'audit).

États d'une clé (par couple adresse + empreinte) :
  pending     déposée, en attente de validation par un administrateur ;
  approved    validée : publiée dans le WKD (une seule par adresse) ;
  rejected    refusée par un administrateur ;
  superseded  remplacée par une clé plus récente validée (rotation) ;
  revoked     révoquée : par certificat (la clé révoquée reste publiée pour
              informer les clients) ou par un administrateur (dépubliée).
Le journal d'audit ne contient que des métadonnées.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

from keydir import openpgp, wkd

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    id           INTEGER PRIMARY KEY,
    email        TEXT NOT NULL,
    domain       TEXT NOT NULL,
    wkd_hash     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending','approved','rejected','superseded','revoked')),
    algo         TEXT NOT NULL,
    created      INTEGER NOT NULL,
    expires      INTEGER,
    submitted_at INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    revoked_by   TEXT,
    key_data     BLOB NOT NULL,
    wkd_data     BLOB,
    UNIQUE (email, fingerprint)
);
CREATE INDEX IF NOT EXISTS keys_wkd ON keys (domain, wkd_hash);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    action      TEXT NOT NULL,
    email       TEXT,
    fingerprint TEXT,
    actor       TEXT NOT NULL,
    result      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
"""
PUBLISHED = ("approved", "revoked")


class StoreError(Exception):
    pass


@dataclass
class KeyRow:
    email: str
    fingerprint: str
    state: str
    algo: str
    created: int
    expires: int | None
    submitted_at: int
    updated_at: int
    revoked_by: str | None
    published: bool

    def as_dict(self) -> dict:
        return {"email": self.email, "fingerprint": self.fingerprint, "state": self.state,
                "algorithm": self.algo, "created": self.created, "expires": self.expires,
                "submitted_at": self.submitted_at, "updated_at": self.updated_at,
                "revoked_by": self.revoked_by, "published": self.published}


COLS = "email, fingerprint, state, algo, created, expires, submitted_at, updated_at, revoked_by, wkd_data IS NOT NULL"


class Store:
    def __init__(self, path: str):
        self.path = path
        db = sqlite3.connect(path, timeout=15)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        finally:
            db.close()

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _audit(db, action: str, email: str | None, fpr: str | None, actor: str, result: str):
        db.execute("INSERT INTO audit (ts, action, email, fingerprint, actor, result) VALUES (?,?,?,?,?,?)",
                   (int(time.time()), action, email, fpr, actor, result))

    def audit(self, action: str, email: str | None, fpr: str | None, actor: str, result: str):
        with self._db() as db:
            self._audit(db, action, email, fpr, actor, result)

    # -- lecture --------------------------------------------------------------
    def keys(self, email: str | None = None, state: str | None = None) -> list[KeyRow]:
        sql, args = f"SELECT {COLS} FROM keys WHERE 1=1", []
        if email:
            sql += " AND email = ?"
            args.append(email)
        if state:
            sql += " AND state = ?"
            args.append(state)
        with self._db() as db:
            rows = db.execute(sql + " ORDER BY email, submitted_at", args).fetchall()
        return [KeyRow(*r[:9], bool(r[9])) for r in rows]

    def status(self, email: str) -> dict:
        rows = self.keys(email)
        published = [r for r in rows if r.published]
        pending = [r.fingerprint for r in rows if r.state == "pending"]
        if published:
            cur = max(published, key=lambda r: r.updated_at)
            out = {"email": email, "state": cur.state, "fingerprint": cur.fingerprint, "expires": cur.expires}
        elif pending:
            out = {"email": email, "state": "pending", "fingerprint": pending[-1], "expires": None}
        elif any(r.state == "revoked" for r in rows):
            out = {"email": email, "state": "revoked", "fingerprint": None, "expires": None}
        else:
            out = {"email": email, "state": "none", "fingerprint": None, "expires": None}
        out["pending"] = pending
        return out

    def wkd_lookup(self, domain: str, wkd_hash: str) -> bytes | None:
        with self._db() as db:
            row = db.execute("SELECT wkd_data FROM keys WHERE domain = ? AND wkd_hash = ? AND state IN (?, ?) "
                             "AND wkd_data IS NOT NULL ORDER BY updated_at DESC LIMIT 1",
                             (domain, wkd_hash, *PUBLISHED)).fetchone()
        return row[0] if row else None

    def domains(self) -> set[str]:
        with self._db() as db:
            return {r[0] for r in db.execute("SELECT DISTINCT domain FROM keys")}

    # -- écriture -------------------------------------------------------------
    def deposit(self, email: str, info: openpgp.KeyInfo, algo: str, key_data: bytes, actor: str) -> str:
        """Enregistre une clé valide ; renvoie son état (pending ou approved si déjà validée)."""
        now = int(time.time())
        local, _, domain = email.partition("@")
        with self._db() as db:
            row = db.execute("SELECT state FROM keys WHERE email = ? AND fingerprint = ?",
                             (email, info.fingerprint)).fetchone()
            if row and row[0] == "revoked":
                self._audit(db, "deposit", email, info.fingerprint, actor, "refused:revoked")
                raise StoreError("cette clé a été révoquée : déposez une nouvelle clé")
            if row and row[0] in ("approved", "pending"):
                state = row[0]
                db.execute("UPDATE keys SET key_data = ?, expires = ?, updated_at = ? WHERE email = ? AND fingerprint = ?",
                           (key_data, info.expires, now, email, info.fingerprint))
            elif row:
                state = "pending"
                db.execute("UPDATE keys SET state = 'pending', key_data = ?, expires = ?, submitted_at = ?, "
                           "updated_at = ?, wkd_data = NULL WHERE email = ? AND fingerprint = ?",
                           (key_data, info.expires, now, now, email, info.fingerprint))
            else:
                state = "pending"
                db.execute("INSERT INTO keys (email, domain, wkd_hash, fingerprint, state, algo, created, expires, "
                           "submitted_at, updated_at, key_data) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (email, domain, wkd.wkd_hash(local), info.fingerprint, state, algo, info.created,
                            info.expires, now, now, key_data))
            self._audit(db, "deposit", email, info.fingerprint, actor, state)
        return state

    def _get(self, db, email: str, fpr: str):
        return db.execute("SELECT state, key_data FROM keys WHERE email = ? AND fingerprint = ?",
                          (email, fpr)).fetchone()

    def approve(self, email: str, fpr: str, actor: str) -> list[str]:
        """Valide une clé en attente ; renvoie les empreintes remplacées (rotation)."""
        now = int(time.time())
        with self._db() as db:
            row = self._get(db, email, fpr)
            if not row or row[0] != "pending":
                raise StoreError(f"aucune clé en attente pour {email} avec l'empreinte {fpr}")
            blob = openpgp.export_for_wkd(row[1], fpr, email)
            old = [r[0] for r in db.execute(
                "SELECT fingerprint FROM keys WHERE email = ? AND state IN (?, ?) AND wkd_data IS NOT NULL",
                (email, *PUBLISHED))]
            db.execute("UPDATE keys SET state = 'superseded', wkd_data = NULL, updated_at = ? "
                       "WHERE email = ? AND state = 'approved'", (now, email))
            db.execute("UPDATE keys SET wkd_data = NULL, updated_at = ? WHERE email = ? AND state = 'revoked'",
                       (now, email))
            db.execute("UPDATE keys SET state = 'approved', wkd_data = ?, updated_at = ? "
                       "WHERE email = ? AND fingerprint = ?", (blob, now, email, fpr))
            self._audit(db, "approve", email, fpr, actor, "approved" + (f" supersedes={','.join(old)}" if old else ""))
        return old

    def reject(self, email: str, fpr: str, actor: str):
        with self._db() as db:
            row = self._get(db, email, fpr)
            if not row or row[0] != "pending":
                raise StoreError(f"aucune clé en attente pour {email} avec l'empreinte {fpr}")
            db.execute("UPDATE keys SET state = 'rejected', updated_at = ? WHERE email = ? AND fingerprint = ?",
                       (int(time.time()), email, fpr))
            self._audit(db, "reject", email, fpr, actor, "rejected")

    def revoke_admin(self, email: str, actor: str) -> list[str]:
        """Révocation administrative : clés validées et en attente dépubliées."""
        with self._db() as db:
            fprs = [r[0] for r in db.execute("SELECT fingerprint FROM keys WHERE email = ? AND state IN ('approved','pending')",
                                             (email,))]
            if not fprs:
                raise StoreError(f"aucune clé validée ou en attente pour {email}")
            db.execute("UPDATE keys SET state = 'revoked', revoked_by = 'admin', wkd_data = NULL, updated_at = ? "
                       "WHERE email = ? AND state IN ('approved','pending')", (int(time.time()), email))
            for f in fprs:
                self._audit(db, "revoke", email, f, actor, "revoked:admin")
        return fprs

    def revoke_certificate(self, email: str, revocation: bytes, actor: str) -> str:
        """Applique un certificat de révocation à la clé (validée ou en attente) qu'il concerne."""
        now = int(time.time())
        with self._db() as db:
            rows = db.execute("SELECT fingerprint, state, key_data FROM keys WHERE email = ? AND state IN "
                              "('approved','pending','superseded')", (email,)).fetchall()
            for fpr, state, key_data in rows:
                revoked = openpgp.apply_revocation(key_data, fpr, revocation)
                if revoked is None:
                    continue
                blob = openpgp.export_for_wkd(revoked, fpr, email) if state == "approved" else None
                db.execute("UPDATE keys SET state = 'revoked', revoked_by = 'certificate', key_data = ?, "
                           "wkd_data = ?, updated_at = ? WHERE email = ? AND fingerprint = ?",
                           (revoked, blob, now, email, fpr))
                self._audit(db, "revoke", email, fpr, actor, "revoked:certificate")
                return fpr
            self._audit(db, "revoke", email, None, actor, "refused:no-matching-key")
        raise StoreError(f"ce certificat de révocation ne s'applique à aucune clé de {email}")

    def remove(self, email: str, actor: str) -> int:
        with self._db() as db:
            n = db.execute("DELETE FROM keys WHERE email = ?", (email,)).rowcount
            self._audit(db, "remove", email, None, actor, f"removed:{n}")
        return n

    def purge_audit(self, retention_days: int) -> int:
        limit = int(time.time()) - retention_days * 86400
        with self._db() as db:
            return db.execute("DELETE FROM audit WHERE ts < ?", (limit,)).rowcount

    def audit_entries(self, limit: int = 50) -> list[tuple]:
        with self._db() as db:
            return db.execute("SELECT ts, action, email, fingerprint, actor, result FROM audit "
                              "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
