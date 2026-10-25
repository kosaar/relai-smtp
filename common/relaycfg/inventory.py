"""Inventaire des applications autorisées à envoyer (config/applications.toml).

Format :

    sender_domain = "example.com"

    [defaults]
    quota_per_hour = 200

    [applications.gitlab]
    address = "gitlab@example.com"     # adresse expéditrice liée au login « gitlab »
    client_ips = ["10.0.1.10"]         # IP d'hôte (pas de CIDR)
    quota_per_hour = 500               # optionnel (défaut : [defaults])
    description = "GitLab CE"          # optionnel

Le nom de la table (« gitlab ») est le login SASL de l'application ; son mot
de passe est le fichier <répertoire des secrets>/<nom>.

Application locale : client_ips = ["127.0.0.1"] (ou ["::1"]), seule IP de
l'application, la réserve aux processus du conteneur du relai lui-même
(message de contrôle de relay-smoke-test). Aucune autre adresse de bouclage
n'est acceptée.
Toutes les erreurs sont collectées puis signalées ensemble (InventoryError).
"""
from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LOCAL_IPS = ("127.0.0.1", "::1")   # bouclage : application locale au conteneur du relai
MIN_PASSWORD_LEN = 16
QUOTA_MAX = 100_000
DEFAULT_QUOTA = 200

TOP_KEYS = {"sender_domain", "defaults", "applications"}
DEFAULT_KEYS = {"quota_per_hour"}
APP_KEYS = {"address", "client_ips", "quota_per_hour", "description"}


class InventoryError(Exception):
    """Inventaire invalide : `errors` contient tous les problèmes détectés."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class Application:
    name: str
    address: str
    client_ips: tuple[str, ...]
    quota_per_hour: int
    description: str = ""


@dataclass(frozen=True)
class Inventory:
    sender_domain: str
    applications: dict[str, Application]

    def by_login(self, login: str | None) -> Application | None:
        return self.applications.get(login) if login else None

    def client_ips(self) -> list[str]:
        """IP de toutes les applications (liste blanche du relai), triées, sans doublon."""
        ips = {ip for app in self.applications.values() for ip in app.client_ips}
        return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version, ipaddress.ip_address(s)))


def _quota(value, where: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= QUOTA_MAX:
        errors.append(f"{where} : quota_per_hour={value!r} invalide (entier de 1 à {QUOTA_MAX}).")
        return None
    return value


def _ip(value, where: str, errors: list[str]) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{where} : IP {value!r} invalide (chaîne attendue).")
        return None
    if "/" in value:
        errors.append(f"{where} : '{value}' refusée : une adresse d'hôte unique est attendue (pas de CIDR).")
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        errors.append(f"{where} : '{value}' n'est pas une adresse IPv4 ou IPv6.")
        return None
    if ip.compressed in LOCAL_IPS:
        return ip.compressed
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        errors.append(f"{where} : '{value}' refusée (adresse non spécifiée, de bouclage ou multicast ; "
                      f"seules {' et '.join(LOCAL_IPS)} sont admises, pour une application locale).")
        return None
    return ip.compressed


def parse(data: dict, source: str = "inventaire") -> Inventory:
    errors: list[str] = []

    for key in sorted(set(data) - TOP_KEYS):
        errors.append(f"{source} : clé inconnue '{key}' (attendu : {', '.join(sorted(TOP_KEYS))}).")

    domain = data.get("sender_domain")
    if not isinstance(domain, str) or not DOMAIN_RE.match(domain):
        errors.append(f"{source} : sender_domain={domain!r} absent ou invalide (ex. \"example.com\").")
        domain = None

    defaults = data.get("defaults", {})
    default_quota = DEFAULT_QUOTA
    if not isinstance(defaults, dict):
        errors.append(f"{source} : [defaults] doit être une table.")
    else:
        for key in sorted(set(defaults) - DEFAULT_KEYS):
            errors.append(f"{source} : [defaults] clé inconnue '{key}'.")
        if "quota_per_hour" in defaults:
            default_quota = _quota(defaults["quota_per_hour"], f"{source} [defaults]", errors) or DEFAULT_QUOTA

    apps_raw = data.get("applications")
    apps: dict[str, Application] = {}
    if not isinstance(apps_raw, dict) or not apps_raw:
        errors.append(f"{source} : aucune application déclarée ([applications.<nom>]).")
        apps_raw = {}

    owners: dict[str, str] = {}
    for name, entry in apps_raw.items():
        where = f"application '{name}'"
        if not NAME_RE.match(name):
            errors.append(f"{where} : nom invalide (minuscules, chiffres, '-', 32 caractères max, commence par une lettre).")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where} : doit être une table.")
            continue
        for key in sorted(set(entry) - APP_KEYS):
            errors.append(f"{where} : clé inconnue '{key}' (attendu : {', '.join(sorted(APP_KEYS))}).")

        address = entry.get("address")
        if not isinstance(address, str) or address.count("@") != 1:
            errors.append(f"{where} : address={address!r} absente ou invalide.")
            address = None
        else:
            address = address.strip().lower()
            local, _, adomain = address.partition("@")
            if not LOCAL_RE.match(local):
                errors.append(f"{where} : partie locale de '{address}' invalide.")
                address = None
            elif domain and adomain != domain:
                errors.append(f"{where} : l'adresse '{address}' n'appartient pas à sender_domain '{domain}'.")
                address = None
        if address:
            if address in owners:
                errors.append(f"{where} : l'adresse '{address}' est déjà attribuée à l'application '{owners[address]}'.")
            else:
                owners[address] = name

        ips_raw = entry.get("client_ips")
        ips: list[str] = []
        if not isinstance(ips_raw, list) or not ips_raw:
            errors.append(f"{where} : client_ips doit être une liste non vide d'IP d'hôte.")
        else:
            for raw in ips_raw:
                ip = _ip(raw, where, errors)
                if ip and ip not in ips:
                    ips.append(ip)
            if len(ips) > 1 and any(ip in LOCAL_IPS for ip in ips):
                errors.append(f"{where} : une adresse de bouclage ({', '.join(LOCAL_IPS)}) doit être la seule IP "
                              "de l'application (application locale au conteneur du relai).")

        quota = default_quota
        if "quota_per_hour" in entry:
            quota = _quota(entry["quota_per_hour"], where, errors)

        description = entry.get("description", "")
        if not isinstance(description, str):
            errors.append(f"{where} : description doit être une chaîne.")
            description = ""

        if address and ips and quota:
            apps[name] = Application(name, address, tuple(ips), quota, description)

    if errors:
        raise InventoryError(errors)
    return Inventory(domain, apps)


def load(path: str | Path) -> Inventory:
    path = Path(path)
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise InventoryError([f"inventaire {path} introuvable."]) from None
    except tomllib.TOMLDecodeError as e:
        raise InventoryError([f"inventaire {path} : TOML invalide ({e})."]) from None
    return parse(data, str(path))


def read_password(secrets_dir: str | Path, name: str) -> str:
    """Mot de passe d'une application (fichier <secrets_dir>/<name>, une ligne)."""
    value = (Path(secrets_dir) / name).read_text(encoding="utf-8")
    return value.removesuffix("\n").removesuffix("\r")


def check_secrets(inv: Inventory, secrets_dir: str | Path) -> list[str]:
    """Erreurs sur les secrets des applications (absents, vides, trop courts)."""
    errors = []
    for name in inv.applications:
        path = Path(secrets_dir) / name
        try:
            pw = read_password(secrets_dir, name)
        except FileNotFoundError:
            errors.append(f"application '{name}' : secret {path} absent.")
            continue
        except (OSError, UnicodeDecodeError) as e:
            errors.append(f"application '{name}' : secret {path} illisible ({e}).")
            continue
        if "\n" in pw or "\r" in pw:
            errors.append(f"application '{name}' : le secret {path} doit tenir sur une ligne.")
        elif len(pw) < MIN_PASSWORD_LEN:
            errors.append(f"application '{name}' : le secret {path} doit faire au moins {MIN_PASSWORD_LEN} caractères.")
    return errors
