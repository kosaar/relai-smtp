"""Registre minimal de métriques Prometheus (format texte 0.0.4), sans dépendance.

Compteurs et jauges à étiquettes, sûrs entre fils d'exécution. Les valeurs
d'étiquettes sont échappées selon le format d'exposition Prometheus.
"""
from __future__ import annotations

import math
import threading


def escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def fmt_value(v: float) -> str:
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int) or (isinstance(v, float) and v.is_integer() and abs(v) < 1e15):
        return str(int(v))
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    return repr(float(v))


def sample(name: str, labels: dict[str, str] | None, value: float) -> str:
    if labels:
        inner = ",".join(f'{k}="{escape(v)}"' for k, v in labels.items())
        return f"{name}{{{inner}}} {fmt_value(value)}"
    return f"{name} {fmt_value(value)}"


class Family:
    """Une métrique (compteur ou jauge) et ses séries, indexées par étiquettes."""

    def __init__(self, name: str, kind: str, help_text: str, labelnames: tuple[str, ...] = ()):
        self.name, self.kind, self.help, self.labelnames = name, kind, help_text, labelnames
        self._values: dict[tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, str]) -> tuple[str, ...]:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"{self.name} : étiquettes {sorted(labels)} != {sorted(self.labelnames)}")
        return tuple(str(labels[n]) for n in self.labelnames)

    def inc(self, amount: float = 1, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + amount

    def set(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = value

    def get(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0)

    def clear(self) -> None:
        with self._lock:
            self._values.clear()

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]
        with self._lock:
            items = sorted(self._values.items())
        for key, value in items:
            out.append(sample(self.name, dict(zip(self.labelnames, key)), value))
        return out


class Registry:
    def __init__(self):
        self._families: dict[str, Family] = {}

    def counter(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()) -> Family:
        return self._add(Family(name, "counter", help_text, labelnames))

    def gauge(self, name: str, help_text: str, labelnames: tuple[str, ...] = ()) -> Family:
        return self._add(Family(name, "gauge", help_text, labelnames))

    def _add(self, fam: Family) -> Family:
        if fam.name in self._families:
            raise ValueError(f"métrique {fam.name} déjà déclarée")
        self._families[fam.name] = fam
        return fam

    def render(self) -> str:
        lines: list[str] = []
        for fam in self._families.values():
            lines.extend(fam.render())
        return "\n".join(lines) + "\n"
