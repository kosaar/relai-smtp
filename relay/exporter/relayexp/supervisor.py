"""relay-run : processus principal (PID 1) du conteneur relai.

  - lance Postfix au premier plan (« postfix start-fg »), journaux sur un tube ;
  - recopie chaque ligne de journal sur sa sortie standard (journaux Docker,
    inchangés) et en donne une copie à l'exporteur de métriques ;
  - lance l'exporteur sous un utilisateur non privilégié et le relance s'il
    s'arrête ; l'exporteur ne peut jamais bloquer les journaux ni le courrier
    (copie non bloquante : en cas de retard, des lignes sont perdues pour les
    métriques seulement) ;
  - relaie SIGTERM/SIGINT/SIGHUP à Postfix, récupère les processus orphelins,
    et se termine avec le code de sortie de Postfix.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time

EXPORTER_CMD = ["/usr/local/bin/relay-exporter"]
EXPORTER_USER = "nobody"
EXPORTER_GROUP = "nogroup"
EXPORTER_EXTRA_GROUPS = ["postdrop"]   # « postqueue -j » : accès au socket showq
MAX_FEED_LINE = 4000                   # < PIPE_BUF : écriture atomique dans le tube
RESTART_DELAY = 5
MASTER_PID_FILE = "/var/spool/postfix/pid/master.pid"


def log(msg: str) -> None:
    sys.stderr.write(f"relay-run: {msg}\n")
    sys.stderr.flush()


class Supervisor:
    def __init__(self, cmd: list[str], exporter_cmd: list[str] | None = None, drop_privileges: bool = True):
        self.cmd = cmd
        self.exporter_cmd = exporter_cmd
        self.drop_privileges = drop_privileges
        self.main: subprocess.Popen | None = None
        self.main_status: int | None = None
        self.exporter: subprocess.Popen | None = None
        self.exporter_fd: int | None = None
        self.next_start = 0.0
        self.dropped = 0
        # Réentrant : le gestionnaire de SIGCHLD (reap) s'exécute dans le fil principal,
        # éventuellement pendant que celui-ci tient déjà le verrou.
        self.lock = threading.RLock()

    # -- exporteur ----------------------------------------------------------------
    def start_exporter(self) -> None:
        if not self.exporter_cmd or time.monotonic() < self.next_start:
            return
        self.next_start = time.monotonic() + RESTART_DELAY
        ids = dict(user=EXPORTER_USER, group=EXPORTER_GROUP,
                   extra_groups=EXPORTER_EXTRA_GROUPS) if self.drop_privileges else {}
        try:
            proc = subprocess.Popen(self.exporter_cmd, stdin=subprocess.PIPE, stdout=sys.stderr,
                                    close_fds=True, **ids)
        except OSError as e:
            log(f"exporteur de métriques non démarré ({e})")
            return
        os.set_blocking(proc.stdin.fileno(), False)
        with self.lock:
            self.exporter, self.exporter_fd = proc, proc.stdin.fileno()

    def stop_exporter(self) -> None:
        with self.lock:
            proc, self.exporter, self.exporter_fd = self.exporter, None, None
        if proc:
            try:
                proc.stdin.close()
            except OSError:
                pass
            proc.terminate()

    def feed(self, line: bytes) -> None:
        with self.lock:
            fd = self.exporter_fd
        if fd is None:
            self.start_exporter()
            return
        try:
            os.write(fd, line[:MAX_FEED_LINE] if len(line) <= MAX_FEED_LINE
                     else line[:MAX_FEED_LINE - 1] + b"\n")
        except BlockingIOError:
            self.dropped += 1
        except (BrokenPipeError, OSError):
            log("exporteur de métriques arrêté : redémarrage")
            self.stop_exporter()
            self.start_exporter()

    # -- processus ----------------------------------------------------------------
    def reap(self) -> None:
        """Récupère tous les fils terminés (PID 1 : orphelins compris)."""
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            if self.main and pid == self.main.pid:
                self.main_status = os.waitstatus_to_exitcode(status)
                self.main.returncode = self.main_status
            elif self.exporter and pid == self.exporter.pid:
                code = self.exporter.returncode = os.waitstatus_to_exitcode(status)
                with self.lock:
                    self.exporter, self.exporter_fd = None, None
                if self.main_status is None:
                    log(f"exporteur de métriques arrêté (code {code}) : relancé à la prochaine ligne de journal")

    def forward(self, signum, _frame) -> None:
        """Hors PID 1, « postfix start-fg » lance master comme fils d'un shell :
        le signal va au processus maître (fichier pid), à défaut au fils direct."""
        if not self.main or self.main_status is not None:
            return
        target = self.main.pid
        try:
            with open(MASTER_PID_FILE) as f:
                pid = int(f.read().split()[0])
            os.kill(pid, 0)
            target = pid
        except (OSError, ValueError, IndexError):
            pass
        try:
            os.kill(target, signum)
        except ProcessLookupError:
            pass

    def run(self) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self.forward)
        signal.signal(signal.SIGCHLD, lambda *_: self.reap())
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        self.start_exporter()
        self.main = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, close_fds=True)
        out = sys.stdout.buffer
        for line in self.main.stdout:
            try:
                out.write(line)
                out.flush()
            except OSError:
                pass
            self.feed(line)
        # Fin des journaux : attente explicite de la fin de Postfix (sans dépendre
        # de la remise du signal SIGCHLD).
        deadline = time.monotonic() + 30
        while self.main_status is None and time.monotonic() < deadline:
            self.reap()
            if self.main_status is None:
                time.sleep(0.05)
        self.stop_exporter()
        status = self.main_status if self.main_status is not None else 1
        if self.dropped:
            log(f"{self.dropped} ligne(s) de journal non transmises à l'exporteur (retard)")
        log(f"Postfix terminé (code {status})")
        return status


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--":
        args = args[1:]
    cmd = args or ["postfix", "start-fg"]
    enabled = os.environ.get("RELAY_METRICS_ENABLED", "yes") != "no"
    return Supervisor(cmd, EXPORTER_CMD if enabled else None).run()
