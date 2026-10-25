# Tests unitaires des modules Python purs (relaycfg, relaygw).
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for sub in ("common", "gateway"):
    path = str(ROOT / sub)
    if path not in sys.path:
        sys.path.insert(0, path)
