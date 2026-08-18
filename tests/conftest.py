from __future__ import annotations

import sys
from pathlib import Path

# data/build_alerts.py is a standalone script, not part of the installed
# package - added to the path here so tests can import it directly rather
# than duplicating its generation logic.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "data"))
