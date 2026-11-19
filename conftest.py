"""
Ensures the project root (this file's directory) is on sys.path so that
`from core import ...` / `from agent import ...` resolve correctly during
test collection — regardless of how pytest is invoked (`pytest`,
`python -m pytest`, from VS Code's Test Explorer, etc.) or whether
pytest.ini's `pythonpath` setting was picked up.

This file's location IS the signal: pytest automatically inserts the
directory of the nearest conftest.py into sys.path during collection
(rootdir-based conftest discovery is a core pytest mechanism, unlike the
`pythonpath` ini option, which depends on the ini file being found/parsed
correctly — see the Phase 3 troubleshooting note in README.md for a case
where pytest.ini alone was not enough).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
