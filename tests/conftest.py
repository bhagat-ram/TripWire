"""
tests/conftest.py

Ensures backend/ (repo root's module dir, per the build-plan repo structure
in Section 1) is importable as `config`, `events`, `classifier`, etc. from
anywhere pytest is invoked. Drop this alongside test_classifier.py,
test_panic_allowlist.py, and test_chaos.py in tripwire/tests/, with the
Stage 0-8 modules in tripwire/backend/.

Run all three suites from the repo root:
    pytest tests/ -v
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")

for _p in (_BACKEND_DIR, _REPO_ROOT):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)
