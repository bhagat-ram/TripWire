"""
config.py — Stage 0
Single source of truth for every path, threshold, and allowlist entry.
No other module should hardcode a path, a magic number, or a process name.
"""

from __future__ import annotations
import os
import platform
import random
import string

# ─── Root paths ──────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR  = os.path.join(BASE_DIR, "logs")
DB_PATH   = os.path.join(BASE_DIR, "tripwire.db")
REAL_DATA_DIR = os.path.join(BASE_DIR, "real_data")

# Keep a private staging dir for the manifest only — no decoys live here.
_STAGING_DIR = os.path.join(BASE_DIR, ".tripwire_state")

for _d in (LOGS_DIR, REAL_DATA_DIR, _STAGING_DIR):
    os.makedirs(_d, exist_ok=True)

# ─── Real-filesystem decoy placements ─────────────────────────────────────
# Decoys are placed on the actual system, in locations a real intruder/
# ransomware sweep would hit.  Each entry carries:
#   id        – internal key
#   label     – human-readable name shown in the dashboard
#   path      – absolute path on disk
#   kind      – "known" | "random" (for dashboard display)
#
# SAFETY RULES enforced by is_path_allowed():
#   ✓  anything under HOME
#   ✓  /tmp  and /var/tmp
#   ✗  /etc, /usr, /bin, /sbin, /lib*, /proc, /sys, /dev, /boot, /root (unless HOME=/root)
#
# On macOS:  ~/Library/Application Support gets an entry.
# On Linux:  ~/.local/share  and  ~/.config  get entries.
# Always:    ~/Desktop, ~/Documents, ~/Downloads, /tmp/<random>

HOME = os.path.expanduser("~")

def _rand_folder_name(seed: str, length: int = 8) -> str:
    """Deterministic-from-seed but opaque-looking folder name, so each host
    gets its own 'random' path that stays stable across restarts."""
    rng = random.Random(seed + platform.node())
    chars = string.ascii_lowercase + string.digits
    return "." + "".join(rng.choices(chars, k=length))   # hidden dot-dir

_RAND_HOME   = os.path.join(HOME,  _rand_folder_name("home_rand"))
_RAND_TMP    = os.path.join("/tmp", _rand_folder_name("tmp_rand"))

_known: list[dict] = [
    {"id": "desktop",   "label": "~/Desktop",           "path": os.path.join(HOME, "Desktop"),   "kind": "known"},
    {"id": "documents", "label": "~/Documents",          "path": os.path.join(HOME, "Documents"),  "kind": "known"},
    {"id": "downloads", "label": "~/Downloads",          "path": os.path.join(HOME, "Downloads"),  "kind": "known"},
    {"id": "pictures",  "label": "~/Pictures",           "path": os.path.join(HOME, "Pictures"),   "kind": "known"},
    {"id": "tmp",       "label": "/tmp (named subdir)",  "path": _RAND_TMP,                         "kind": "random"},
    {"id": "home_rand", "label": "~/.<random>",          "path": _RAND_HOME,                        "kind": "random"},
]

# Platform-specific known locations
if platform.system() == "Darwin":
    _known += [
        {"id": "app_support", "label": "~/Library/Application Support", "path": os.path.join(HOME, "Library", "Application Support"), "kind": "known"},
    ]
else:  # Linux and everything else
    _known += [
        {"id": "local_share", "label": "~/.local/share",  "path": os.path.join(HOME, ".local", "share"), "kind": "known"},
        {"id": "dot_config",  "label": "~/.config",       "path": os.path.join(HOME, ".config"),          "kind": "known"},
    ]

DECOY_PLACEMENTS: list[dict] = _known

# Paths where decoys may never be written — checked in is_path_allowed().
_BLOCKED_PREFIXES = [
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/proc", "/sys", "/dev", "/boot",
]

def is_path_allowed(path: str) -> bool:
    """Sandbox check — must pass before any decoy write, watch, or delete.
    Allows HOME subtree and /tmp subtree; blocks system-critical prefixes.
    Tests that swap HOME or /tmp override the placement list and rely on
    the same logic remaining correct."""
    real = os.path.realpath(os.path.abspath(path))
    home_real = os.path.realpath(HOME)
    tmp_real  = os.path.realpath("/tmp")
    var_tmp   = os.path.realpath("/var/tmp")

    def _under(root: str) -> bool:
        return real == root or real.startswith(root + os.sep)

    if not (_under(home_real) or _under(tmp_real) or _under(var_tmp)):
        return False

    # Even inside home, block root-owned system dirs that can appear as symlinks
    for blk in _BLOCKED_PREFIXES:
        if _under(os.path.realpath(blk)):
            return False
    return True

# Validate at import time — misconfigured placements fail loud, not silently.
for _p in DECOY_PLACEMENTS:
    if not is_path_allowed(_p["path"]):
        raise RuntimeError(
            f"decoy placement escapes allowed filesystem zone: {_p['path']!r}\n"
            f"Allowed: HOME={HOME}, /tmp, /var/tmp"
        )

# Manifest lives in the staging dir, not inside a decoy folder.
MANIFEST_PATH = os.path.join(_STAGING_DIR, "manifest.json")

# ─── Watcher (Stage 2) ───────────────────────────────────────────────────
POLL_FALLBACK_SECONDS      = 2.0
DEBOUNCE_MS                = 250

# ─── Attribution (Stage 3) ───────────────────────────────────────────────
PROCESS_SNAPSHOT_INTERVAL_MS   = 500
ATTRIBUTION_CANDIDATE_WINDOW_S = 2.0

# ─── Classifier (Stage 4) ────────────────────────────────────────────────
CLASSIFIER_WINDOW_S        = 10.0
WARNING_TOUCH_THRESHOLD    = 3
CRITICAL_TOUCH_THRESHOLD   = 6

# ─── Panic mode (Stage 5) ────────────────────────────────────────────────
PANIC_DRY_RUN = os.environ.get("PANIC_DRY_RUN", "1") == "1"

# Bare "python"/"python3" are allowlisted only in dev mode, so this project's
# own tooling (pytest, the self-tests in panic.py/server.py, a dev running
# the simulator) never gets suspended/killed while poking at itself.
# On a real deployment this is a wide exemption — ANY Python process,
# including a malicious script, is immune to suspend/kill — so it's gated
# behind TRIPWIRE_DEV_MODE. Set TRIPWIRE_DEV_MODE=0 (or list specific
# script names instead of the bare interpreter) before this ever protects
# a real machine.
TRIPWIRE_DEV_MODE = os.environ.get("TRIPWIRE_DEV_MODE", "1") == "1"
ALLOWLIST_PROCESS_NAMES = {"explorer.exe", "finder", "systemd", "launchd"}
if TRIPWIRE_DEV_MODE:
    ALLOWLIST_PROCESS_NAMES |= {"python", "python3"}

# ─── Auto-response rules (Stage 5.5) ──────────────────────────────────────
# Per-severity automatic response, checked the moment a touch classifies at
# that severity. "monitor" means alert-only — the dashboard/incident queue
# still lights up, but no containment action fires on its own; an analyst
# has to click Suspend/Kill/Lock manually. Editable live via
# POST /config/auto-response (never edit ALLOWLIST/thresholds by hand while
# the server is running — go through that endpoint so the change is logged).
AUTO_RESPONSE_RULES: dict[str, list[str]] = {
    "info":     ["monitor"],
    "warning":  ["monitor"],
    "critical": ["suspend", "lock"],
}

# A single suspend/lock is often not enough against something that keeps
# running: real malware doesn't stop just because a decoy sweep tripped
# once. If a PID that panic.py already suspended keeps generating touches
# afterward (suspend failed, was a dry-run, or the process caught/ignored
# it), auto-escalate straight to kill once it crosses this many additional
# post-suspend touches — no analyst click required.
AUTO_ESCALATE_TO_KILL_AFTER_TOUCHES = 3

# ─── Server (Stage 6) ─────────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT  = 5050

# ─── Simulator (Stage 8) ──────────────────────────────────────────────────
SIMULATOR_SLEEP_S = 0.05

# ─── MITRE mapping used by classifier ─────────────────────────────────────
MITRE_ID_MASS_ACCESS = "T1486"   # Data Encrypted for Impact
MITRE_ID_DISCOVERY   = "T1083"   # File and Directory Discovery
