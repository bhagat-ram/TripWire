"""
decoy_gen.py — Stage 1
Generates and manages decoy files spread across the real filesystem at
locations defined in config.DECOY_PLACEMENTS — actual ~/Desktop,
~/Documents, /tmp/<random>, ~/.config, etc.

Each decoy looks like a file that belongs in its location:
  ~/Desktop         → credentials/notes a user left on their desktop
  ~/Documents       → contracts, board minutes, due-diligence PDFs
  ~/Downloads       → invoice scans, exports downloaded from a SaaS tool
  /tmp/<random>     → a temp export that "never got cleaned up"
  ~/.config         → a credential/config file an app would drop there
  ~/.local/share    → an app database or cache with sensitive-looking content
  ~/Pictures        → a disguised payload (some ransomware sweeps here)

Reliability guarantees (same as before, now across real FS):
  - Idempotent: rerun only creates what's missing, never overwrites.
  - Diverged files (content changed since generation) are reported, not
    clobbered — changed content IS the intrusion signal; destroying it
    destroys evidence.
  - Every target path passes config.is_path_allowed() before any write.
  - Manifest lives in .tripwire_state/ (never inside a watched folder).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import random
import time

import config

# ─── Decoy specs ─────────────────────────────────────────────────────────
# (filename, generator_kind, placement_id)
# Filenames chosen to look plausible for their folder context.
DECOY_SPECS: list[tuple[str, str, str]] = [
    # Desktop — stuff a real user leaves on their desktop
    ("Passwords_Backup.txt",           "text",   "desktop"),
    ("VPN_Config_Backup.txt",          "text",   "desktop"),
    ("meeting_notes_q3_private.txt",   "text",   "desktop"),

    # Documents — contracts, financials, sensitive docs
    ("Client_Contracts_2025.docx",     "text",   "documents"),
    ("Board_Meeting_Minutes.docx",     "text",   "documents"),
    ("M&A_Due_Diligence.pdf",          "binary", "documents"),
    ("Tax_Returns_2024.pdf",           "binary", "documents"),
    ("Employee_SSNs.csv",              "csv",    "documents"),

    # Downloads — things "downloaded from the web/SaaS"
    ("invoice_scan_2025_1284.pdf",     "binary", "downloads"),
    ("company_directory_export.csv",   "csv",    "downloads"),
    ("Q3_Budget_Forecast.xlsx",        "csv",    "downloads"),

    # /tmp/<random> — a temp export that "never got cleaned up"
    ("db_export_temp_DO_NOT_SHARE.csv","csv",    "tmp"),
    ("auth_tokens_backup.txt",         "text",   "tmp"),

    # ~/.config — app credential/config files
    ("aws_credentials",                "text",   "dot_config"),
    ("gcloud_service_account.json",    "text",   "dot_config"),

    # ~/.local/share — app data / "database"
    ("Salary_Details.xlsx",            "csv",    "local_share"),
    ("Customer_Database_Export.csv",   "csv",    "local_share"),

    # ~/Pictures — disguised payload (ransomware sweeps here)
    ("family_photo_metadata.csv",      "csv",    "pictures"),
    ("backup_archive.pdf",             "binary", "pictures"),

    # ~/.g12... (random hidden home dir)
    ("full_system_backup_2025.zip",    "binary", "home_rand"),
    ("ssh_key_backup.txt",             "text",   "home_rand"),
]

# macOS-only placement
_MACOS_SPECS: list[tuple[str, str, str]] = [
    ("Keychain_Export.csv",            "csv",    "app_support"),
    ("app_credentials.plist",          "text",   "app_support"),
]

import platform
if platform.system() == "Darwin":
    DECOY_SPECS += _MACOS_SPECS


# ─── Generators ──────────────────────────────────────────────────────────

def _gen_csv_bytes(seed_name: str) -> bytes:
    rng = random.Random(seed_name)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "name", "department", "value", "notes"])
    depts = ["Engineering", "Finance", "Sales", "Legal", "Ops"]
    for i in range(rng.randint(40, 120)):
        w.writerow([i, f"Person_{rng.randint(1000,9999)}", rng.choice(depts),
                    round(rng.uniform(40000, 220000), 2), "confidential"])
    return buf.getvalue().encode("utf-8")


def _gen_text_bytes(seed_name: str) -> bytes:
    rng = random.Random(seed_name)
    lines = [f"CONFIDENTIAL — {seed_name}", "=" * 40, ""]
    for i in range(rng.randint(20, 60)):
        lines.append(f"entry_{i}: ref-{rng.randint(100000, 999999)}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _gen_binary_bytes(seed_name: str) -> bytes:
    rng = random.Random(seed_name)
    header = b"%PDF-1.4\n%tripwire-decoy\n"
    body = bytes(rng.randrange(256) for _ in range(rng.randint(2000, 8000)))
    return header + body


_GENERATORS = {"csv": _gen_csv_bytes, "text": _gen_text_bytes, "binary": _gen_binary_bytes}


# ─── Placement lookup ─────────────────────────────────────────────────────

def _placement_path(placement_id: str) -> str:
    for p in config.DECOY_PLACEMENTS:
        if p["id"] == placement_id:
            return p["path"]
    raise KeyError(f"unknown decoy placement id: {placement_id!r}")


# ─── Manifest helpers ─────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_manifest() -> dict:
    if os.path.exists(config.MANIFEST_PATH):
        try:
            with open(config.MANIFEST_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_manifest(manifest: dict):
    tmp = config.MANIFEST_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, config.MANIFEST_PATH)


# ─── Public API ───────────────────────────────────────────────────────────

def generate_decoys(force: bool = False) -> dict:
    """
    Place decoy files across the real filesystem (as configured in
    config.DECOY_PLACEMENTS). Idempotent — safe to call on every startup.

    Returns:
        {
          "created":          ["<placement>/<name>", ...],
          "skipped_existing": [...],
          "diverged":         [...],   # content changed since generation
          "skipped_no_dir":   [...],   # placement dir doesn't exist (Desktop etc.)
        }
    """
    manifest = _load_manifest()
    summary = {"created": [], "skipped_existing": [], "diverged": [], "skipped_no_dir": []}

    for name, kind, placement_id in DECOY_SPECS:
        try:
            placement_dir = _placement_path(placement_id)
        except KeyError:
            # Placement only exists on one platform (e.g. app_support on macOS)
            summary["skipped_no_dir"].append(f"{placement_id}/{name}")
            continue

        # Create the dir if it doesn't already exist — but only if the
        # placement itself is allowed. Unknown dirs we never create silently.
        if not config.is_path_allowed(placement_dir):
            raise RuntimeError(f"refusing to write outside allowed zone: {placement_dir}")
        os.makedirs(placement_dir, exist_ok=True)

        path = os.path.join(placement_dir, name)
        if not config.is_path_allowed(path):
            raise RuntimeError(f"refusing to write outside allowed zone: {path}")

        key = f"{placement_id}/{name}"
        gen_fn = _GENERATORS[kind]

        if os.path.exists(path) and not force:
            with open(path, "rb") as fh:
                current_hash = _sha256(fh.read())
            recorded_hash = manifest.get(key, {}).get("sha256")
            if recorded_hash == current_hash:
                summary["skipped_existing"].append(key)
                continue
            else:
                # Content changed after we wrote it → the thing we want to detect
                # DO NOT overwrite — preserve the evidence.
                summary["diverged"].append(key)
                continue

        data = gen_fn(name)
        tmp_path = path + ".tw_tmp"
        with open(tmp_path, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, path)   # atomic

        manifest[key] = {
            "sha256":       _sha256(data),
            "size":         len(data),
            "created_at":   time.time(),
            "placement_id": placement_id,
            "label":        next((p["label"] for p in config.DECOY_PLACEMENTS if p["id"] == placement_id), placement_id),
            "kind":         next((p["kind"]  for p in config.DECOY_PLACEMENTS if p["id"] == placement_id), "unknown"),
            "path":         path,
        }
        summary["created"].append(key)

    _save_manifest(manifest)
    return summary


def all_decoy_paths() -> list[str]:
    """Every currently-placed decoy's absolute path — used by the watcher
    and the /health endpoint."""
    manifest = _load_manifest()
    return [e["path"] for e in manifest.values() if "path" in e and os.path.exists(e["path"])]


def decoy_manifest() -> dict:
    """Full manifest dict — used by the dashboard to show placement details."""
    return _load_manifest()


def remove_decoys() -> list[str]:
    """Remove every decoy tracked in the manifest.  Call on clean shutdown
    or during testing.  Returns list of removed paths."""
    manifest = _load_manifest()
    removed = []
    for entry in manifest.values():
        p = entry.get("path", "")
        if p and os.path.exists(p):
            try:
                os.remove(p)
                removed.append(p)
            except OSError:
                pass
    _save_manifest({})
    return removed


# ─── Self-test ────────────────────────────────────────────────────────────

def _run_self_test():
    import tempfile, shutil, platform

    tmp_root = tempfile.mkdtemp()
    orig_manifest = config.MANIFEST_PATH
    orig_placements = config.DECOY_PLACEMENTS
    orig_home = config.HOME

    # Build a fully tmp-local placement set so we don't touch the real FS
    test_placements = [
        {"id": pid, "label": pid, "path": os.path.join(tmp_root, pid), "kind": "known"}
        for pid in {placement_id for _, _, placement_id in DECOY_SPECS}
        if pid != "app_support" or platform.system() == "Darwin"
    ]
    config.DECOY_PLACEMENTS = test_placements
    config.HOME = tmp_root
    config.MANIFEST_PATH = os.path.join(tmp_root, ".manifest.json")

    try:
        print("[1/5] first run places all decoys on the 'filesystem' ... ", end="", flush=True)
        s1 = generate_decoys()
        spec_count = len(DECOY_SPECS)
        assert len(s1["created"]) == spec_count, f"expected {spec_count}, created {len(s1['created'])}"
        for name, kind, pid in DECOY_SPECS:
            p = os.path.join(_placement_path(pid), name)
            assert os.path.exists(p) and os.path.getsize(p) > 0, f"missing: {p}"
        print(f"OK → {len(s1['created'])} decoys across {len(test_placements)} real locations")

        print("[2/5] rerun is fully idempotent ... ", end="", flush=True)
        s2 = generate_decoys()
        assert len(s2["created"]) == 0
        assert len(s2["skipped_existing"]) == spec_count
        print(f"OK → {spec_count} unchanged")

        print("[3/5] diverged file (intrusion signal) is never clobbered ... ", end="", flush=True)
        tname, _, tpid = DECOY_SPECS[0]
        tpath = os.path.join(_placement_path(tpid), tname)
        with open(tpath, "ab") as fh:
            fh.write(b"\x00TAMPERED")
        s3 = generate_decoys()
        assert f"{tpid}/{tname}" in s3["diverged"]
        with open(tpath, "rb") as fh:
            assert fh.read().endswith(b"\x00TAMPERED"), "evidence destroyed!"
        print("OK → diverged entry preserved as-is")

        print("[4/5] deleted decoy is recreated on next run ... ", end="", flush=True)
        dname, _, dpid = DECOY_SPECS[1]
        dpath = os.path.join(_placement_path(dpid), dname)
        os.remove(dpath)
        s4 = generate_decoys()
        assert f"{dpid}/{dname}" in s4["created"]
        assert os.path.exists(dpath)
        print("OK")

        print("[5/5] all_decoy_paths() resolves to existing files only ... ", end="", flush=True)
        paths = all_decoy_paths()
        assert all(os.path.exists(p) for p in paths), "manifest has stale path"
        print(f"OK → {len(paths)} paths live on disk")

        print("\n✓ All checks passed.")
    finally:
        config.DECOY_PLACEMENTS = orig_placements
        config.HOME = orig_home
        config.MANIFEST_PATH = orig_manifest
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    _run_self_test()
