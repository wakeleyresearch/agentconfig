"""Built-in zero-trust failsafe profile switch and ephemeral forensic launch."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .deployer import apply_targets, restore_snapshot
from .formats import FormatError, dump_json, parse_json
from .paths import RuntimeContext, atomic_write_text


def failsafe_apply(ctx: RuntimeContext) -> dict[str, Any]:
    """Snapshot live configs/memory and atomically swap deployed targets to failsafe baselines."""
    res = apply_targets(ctx, safe=True, approve_drift=True, failsafe=True)
    state_file = ctx.state_dir / "failsafe-state.json"
    state_obj = {
        "active": True,
        "snapshot_id": res["snapshot_id"],
        "applied_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_text(state_file, dump_json(state_obj), mode=0o600, boundary_root=ctx.state_dir)
    return {
        "ok": True,
        "mode": "failsafe",
        "snapshot_id": res["snapshot_id"],
        "applied_ids": res["applied_ids"],
    }


def failsafe_restore(ctx: RuntimeContext) -> dict[str, Any]:
    """Restore live targets from pre-failsafe snapshot."""
    state_file = ctx.state_dir / "failsafe-state.json"
    snap_id: str | None = None
    if state_file.exists():
        try:
            doc = parse_json(state_file.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("snapshot_id"):
                snap_id = str(doc["snapshot_id"])
        except (FormatError, OSError):
            snap_id = None

    if snap_id is None:
        snaps_dir = ctx.state_dir / "snapshots"
        if snaps_dir.exists():
            fs_snaps = sorted(
                d.name for d in snaps_dir.iterdir()
                if d.is_dir() and d.name.endswith("-failsafe") and (d / "snapshot.json").exists()
            )
            if fs_snaps:
                snap_id = fs_snaps[-1]

    res = restore_snapshot(ctx, snapshot_id=snap_id, take_pre_snapshot=True)
    atomic_write_text(
        state_file,
        dump_json({"active": False, "restored_from": res["snapshot_id"], "restored_at": datetime.now(timezone.utc).isoformat()}),
        mode=0o600,
        boundary_root=ctx.state_dir,
    )
    return res


def failsafe_exec(
    ctx: RuntimeContext,
    harness: str,
    extra_args: list[str] | None = None,
) -> int:
    """Delegate ephemeral isolated launch to wrappers/agent-env-run --failsafe."""
    wrapper = ctx.repo_root / "wrappers" / "agent-env-run"
    if not wrapper.exists():
        raise FileNotFoundError(f"Missing wrapper script: {wrapper}")
    cmd = [str(wrapper), "--failsafe", "--repo", str(ctx.repo_root), "--", harness, *(extra_args or [])]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode
