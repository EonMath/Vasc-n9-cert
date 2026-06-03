#!/usr/bin/env python3
"""Frozen range plans for exact Vasc Polya batch coverage.

The plan is a mechanical scheduling/audit artifact.  It does not certify any
root and never sets complete_certificate=true.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
BATCH_TOOL = WORKSPACE / "tools" / "vasc_polya_batch.py"
CERT_ROOT = WORKSPACE / "certificates" / "polya_batches"
TOOL_VERSION = "vasc_range_plan_v1"


def load_batch_tool():
    spec = importlib.util.spec_from_file_location("vasc_polya_batch", BATCH_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BATCH_TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


batch_tool = load_batch_tool()
base = batch_tool.base


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_prefix_start(n: int) -> int:
    coverage_path = CERT_ROOT / f"n{n}" / "coverage_index.json"
    if not coverage_path.exists():
        return 0
    coverage = read_json(coverage_path)
    return int(coverage["coverage"].get("next_uncovered_start_after_prefix", 0))


def plan_path(n: int, start: int, end: int, batch_size: int, shards: int) -> Path:
    name = f"range_plan_{start:07d}_{end:07d}_b{batch_size:04d}_s{shards:02d}.json"
    return CERT_ROOT / f"n{n}" / "range_plans" / name


def batch_dir_name(start: int, count: int) -> str:
    return f"batch_{start:07d}_{start + count:07d}"


def command(n: int, start: int, count: int, max_k: int, kind: str, include_root_hash: bool) -> str:
    cmd = (
        f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_polya_batch.py'} "
        f"{kind} --n {n} --start {start} --count {count} --max-polya-power {max_k}"
    )
    if include_root_hash:
        cmd += " --include-root-universe-hash"
    return cmd


def build_batches(n: int, start: int, end: int, batch_size: int, max_k: int, include_root_hash: bool):
    rows = []
    cursor = start
    batch_index = 0
    while cursor < end:
        count = min(batch_size, end - cursor)
        rows.append(
            {
                "batch_dir": batch_dir_name(cursor, count),
                "batch_index": batch_index,
                "check_command": command(n, cursor, count, max_k, "check", include_root_hash),
                "count": count,
                "end_exclusive": cursor + count,
                "expected_checker_status": "PASS",
                "max_polya_power": max_k,
                "produce_command": command(n, cursor, count, max_k, "produce", include_root_hash),
                "start": cursor,
            }
        )
        batch_index += 1
        cursor += count
    return rows


def build_shards(batches: list[dict[str, object]], shard_count: int):
    if shard_count <= 0:
        raise ValueError("shard count must be positive")
    if not batches:
        return []
    out = []
    batch_count = len(batches)
    for shard_index in range(shard_count):
        first = (batch_count * shard_index) // shard_count
        last = (batch_count * (shard_index + 1)) // shard_count
        if first == last:
            continue
        selected = batches[first:last]
        out.append(
            {
                "batch_count": len(selected),
                "batch_index_range": [int(selected[0]["batch_index"]), int(selected[-1]["batch_index"]) + 1],
                "end_exclusive": int(selected[-1]["end_exclusive"]),
                "root_count": sum(int(row["count"]) for row in selected),
                "shard_id": f"shard_{shard_index:02d}",
                "start": int(selected[0]["start"]),
            }
        )
    return out


def produce(args: argparse.Namespace) -> None:
    n = args.n
    full_root_count = math.factorial(n - 1)
    start = args.start if args.start is not None else current_prefix_start(n)
    end = args.end if args.end is not None else full_root_count
    if not (0 <= start < end <= full_root_count):
        raise ValueError(f"invalid range [{start},{end}) for n={n}")
    if args.batch_size <= 0:
        raise ValueError("batch size must be positive")

    coverage_path = CERT_ROOT / f"n{n}" / "coverage_index.json"
    coverage_hash = sha256_file(coverage_path) if coverage_path.exists() else None
    root_count, root_hash = base.root_universe_hash(n)
    if root_count != full_root_count:
        raise RuntimeError("root universe count mismatch")

    batches = build_batches(n, start, end, args.batch_size, args.max_polya_power, args.include_root_universe_hash)
    shards = build_shards(batches, args.shards)
    plan = {
        "audit_status": "plan_only_not_a_certificate",
        "batch_count": len(batches),
        "batch_size": args.batch_size,
        "batches": batches,
        "complete_certificate": False,
        "coverage_source": {
            "coverage_index_path": str(coverage_path),
            "coverage_index_sha256": coverage_hash,
            "covered_prefix_start": start,
        },
        "end_exclusive": end,
        "full_problem_certificate": False,
        "full_root_count": full_root_count,
        "include_root_universe_hash_in_batch_commands": bool(args.include_root_universe_hash),
        "max_polya_power": args.max_polya_power,
        "n": n,
        "reason": "frozen disjoint schedule only; proof use requires PASS batches, full coverage, bridge obligations, and Computation Auditor acceptance",
        "root_count": end - start,
        "root_universe": {
            "fixed_maximum_variable": "x1",
            "root_count": root_count,
            "root_stream_hash": root_hash,
            "type": "cyclic_maximum_then_all_orderings_stream",
        },
        "shard_count": len(shards),
        "shards": shards,
        "start": start,
        "tool": TOOL_VERSION,
    }
    path = plan_path(n, start, end, args.batch_size, args.shards)
    write_json(path, plan)

    audit = {
        "complete_certificate": False,
        "files": {
            "plan_json_sha256": sha256_file(path),
            "tool_source_sha256": sha256_file(Path(__file__)),
        },
        "n": n,
        "plan_path": str(path),
        "reproduction_commands": [
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_range_plan.py'} "
                f"produce --n {n} --start {start} --end {end} --batch-size {args.batch_size} "
                f"--max-polya-power {args.max_polya_power} --shards {args.shards}"
                + (" --include-root-universe-hash" if args.include_root_universe_hash else "")
            ),
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_range_plan.py'} "
                f"check --plan {path}"
            ),
        ],
        "status": "PLAN_WRITTEN",
        "tool": TOOL_VERSION,
    }
    write_json(path.with_name(path.stem + "_audit_index.json"), audit)
    write_recovery_note(path, plan, audit)


def validate_plan(plan: dict[str, object]) -> list[str]:
    failures = []
    n = int(plan["n"])
    full_root_count = math.factorial(n - 1)
    if int(plan["full_root_count"]) != full_root_count:
        failures.append("full root count mismatch")
    if plan.get("complete_certificate") is not False:
        failures.append("complete_certificate must be false")
    if plan.get("full_problem_certificate") is not False:
        failures.append("full_problem_certificate must be false")
    batches = plan.get("batches", [])
    cursor = int(plan["start"])
    for expected_index, row in enumerate(batches):
        if int(row["batch_index"]) != expected_index:
            failures.append(f"batch {expected_index}: index mismatch")
        if int(row["start"]) != cursor:
            failures.append(f"batch {expected_index}: gap or overlap at {cursor}")
        if int(row["end_exclusive"]) <= int(row["start"]):
            failures.append(f"batch {expected_index}: nonpositive interval")
        if int(row["count"]) != int(row["end_exclusive"]) - int(row["start"]):
            failures.append(f"batch {expected_index}: count mismatch")
        cursor = int(row["end_exclusive"])
    if cursor != int(plan["end_exclusive"]):
        failures.append("final endpoint mismatch")
    if sum(int(row["count"]) for row in batches) != int(plan["root_count"]):
        failures.append("root count mismatch")
    for shard in plan.get("shards", []):
        first, last = shard["batch_index_range"]
        selected = batches[first:last]
        if not selected:
            failures.append(f"{shard['shard_id']}: empty shard")
            continue
        if int(shard["start"]) != int(selected[0]["start"]):
            failures.append(f"{shard['shard_id']}: start mismatch")
        if int(shard["end_exclusive"]) != int(selected[-1]["end_exclusive"]):
            failures.append(f"{shard['shard_id']}: end mismatch")
        if int(shard["root_count"]) != sum(int(row["count"]) for row in selected):
            failures.append(f"{shard['shard_id']}: root count mismatch")
    return failures


def check(args: argparse.Namespace) -> None:
    path = Path(args.plan)
    plan = read_json(path)
    failures = validate_plan(plan)
    result = {
        "complete_certificate": False,
        "failures": failures,
        "n": plan["n"],
        "plan_path": str(path),
        "root_count": plan["root_count"],
        "status": "PASS" if not failures else "FAIL",
        "tool": TOOL_VERSION,
    }
    write_json(path.with_name(path.stem + "_checker_result.json"), result)


def write_recovery_note(path: Path, plan: dict[str, object], audit: dict[str, object]) -> None:
    note = [
        "# Polya Frozen Range Plan 1",
        "",
        "## Scope",
        "This is a mechanical scheduling and audit-scope artifact only.  It is",
        "not a proof certificate and does not certify any uncomputed root.",
        "",
        "## Plan",
        f"- Target: `n={plan['n']}`.",
        f"- Planned interval: `[{plan['start']},{plan['end_exclusive']})`.",
        f"- Planned roots: `{plan['root_count']}`.",
        f"- Batch size: `{plan['batch_size']}`.",
        f"- Batch count: `{plan['batch_count']}`.",
        f"- Shard count: `{plan['shard_count']}`.",
        f"- Max Polya power per planned command: `{plan['max_polya_power']}`.",
        f"- Plan JSON: `{path}`.",
        f"- Plan SHA256: `{audit['files']['plan_json_sha256']}`.",
        "",
        "## Audit Flags",
        "- `complete_certificate=false`.",
        "- `full_problem_certificate=false`.",
        "- Proof use still requires PASS batches for the planned ranges, zero",
        "  unresolved roots, fixed-maximum/root-cone bridge obligations,",
        "  denominator-clearing bridge obligations, Polya multiplier implication,",
        "  and Computation Auditor acceptance.",
        "",
        "## Next Mechanical Step",
        "- Assign shards or individual batch intervals to workers.  Each produced",
        "  batch must be checked by `vasc_polya_batch.py check` before it can enter",
        "  any frozen coverage snapshot.",
        "",
    ]
    (WORKSPACE / "recovery" / "polya_frozen_range_plan_1.md").write_text("\n".join(note), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    produce_parser = sub.add_parser("produce")
    produce_parser.add_argument("--n", type=int, required=True, choices=(9, 11))
    produce_parser.add_argument("--start", type=int, default=None)
    produce_parser.add_argument("--end", type=int, default=None)
    produce_parser.add_argument("--batch-size", type=int, default=64)
    produce_parser.add_argument("--max-polya-power", type=int, default=8)
    produce_parser.add_argument("--shards", type=int, default=8)
    produce_parser.add_argument("--include-root-universe-hash", action="store_true")
    check_parser = sub.add_parser("check")
    check_parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    if args.cmd == "produce":
        produce(args)
    elif args.cmd == "check":
        check(args)


if __name__ == "__main__":
    main()
