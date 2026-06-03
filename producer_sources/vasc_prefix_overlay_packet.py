#!/usr/bin/env python3
"""Composite prefix packet with hard-root overlays for Vasc Polya batches."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
BATCH_ROOT = WORKSPACE / "certificates" / "polya_batches"
PACKET_ROOT = WORKSPACE / "certificates" / "polya_packets"
TOOL_VERSION = "vasc_prefix_overlay_packet_v1"


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_canonical_json(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def packet_dir(n: int, packet_id: str) -> Path:
    return PACKET_ROOT / f"n{n}" / packet_id


def batch_dirs_for_prefix(n: int, start: int, end: int) -> list[Path]:
    root = BATCH_ROOT / f"n{n}"
    out = []
    cursor = start
    for path in sorted(root.glob("batch_*")):
        manifest = read_json(path / "manifest.json")
        cov = manifest["coverage"]
        if cov["start"] == cursor and cov["end_exclusive"] <= end:
            out.append(path)
            cursor = cov["end_exclusive"]
        if cursor == end:
            break
    if cursor != end:
        raise ValueError(f"batches do not form requested contiguous prefix [{start},{end}); stopped at {cursor}")
    return out


def load_overlay_leaves(n: int, overlay_packet_ids: list[str]) -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    leaves: dict[str, dict[str, object]] = {}
    rows: list[dict[str, object]] = []
    for packet_id in overlay_packet_ids:
        pdir = packet_dir(n, packet_id)
        manifest = read_json(pdir / "manifest.json")
        checker = read_json(pdir / "checker_result.json")
        if checker.get("status") != "PASS":
            raise ValueError(f"overlay packet {packet_id} checker is not PASS")
        for leaf in read_jsonl(pdir / "leaves.jsonl"):
            root_id = leaf["root_id"]
            if root_id in leaves:
                raise ValueError(f"duplicate overlay leaf for {root_id}")
            leaves[root_id] = leaf
            rows.append({
                "certificate_type": leaf["certificate_type"],
                "overlay_packet": packet_id,
                "overlay_packet_manifest_hash_schema": "canonical_json_v1",
                "overlay_packet_manifest_sha256": sha256_canonical_json(manifest),
                "overlay_packet_manifest_file_sha256": sha256_file(pdir / "manifest.json"),
                "overlay_packet_checker_sha256": sha256_file(pdir / "checker_result.json"),
                "root_id": root_id,
            })
    return leaves, rows


def produce(args: argparse.Namespace) -> dict[str, object]:
    n = args.n
    out_dir = packet_dir(n, args.packet_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    batch_paths = batch_dirs_for_prefix(n, args.start, args.end)
    overlay_leaves, overlay_rows = load_overlay_leaves(n, args.overlay_packet)

    source_batch_rows: list[dict[str, object]] = []
    tree_status_rows: list[dict[str, object]] = []
    counts = {
        "amgm_midpoint_overlay_leaf_count": 0,
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
    }
    seen_roots: set[str] = set()

    for path in batch_paths:
        manifest = read_json(path / "manifest.json")
        checker = read_json(path / "checker_result.json")
        if checker.get("status") != "PASS":
            raise ValueError(f"{path.name} checker is not PASS")
        source_batch_rows.append({
            "batch_dir": path.name,
            "checker_result_sha256": sha256_file(path / "checker_result.json"),
            "coverage": manifest["coverage"],
            "manifest_hash_schema": "file_bytes_v1",
            "manifest_sha256_current": sha256_file(path / "manifest.json"),
            "root_count": manifest["coverage"]["covered_root_count"],
            "tree_jsonl_sha256": sha256_file(path / "tree.jsonl"),
        })
        leaves = {leaf["root_id"]: leaf for leaf in read_jsonl(path / "leaves.jsonl")}
        unresolved = {row["root_id"]: row for row in read_jsonl(path / "unresolved.jsonl")}
        for row in read_jsonl(path / "tree.jsonl"):
            root_id = row["root_id"]
            if root_id in seen_roots:
                raise ValueError(f"duplicate root {root_id}")
            seen_roots.add(root_id)
            status = row["certificate_status"]
            packet_status = status
            overlay_packet = None
            if status == "coefficient_leaf":
                if root_id not in leaves:
                    raise ValueError(f"{root_id}: missing coefficient leaf")
                counts["coefficient_leaf_count"] += 1
            elif status == "polya_multiplier_leaf":
                if root_id not in leaves:
                    raise ValueError(f"{root_id}: missing Polya leaf")
                counts["polya_leaf_count"] += 1
            elif status == "unresolved":
                if root_id not in unresolved:
                    raise ValueError(f"{root_id}: missing source unresolved row")
                overlay = overlay_leaves.get(root_id)
                if overlay is None:
                    counts["unresolved_count"] += 1
                else:
                    if overlay["pullback_hash"] != row["pullback_hash"]:
                        raise ValueError(f"{root_id}: overlay pullback hash mismatch")
                    packet_status = overlay["certificate_type"]
                    counts["amgm_midpoint_overlay_leaf_count"] += 1
                    overlay_packet = next(r["overlay_packet"] for r in overlay_rows if r["root_id"] == root_id)
            else:
                raise ValueError(f"{root_id}: unsupported source status {status}")
            tree_status_rows.append({
                "overlay_packet": overlay_packet,
                "packet_status": packet_status,
                "root_id": root_id,
                "root_index": row["root_index"],
                "source_batch": path.name,
                "source_status": status,
            })

    if len(seen_roots) != args.end - args.start:
        raise ValueError("root count mismatch in prefix packet")

    write_jsonl(out_dir / "source_batches.jsonl", source_batch_rows)
    write_jsonl(out_dir / "overlay_refs.jsonl", overlay_rows)
    write_jsonl(out_dir / "root_status.jsonl", tree_status_rows)

    manifest = {
        "complete_certificate": False,
        "coverage": {
            "coverage_type": "contiguous_prefix_with_overlay_leaves",
            "end_exclusive": args.end,
            "full_root_count": math.factorial(n - 1),
            "n": n,
            "root_count": args.end - args.start,
            "start": args.start,
        },
        "full_problem_certificate": False,
        "interpretation": "Composite finite prefix packet; not a full problem certificate and not a symbolic compression rule.",
        "n": n,
        "overlay_packets": args.overlay_packet,
        "packet_counts": {**counts, "root_count": args.end - args.start},
        "source_batch_count": len(source_batch_rows),
        "tool": TOOL_VERSION,
    }
    write_json(out_dir / "manifest.json", manifest)

    audit_index = {
        "complete_certificate": False,
        "files": {
            "manifest_hash_schema": "canonical_json_v1",
            "manifest_sha256": sha256_canonical_json(manifest),
            "manifest_file_sha256": sha256_file(out_dir / "manifest.json"),
            "overlay_refs_jsonl_sha256": sha256_file(out_dir / "overlay_refs.jsonl"),
            "root_status_jsonl_sha256": sha256_file(out_dir / "root_status.jsonl"),
            "source_batches_jsonl_sha256": sha256_file(out_dir / "source_batches.jsonl"),
        },
        "n": n,
        "packet_counts": manifest["packet_counts"],
        "reproduction_commands": [
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_prefix_overlay_packet.py'} "
                f"produce --n {n} --packet-id {args.packet_id} --start {args.start} --end {args.end}"
                + "".join(f" --overlay-packet {pid}" for pid in args.overlay_packet)
            ),
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_prefix_overlay_packet.py'} "
                f"check --n {n} --packet-id {args.packet_id}"
            ),
        ],
        "tool": TOOL_VERSION,
    }
    write_json(out_dir / "audit_index.json", audit_index)
    return {
        "out_dir": str(out_dir),
        "status": "PASS" if counts["unresolved_count"] == 0 else "NEEDS_MORE_EVIDENCE",
        **manifest["packet_counts"],
    }


def check(args: argparse.Namespace) -> dict[str, object]:
    n = args.n
    out_dir = packet_dir(n, args.packet_id)
    failures: list[str] = []
    manifest = read_json(out_dir / "manifest.json")
    audit_index = read_json(out_dir / "audit_index.json")
    for key, rel in [
        ("source_batches_jsonl_sha256", "source_batches.jsonl"),
        ("overlay_refs_jsonl_sha256", "overlay_refs.jsonl"),
        ("root_status_jsonl_sha256", "root_status.jsonl"),
    ]:
        if sha256_file(out_dir / rel) != audit_index["files"][key]:
            failures.append(f"{rel} hash mismatch")
    if sha256_canonical_json(manifest) != audit_index["files"]["manifest_sha256"]:
        failures.append("manifest hash mismatch")
    if "manifest_file_sha256" in audit_index["files"] and sha256_file(out_dir / "manifest.json") != audit_index["files"]["manifest_file_sha256"]:
        failures.append("manifest file hash mismatch")

    counts = {
        "amgm_midpoint_overlay_leaf_count": 0,
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
        "root_count": 0,
    }
    source_rows = read_jsonl(out_dir / "source_batches.jsonl")
    overlay_refs = {row["root_id"]: row for row in read_jsonl(out_dir / "overlay_refs.jsonl")}
    root_status = read_jsonl(out_dir / "root_status.jsonl")
    batch_lookup = {row["batch_dir"]: row for row in source_rows}

    for row in source_rows:
        bdir = BATCH_ROOT / f"n{n}" / row["batch_dir"]
        if sha256_file(bdir / "tree.jsonl") != row["tree_jsonl_sha256"]:
            failures.append(f"{row['batch_dir']}: tree hash mismatch")
        if sha256_file(bdir / "checker_result.json") != row["checker_result_sha256"]:
            failures.append(f"{row['batch_dir']}: checker hash mismatch")
        if read_json(bdir / "checker_result.json").get("status") != "PASS":
            failures.append(f"{row['batch_dir']}: checker not PASS")

    seen: set[str] = set()
    for row in root_status:
        root_id = row["root_id"]
        if root_id in seen:
            failures.append(f"{root_id}: duplicate status row")
        seen.add(root_id)
        if row["source_batch"] not in batch_lookup:
            failures.append(f"{root_id}: unknown source batch")
        status = row["packet_status"]
        if status == "coefficient_leaf":
            counts["coefficient_leaf_count"] += 1
        elif status == "polya_multiplier_leaf":
            counts["polya_leaf_count"] += 1
        elif status == "amgm_midpoint_circuit_polya_leaf":
            counts["amgm_midpoint_overlay_leaf_count"] += 1
            if root_id not in overlay_refs:
                failures.append(f"{root_id}: missing overlay ref")
        elif status == "unresolved":
            counts["unresolved_count"] += 1
        else:
            failures.append(f"{root_id}: unknown packet status {status}")
        counts["root_count"] += 1

    for key, value in counts.items():
        if manifest["packet_counts"].get(key) != value:
            failures.append(f"count mismatch for {key}")
    if counts["root_count"] != manifest["coverage"]["root_count"]:
        failures.append("coverage root count mismatch")

    result = {
        "complete_certificate": False,
        "failures": failures,
        "full_problem_certificate": False,
        "n": n,
        "packet_counts": counts,
        "packet_id": args.packet_id,
        "status": "PASS" if not failures else "FAIL",
        "tool": TOOL_VERSION,
    }
    write_json(out_dir / "checker_result.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    produce_parser = sub.add_parser("produce")
    produce_parser.add_argument("--n", type=int, required=True, choices=(9, 11))
    produce_parser.add_argument("--packet-id", required=True)
    produce_parser.add_argument("--start", type=int, default=0)
    produce_parser.add_argument("--end", type=int, required=True)
    produce_parser.add_argument("--overlay-packet", action="append", default=[])

    check_parser = sub.add_parser("check")
    check_parser.add_argument("--n", type=int, required=True, choices=(9, 11))
    check_parser.add_argument("--packet-id", required=True)

    args = parser.parse_args()
    if args.command == "produce":
        print(canonical_json(produce(args)))
    elif args.command == "check":
        print(canonical_json(check(args)))
    else:
        raise AssertionError(args.command)


if __name__ == "__main__":
    main()
