#!/usr/bin/env python3
"""Regenerate the Vasc n=9 reviewer certificate files from producer sources.

The default mode is intentionally non-destructive.  It prepares a separate
build workspace, copies the producer sources there, and runs the deterministic
build plan in ``rebuild/n9_rebuild_plan.json``.  Existing non-empty build
workspaces require ``--resume``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PRODUCER_SOURCE_DIR = PACKAGE_ROOT / "producer_sources"
DEFAULT_PLAN = PACKAGE_ROOT / "rebuild" / "n9_rebuild_plan.json"
DEFAULT_BUILD_WORKSPACE = PACKAGE_ROOT / "_rebuild_workspace"
DEFAULT_SHA256SUMS = PACKAGE_ROOT / "SHA256SUMS"
FINAL_PACKET_ID = "prefix_0000000_0040320_with_hardroots"

PRODUCER_FILES = [
    "vasc_certificate_producer.py",
    "vasc_polya_pilot.py",
    "vasc_polya_batch.py",
    "vasc_hardroot_packet.py",
    "vasc_prefix_overlay_packet.py",
    "vasc_n9_cover_pipeline.py",
    "vasc_n9_range_worker.py",
    "vasc_range_plan.py",
]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shell_cmd(cmd: list[str]) -> str:
    return shlex.join(cmd)


def run(cmd: list[str], build_workspace: Path, dry_run: bool = False) -> None:
    env = os.environ.copy()
    env["VASC_WORKSPACE"] = str(build_workspace)
    print(shell_cmd(cmd), flush=True)
    if dry_run:
        return
    subprocess.run(cmd, cwd=build_workspace, env=env, check=True)


def load_plan(path: Path) -> dict:
    plan = read_json(path)
    if plan.get("schema") != "vasc_n9_rebuild_plan_v1":
        raise SystemExit(f"unsupported rebuild plan schema in {path}")
    if plan.get("n") != 9 or plan.get("final_packet_id") != FINAL_PACKET_ID:
        raise SystemExit(f"{path} is not the n=9 final certificate plan")
    return plan


def is_nonempty_dir(path: Path) -> bool:
    return path.exists() and any(path.iterdir())


def prepare_build_workspace(build_workspace: Path, plan_path: Path, resume: bool) -> None:
    if build_workspace.exists() and not build_workspace.is_dir():
        raise SystemExit(f"build workspace is not a directory: {build_workspace}")
    if is_nonempty_dir(build_workspace) and not resume:
        raise SystemExit(
            f"build workspace is not empty: {build_workspace}\n"
            "Use --resume to continue in place, or choose a fresh --build-workspace."
        )

    tools_dir = build_workspace / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    (build_workspace / "logs").mkdir(parents=True, exist_ok=True)
    for name in PRODUCER_FILES:
        source = PRODUCER_SOURCE_DIR / name
        if not source.exists():
            raise SystemExit(f"missing producer source: {source}")
        shutil.copy2(source, tools_dir / name)

    verifier = PACKAGE_ROOT / "tools" / "verify_n9_certificate_minimal.py"
    if verifier.exists():
        shutil.copy2(verifier, tools_dir / verifier.name)

    write_json(build_workspace / "rebuild" / "n9_rebuild_plan.json", read_json(plan_path))


def checker_pass(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        return read_json(path).get("status") == "PASS"
    except json.JSONDecodeError:
        return False


def batch_dir(build_workspace: Path, batch: dict) -> Path:
    return build_workspace / "certificates" / "polya_batches" / "n9" / batch["batch_dir"]


def hardroot_dir(build_workspace: Path, packet: dict) -> Path:
    return build_workspace / "certificates" / "polya_packets" / "n9" / packet["packet_id"]


def generate_batch(batch: dict, build_workspace: Path, resume: bool, dry_run: bool) -> None:
    target = batch_dir(build_workspace, batch)
    if resume and checker_pass(target / "checker_result.json"):
        print(f"skip checked batch {batch['batch_dir']}", flush=True)
        return
    script = build_workspace / "tools" / "vasc_polya_batch.py"
    common = [
        "--n",
        "9",
        "--start",
        str(batch["start"]),
        "--count",
        str(batch["count"]),
        "--max-polya-power",
        str(batch["max_polya_power"]),
    ]
    if batch.get("include_root_universe_hash", True):
        common.append("--include-root-universe-hash")
    run([sys.executable, str(script), "produce", *common], build_workspace, dry_run=dry_run)
    run([sys.executable, str(script), "check", *common], build_workspace, dry_run=dry_run)


def generate_hardroot_packet(packet: dict, build_workspace: Path, resume: bool, dry_run: bool) -> None:
    target = hardroot_dir(build_workspace, packet)
    if resume and checker_pass(target / "checker_result.json"):
        print(f"skip checked hardroot packet {packet['packet_id']}", flush=True)
        return
    script = build_workspace / "tools" / "vasc_hardroot_packet.py"
    cmd = [
        sys.executable,
        str(script),
        "produce",
        "--n",
        "9",
        "--packet-id",
        packet["packet_id"],
        "--source-batch",
        packet["source_batch"],
        "--polya-power",
        str(packet["polya_power"]),
        "--max-direction-step",
        str(packet.get("max_direction_step", 3)),
    ]
    for root_id in packet["root_ids"]:
        cmd.extend(["--root-id", root_id])
    run(cmd, build_workspace, dry_run=dry_run)
    run(
        [
            sys.executable,
            str(script),
            "check",
            "--n",
            "9",
            "--packet-id",
            packet["packet_id"],
        ],
        build_workspace,
        dry_run=dry_run,
    )


def generate_overlay(plan: dict, build_workspace: Path, resume: bool, dry_run: bool) -> None:
    packet_dir = build_workspace / "certificates" / "polya_packets" / "n9" / FINAL_PACKET_ID
    if resume and checker_pass(packet_dir / "checker_result.json"):
        print(f"skip checked overlay packet {FINAL_PACKET_ID}", flush=True)
        return
    script = build_workspace / "tools" / "vasc_prefix_overlay_packet.py"
    cmd = [
        sys.executable,
        str(script),
        "produce",
        "--n",
        "9",
        "--packet-id",
        FINAL_PACKET_ID,
        "--start",
        str(plan["final_range"]["start"]),
        "--end",
        str(plan["final_range"]["end_exclusive"]),
    ]
    for packet_id in plan["overlay_packets"]:
        cmd.extend(["--overlay-packet", packet_id])
    run(cmd, build_workspace, dry_run=dry_run)
    run(
        [
            sys.executable,
            str(script),
            "check",
            "--n",
            "9",
            "--packet-id",
            FINAL_PACKET_ID,
        ],
        build_workspace,
        dry_run=dry_run,
    )


def select_hardroot_smoke_packet(plan: dict) -> dict:
    batches = {row["batch_dir"]: row for row in plan["batches"]}
    return min(
        plan["hardroot_packets"],
        key=lambda packet: (
            batches[packet["source_batch"]]["max_polya_power"],
            len(packet["root_ids"]),
            packet["packet_id"],
        ),
    )


def generate_smoke_overlay(first_batch: dict, build_workspace: Path, dry_run: bool) -> None:
    script = build_workspace / "tools" / "vasc_prefix_overlay_packet.py"
    packet_id = "smoke_prefix_0000000_0000032"
    run(
        [
            sys.executable,
            str(script),
            "produce",
            "--n",
            "9",
            "--packet-id",
            packet_id,
            "--start",
            "0",
            "--end",
            str(first_batch["end_exclusive"]),
        ],
        build_workspace,
        dry_run=dry_run,
    )
    run(
        [sys.executable, str(script), "check", "--n", "9", "--packet-id", packet_id],
        build_workspace,
        dry_run=dry_run,
    )


def parse_sha256sums(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            digest, rel = line.split(None, 1)
        except ValueError as exc:
            raise SystemExit(f"bad SHA256SUMS line {line_no}: {line!r}") from exc
        rows.append((digest, rel.strip()))
    return rows


def compare_certificate_hashes(
    build_workspace: Path,
    sha256sums: Path,
    prefixes: list[str] | None = None,
) -> None:
    checked = 0
    failures: list[str] = []
    for expected, rel in parse_sha256sums(sha256sums):
        if not rel.startswith("certificates/"):
            continue
        if prefixes is not None and not any(rel.startswith(prefix) for prefix in prefixes):
            continue
        path = build_workspace / rel
        if not path.exists():
            failures.append(f"missing {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            failures.append(f"hash mismatch {rel}: expected {expected}, got {actual}")
        checked += 1

    print(f"checked {checked} listed certificate hashes", flush=True)
    if failures:
        for failure in failures[:20]:
            print(failure, flush=True)
        if len(failures) > 20:
            print(f"... {len(failures) - 20} more failures", flush=True)
        raise SystemExit("certificate hash comparison failed")


def run_independent_verifier(build_workspace: Path, limit: int | None, dry_run: bool) -> None:
    script = build_workspace / "tools" / "verify_n9_certificate_minimal.py"
    cmd = [
        sys.executable,
        str(script),
        "--workspace",
        str(build_workspace),
        "--packet-id",
        FINAL_PACKET_ID,
        "--quiet",
    ]
    if limit is not None:
        cmd.extend(["--limit", str(limit)])
    run(cmd, build_workspace, dry_run=dry_run)


def print_plan_summary(plan: dict, args: argparse.Namespace) -> None:
    print("Vasc n=9 rebuild plan")
    print(f"  batches: {plan['batch_count']}")
    print(f"  hardroot packets: {plan['hardroot_packet_count']}")
    print(f"  final packet: {plan['final_packet_id']}")
    print(f"  build workspace: {args.build_workspace}")
    print("")
    print("Smoke test:")
    print(
        shell_cmd(
            [
                sys.executable,
                str(PACKAGE_ROOT / "tools" / "rebuild_n9_certificate_from_sources.py"),
                "--mode",
                "smoke",
                "--build-workspace",
                str(args.build_workspace),
            ]
        )
    )
    print("")
    print("Full rebuild:")
    print(
        shell_cmd(
            [
                sys.executable,
                str(PACKAGE_ROOT / "tools" / "rebuild_n9_certificate_from_sources.py"),
                "--mode",
                "full",
                "--build-workspace",
                str(args.build_workspace),
            ]
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "smoke", "full"), default="plan")
    parser.add_argument("--build-workspace", type=Path, default=DEFAULT_BUILD_WORKSPACE)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--sha256sums", type=Path, default=DEFAULT_SHA256SUMS)
    parser.add_argument("--resume", action="store_true", help="continue in an existing build workspace")
    parser.add_argument("--dry-run", action="store_true", help="print commands without running them")
    parser.add_argument(
        "--include-hardroot-smoke",
        action="store_true",
        help="also rebuild the first AM-GM hardroot packet during smoke mode",
    )
    parser.add_argument(
        "--skip-hash-check",
        action="store_true",
        help="do not compare generated certificate files against SHA256SUMS",
    )
    parser.add_argument(
        "--run-independent-verifier",
        action="store_true",
        help="after full rebuild, run the independent minimal checker; this can take a day or more",
    )
    parser.add_argument("--verifier-limit", type=int, default=None)
    args = parser.parse_args()

    plan = load_plan(args.plan)
    args.build_workspace = args.build_workspace.resolve()

    if args.mode == "plan":
        print_plan_summary(plan, args)
        return

    prepare_build_workspace(args.build_workspace, args.plan, args.resume)

    if args.mode == "smoke":
        first_batch = plan["batches"][0]
        generate_batch(first_batch, args.build_workspace, resume=args.resume, dry_run=args.dry_run)
        generate_smoke_overlay(first_batch, args.build_workspace, dry_run=args.dry_run)
        prefixes = [f"certificates/polya_batches/n9/{first_batch['batch_dir']}/"]
        if args.include_hardroot_smoke:
            first_packet = select_hardroot_smoke_packet(plan)
            source_batch = next(row for row in plan["batches"] if row["batch_dir"] == first_packet["source_batch"])
            generate_batch(source_batch, args.build_workspace, resume=args.resume, dry_run=args.dry_run)
            generate_hardroot_packet(first_packet, args.build_workspace, resume=args.resume, dry_run=args.dry_run)
            prefixes.append(f"certificates/polya_packets/n9/{first_packet['packet_id']}/")
        if not args.skip_hash_check and not args.dry_run:
            compare_certificate_hashes(args.build_workspace, args.sha256sums, prefixes=prefixes)
        return

    for batch in plan["batches"]:
        generate_batch(batch, args.build_workspace, resume=args.resume, dry_run=args.dry_run)
    for packet in plan["hardroot_packets"]:
        generate_hardroot_packet(packet, args.build_workspace, resume=args.resume, dry_run=args.dry_run)
    generate_overlay(plan, args.build_workspace, resume=args.resume, dry_run=args.dry_run)

    if not args.skip_hash_check and not args.dry_run:
        compare_certificate_hashes(args.build_workspace, args.sha256sums)
    if args.run_independent_verifier:
        run_independent_verifier(args.build_workspace, args.verifier_limit, args.dry_run)


if __name__ == "__main__":
    main()
