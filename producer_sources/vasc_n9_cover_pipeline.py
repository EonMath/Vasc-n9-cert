#!/usr/bin/env python3
"""Automated exact n=9 prefix coverage pipeline.

The pipeline only produces and checks finite computation packets.  It does not
claim a full problem proof by itself.  For each raw lexicographic batch it:

1. produces/checks a Polya batch;
2. if raw unresolved roots remain, produces/checks small hard-root AM-GM
   midpoint packets for exactly those roots;
3. produces/checks a composite prefix overlay packet with all checked hard-root
   packets available so far.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
POLYA_BATCH_TOOL = WORKSPACE / "tools" / "vasc_polya_batch.py"
HARDROOT_TOOL = WORKSPACE / "tools" / "vasc_hardroot_packet.py"
OVERLAY_TOOL = WORKSPACE / "tools" / "vasc_prefix_overlay_packet.py"
PACKET_ROOT = WORKSPACE / "certificates" / "polya_packets" / "n9"
BATCH_ROOT = WORKSPACE / "certificates" / "polya_batches" / "n9"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


polya_batch = load_module("vasc_polya_batch", POLYA_BATCH_TOOL)
hardroot = load_module("vasc_hardroot_packet", HARDROOT_TOOL)
overlay = load_module("vasc_prefix_overlay_packet", OVERLAY_TOOL)


def emit(event: str, **payload) -> None:
    print(json.dumps({"event": event, **payload}, sort_keys=True), flush=True)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def batch_dir(start: int, count: int) -> Path:
    return BATCH_ROOT / f"batch_{start:07d}_{start + count:07d}"


def checked_hardroot_packets() -> list[str]:
    out: list[str] = []
    if not PACKET_ROOT.exists():
        return out
    for path in sorted(PACKET_ROOT.glob("hardroots_*")):
        checker_path = path / "checker_result.json"
        leaves_path = path / "leaves.jsonl"
        if not checker_path.exists() or not leaves_path.exists():
            continue
        checker = read_json(checker_path)
        if checker.get("status") == "PASS" and checker.get("packet_counts", {}).get("unresolved_count") == 0:
            out.append(path.name)
    return out


def chunks(items: list[str], size: int):
    for idx in range(0, len(items), size):
        yield items[idx:idx + size]


def produce_and_check_batch(start: int, count: int, max_polya_power: int) -> dict[str, object]:
    args = argparse.Namespace(
        count=count,
        include_root_universe_hash=True,
        max_polya_power=max_polya_power,
        n=9,
        start=start,
    )
    polya_batch.produce(args)
    polya_batch.check(args)
    return read_json(batch_dir(start, count) / "checker_result.json")


def produce_and_check_hardroot_packet(source_batch: str, root_ids: list[str], polya_powers: list[int], max_direction_step: int) -> str:
    first = root_ids[0].split("_", 1)[1]
    last = root_ids[-1].split("_", 1)[1]
    packet_id = f"hardroots_{first}_{last}"
    for polya_power in polya_powers:
        args = argparse.Namespace(
            max_direction_step=max_direction_step,
            n=9,
            packet_id=packet_id,
            polya_power=polya_power,
            root_id=root_ids,
            source_batch=source_batch,
        )
        result = hardroot.make_packet(args)
        hardroot.check_packet(argparse.Namespace(n=9, packet_id=packet_id))
        checker = read_json(PACKET_ROOT / packet_id / "checker_result.json")
        emit(
            "hardroot_packet",
            packet_id=packet_id,
            polya_power=polya_power,
            root_count=len(root_ids),
            status=checker["status"],
            unresolved_count=checker["packet_counts"]["unresolved_count"],
        )
        if result["status"] == "PASS" and checker["status"] == "PASS" and checker["packet_counts"]["unresolved_count"] == 0:
            return packet_id
    raise RuntimeError(f"{packet_id}: hard-root packet failed for powers {polya_powers}")


def produce_and_check_overlay(end: int, packet_id: str | None = None) -> dict[str, object]:
    overlay_packets = checked_hardroot_packets()
    if packet_id is None:
        packet_id = f"prefix_0000000_{end:07d}_with_hardroots"
    args = argparse.Namespace(end=end, n=9, overlay_packet=overlay_packets, packet_id=packet_id, start=0)
    result = overlay.produce(args)
    checker = overlay.check(argparse.Namespace(n=9, packet_id=packet_id))
    emit(
        "overlay",
        end=end,
        packet_id=packet_id,
        status=checker["status"],
        unresolved_count=checker["packet_counts"]["unresolved_count"],
        amgm_midpoint_overlay_leaf_count=checker["packet_counts"]["amgm_midpoint_overlay_leaf_count"],
        coefficient_leaf_count=checker["packet_counts"]["coefficient_leaf_count"],
        polya_leaf_count=checker["packet_counts"]["polya_leaf_count"],
    )
    if result["status"] != "PASS" or checker["status"] != "PASS" or checker["packet_counts"]["unresolved_count"] != 0:
        raise RuntimeError(f"{packet_id}: overlay failed")
    return checker


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-polya-power", type=int, default=8)
    parser.add_argument("--hardroot-polya-powers", default="8,10,12,14")
    parser.add_argument("--hardroot-chunk-size", type=int, default=6)
    parser.add_argument("--max-direction-step", type=int, default=3)
    parser.add_argument("--overlay-every", type=int, default=256)
    args = parser.parse_args()

    powers = [int(part) for part in args.hardroot_polya_powers.split(",") if part.strip()]
    cursor = args.start
    last_overlay = args.start
    while cursor < args.end:
        count = min(args.batch_size, args.end - cursor)
        checker = produce_and_check_batch(cursor, count, args.max_polya_power)
        summary = checker["summaries"]
        emit(
            "batch",
            start=cursor,
            end=cursor + count,
            status=checker["status"],
            coefficient_leaf_count=summary["coefficient_leaf_count"],
            polya_leaf_count=summary["polya_leaf_count"],
            unresolved_count=summary["unresolved_count"],
        )
        if checker["status"] != "PASS":
            raise RuntimeError(f"raw batch [{cursor},{cursor + count}) failed")

        if summary["unresolved_count"]:
            source_batch = f"batch_{cursor:07d}_{cursor + count:07d}"
            unresolved_rows = read_jsonl(batch_dir(cursor, count) / "unresolved.jsonl")
            root_ids = [str(row["root_id"]) for row in unresolved_rows]
            for group in chunks(root_ids, args.hardroot_chunk_size):
                produce_and_check_hardroot_packet(source_batch, group, powers, args.max_direction_step)

        cursor += count
        if cursor - last_overlay >= args.overlay_every or cursor == args.end or summary["unresolved_count"]:
            produce_and_check_overlay(cursor)
            last_overlay = cursor
            polya_batch.summarize(argparse.Namespace(n=9))

    emit("done", start=args.start, end=args.end)


if __name__ == "__main__":
    main()
