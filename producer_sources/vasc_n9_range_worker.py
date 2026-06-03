#!/usr/bin/env python3
"""Parallel-safe n=9 range worker for raw batches and hard-root packets.

This worker deliberately does not build prefix overlay packets and does not
update the global coverage index.  It only writes disjoint per-batch artifacts
and named hard-root packets, so multiple workers can run on non-overlapping
ranges.  A separate prefix overlay/check step is still required before any
finite prefix is treated as covered.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
PIPELINE_TOOL = WORKSPACE / "tools" / "vasc_n9_cover_pipeline.py"
BATCH_ROOT = WORKSPACE / "certificates" / "polya_batches" / "n9"


def load_pipeline():
    spec = importlib.util.spec_from_file_location("vasc_n9_cover_pipeline", PIPELINE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PIPELINE_TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load_pipeline()


def emit(event: str, **payload) -> None:
    print(json.dumps({"event": event, **payload}, sort_keys=True), flush=True)


def batch_dir(start: int, count: int) -> Path:
    return BATCH_ROOT / f"batch_{start:07d}_{start + count:07d}"


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def chunks(items: list[str], size: int):
    for idx in range(0, len(items), size):
        yield items[idx:idx + size]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--max-polya-power", type=int, default=8)
    parser.add_argument("--hardroot-polya-powers", default="8,10,12,14")
    parser.add_argument("--hardroot-chunk-size", type=int, default=6)
    parser.add_argument("--max-direction-step", type=int, default=3)
    args = parser.parse_args()

    powers = [int(part) for part in args.hardroot_polya_powers.split(",") if part.strip()]
    cursor = args.start
    while cursor < args.end:
        count = min(args.batch_size, args.end - cursor)
        checker = pipeline.produce_and_check_batch(cursor, count, args.max_polya_power)
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
                pipeline.produce_and_check_hardroot_packet(
                    source_batch,
                    group,
                    powers,
                    args.max_direction_step,
                )
        cursor += count

    emit("done", start=args.start, end=args.end)


if __name__ == "__main__":
    main()
