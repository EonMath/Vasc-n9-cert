#!/usr/bin/env python3
"""Exact lexicographic batch producer/checker for Vasc Polya leaves.

This tool extends the selected-root Polya pilot to deterministic root ranges.
It is still not a proof certificate unless every root range is covered and all
leaves are certified.  Each batch is independently reproducible from its
manifest parameters.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import time
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
CERT_ROOT = WORKSPACE / "certificates" / "polya_batches"
PILOT_TOOL = WORKSPACE / "tools" / "vasc_polya_pilot.py"
TOOL_VERSION = "vasc_polya_batch_v1"


def load_pilot():
    spec = importlib.util.spec_from_file_location("vasc_polya_pilot", PILOT_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PILOT_TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pilot = load_pilot()
base = pilot.base


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")


def write_jsonl_row(handle, row: object) -> None:
    handle.write(canonical_json(row) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def batch_dir(n: int, start: int, count: int) -> Path:
    return CERT_ROOT / f"n{n}" / f"batch_{start:07d}_{start + count:07d}"


def lexicographic_perm_at(n: int, index: int) -> tuple[int, ...]:
    elems = list(range(1, n))
    if index < 0 or index >= math.factorial(n - 1):
        raise ValueError(f"index {index} out of range for n={n}")
    out: list[int] = []
    remainder = index
    for width in range(n - 1, 0, -1):
        block = math.factorial(width - 1)
        pos, remainder = divmod(remainder, block)
        out.append(elems.pop(pos))
    return tuple(out)


def iter_indexed_perms(n: int, start: int, count: int):
    for root_index in range(start, start + count):
        perm = lexicographic_perm_at(n, root_index)
        yield root_index, tuple(perm)


def make_leaf(
    n: int,
    root_id: str,
    pullback_hash: str,
    pullback_summary: dict[str, int],
    pullback,
    max_k: int,
) -> tuple[str, dict[str, object] | None, dict[str, object] | None]:
    if pullback_summary["negative_count"] == 0:
        return "coefficient_leaf", {
            "certificate_type": "coefficientwise_nonnegative",
            "leaf_id": root_id,
            "pullback_hash": pullback_hash,
            "pullback_summary": pullback_summary,
            "reconstruction_rule": "direct_root_pullback_from_P_n_and_lexicographic_perm",
            "root_id": root_id,
        }, None

    polya_k, polya_product, polya_summary = pilot.poly_sum_power_certificate(pullback, n, max_k)
    if polya_k is not None:
        return "polya_multiplier_leaf", {
            "certificate_type": "polya_sum_multiplier",
            "leaf_id": root_id,
            "multiplier": "(y1+...+yn)^k",
            "polya_power": polya_k,
            "polya_product_hash": pilot.poly_stream_hash(
                polya_product,
                n=n,
                label=f"polya_product_{root_id}_k{polya_k}",
            ),
            "polya_product_hash_schema": "stream_terms_v1",
            "polya_product_summary": polya_summary,
            "pullback_hash": pullback_hash,
            "pullback_summary": pullback_summary,
            "reconstruction_rule": "direct_root_pullback_from_P_n_and_lexicographic_perm_then_exact_sum_power",
            "root_id": root_id,
        }, None

    return "unresolved", None, {
        "last_polya_summary": polya_summary,
        "max_polya_power_tried": max_k,
        "pullback_hash": pullback_hash,
        "pullback_summary": pullback_summary,
        "root_id": root_id,
    }


def produce(args: argparse.Namespace) -> None:
    n = args.n
    start = args.start
    count = args.count
    max_k = args.max_polya_power
    full_root_count = math.factorial(n - 1)
    if start < 0 or count <= 0 or start + count > full_root_count:
        raise ValueError(f"invalid range start={start}, count={count}, full_root_count={full_root_count}")

    target_dir = batch_dir(n, start, count)
    target_dir.mkdir(parents=True, exist_ok=True)
    p_poly = base.vasc_polynomial(n)
    started = time.time()

    counts = {
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
    }

    with (
        (target_dir / "roots.jsonl").open("w", encoding="utf-8") as roots_handle,
        (target_dir / "tree.jsonl").open("w", encoding="utf-8") as tree_handle,
        (target_dir / "leaves.jsonl").open("w", encoding="utf-8") as leaves_handle,
        (target_dir / "unresolved.jsonl").open("w", encoding="utf-8") as unresolved_handle,
    ):
        for root_index, perm in iter_indexed_perms(n, start, count):
            root_id = f"root_{root_index:07d}"
            root_record, pullback = base.root_record(n, root_id, perm, p_poly)
            pullback_hash = root_record["pullback_hash"]
            pullback_summary = root_record["coefficient_summary"]
            status, leaf, unresolved = make_leaf(n, root_id, pullback_hash, pullback_summary, pullback, max_k)

            if status == "coefficient_leaf":
                counts["coefficient_leaf_count"] += 1
                write_jsonl_row(leaves_handle, leaf)
            elif status == "polya_multiplier_leaf":
                counts["polya_leaf_count"] += 1
                write_jsonl_row(leaves_handle, leaf)
            else:
                counts["unresolved_count"] += 1
                unresolved["perm"] = list(perm)
                write_jsonl_row(unresolved_handle, unresolved)

            write_jsonl_row(roots_handle, {"n": n, "perm": list(perm), "root_id": root_id, "root_index": root_index})
            write_jsonl_row(tree_handle, {
                "certificate_status": status,
                "depth": 0,
                "node_id": root_id,
                "parent_id": None,
                "perm": list(perm),
                "pullback_hash": pullback_hash,
                "pullback_summary": pullback_summary,
                "root_id": root_id,
                "root_index": root_index,
            })

            del pullback

    root_universe = {
        "fixed_maximum_variable": "x1",
        "root_count": full_root_count,
        "root_record_schema": {"root_index": "lexicographic index", "perm": "ordering of x2..xn by decreasing value"},
        "type": "cyclic_maximum_then_all_orderings_stream",
    }
    if args.include_root_universe_hash:
        root_count, root_hash = base.root_universe_hash(n)
        root_universe["root_count"] = root_count
        root_universe["root_stream_hash"] = root_hash
    else:
        root_universe["root_stream_hash"] = None
        root_universe["root_stream_hash_status"] = "not_recomputed_for_batch"

    manifest = {
        "complete_certificate": False,
        "coverage": {
            "covered_root_count": count,
            "coverage_type": "lexicographic_root_range_batch",
            "end_exclusive": start + count,
            "full_root_count": full_root_count,
            "missing_root_count": full_root_count - count,
            "n": n,
            "start": start,
        },
        "leaf_rule": {
            "coefficient_leaf": "pullback has nonnegative integer coefficients",
            "max_polya_power": max_k,
            "polya_multiplier_leaf": "(sum y_i)^k times pullback has nonnegative integer coefficients; sum y_i is positive off the origin",
        },
        "n": n,
        "pilot_counts": {
            **counts,
            "batch_root_count": count,
        },
        "root_universe": root_universe,
        "target_polynomial_hash": base.poly_hash(p_poly, n=n, label="P_n"),
        "tool": TOOL_VERSION,
    }
    write_json(target_dir / "manifest.json", manifest)

    audit_index = {
        "complete_certificate": False,
        "files": {
            "leaves_jsonl_sha256": sha256_file(target_dir / "leaves.jsonl"),
            "manifest_sha256": hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
            "roots_jsonl_sha256": sha256_file(target_dir / "roots.jsonl"),
            "tree_jsonl_sha256": sha256_file(target_dir / "tree.jsonl"),
            "unresolved_jsonl_sha256": sha256_file(target_dir / "unresolved.jsonl"),
        },
        "n": n,
        "pilot_counts": manifest["pilot_counts"],
        "reproduction_commands": [
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_polya_batch.py'} "
                f"produce --n {n} --start {start} --count {count} --max-polya-power {max_k}"
            ),
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_polya_batch.py'} "
                f"check --n {n} --start {start} --count {count} --max-polya-power {max_k}"
            ),
        ],
        "runtime_seconds": round(time.time() - started, 3),
        "tool": TOOL_VERSION,
    }
    if args.include_root_universe_hash:
        audit_index["reproduction_commands"][0] += " --include-root-universe-hash"
        audit_index["reproduction_commands"][1] += " --include-root-universe-hash"
    write_json(target_dir / "audit_index.json", audit_index)

    log = [
        "# Vasc Polya Batch Producer Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        "- Arithmetic: exact integer polynomial arithmetic.",
        "- Scope: one lexicographic root range batch.",
        "- Complete proof certificate: NO.",
        f"- Target: `n={n}`.",
        f"- Range: `[{start}, {start + count})`.",
        f"- Max Polya power: `{max_k}`.",
        f"- Coefficient leaves: `{counts['coefficient_leaf_count']}`.",
        f"- Polya multiplier leaves: `{counts['polya_leaf_count']}`.",
        f"- Unresolved roots: `{counts['unresolved_count']}`.",
        f"- Runtime seconds: `{audit_index['runtime_seconds']}`.",
        "",
    ]
    (WORKSPACE / "logs" / f"polya_batch_n{n}_{start:07d}_{start + count:07d}_produce.md").write_text(
        "\n".join(log),
        encoding="utf-8",
    )


def check(args: argparse.Namespace) -> None:
    n = args.n
    start = args.start
    count = args.count
    max_k = args.max_polya_power
    target_dir = batch_dir(n, start, count)
    failures: list[str] = []

    manifest = read_json(target_dir / "manifest.json")
    audit_index = read_json(target_dir / "audit_index.json")
    for name, rel in [
        ("roots_jsonl_sha256", "roots.jsonl"),
        ("tree_jsonl_sha256", "tree.jsonl"),
        ("leaves_jsonl_sha256", "leaves.jsonl"),
        ("unresolved_jsonl_sha256", "unresolved.jsonl"),
    ]:
        if sha256_file(target_dir / rel) != audit_index["files"][name]:
            failures.append(f"{rel} hash mismatch")
    if hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest() != audit_index["files"]["manifest_sha256"]:
        failures.append("manifest hash mismatch")

    full_root_count = math.factorial(n - 1)
    if manifest["coverage"] != {
        "covered_root_count": count,
        "coverage_type": "lexicographic_root_range_batch",
        "end_exclusive": start + count,
        "full_root_count": full_root_count,
        "missing_root_count": full_root_count - count,
        "n": n,
        "start": start,
    }:
        failures.append("coverage metadata mismatch")

    p_poly = base.vasc_polynomial(n)
    if base.poly_hash(p_poly, n=n, label="P_n") != manifest["target_polynomial_hash"]:
        failures.append("target polynomial hash mismatch")
    if manifest["root_universe"]["root_count"] != full_root_count:
        failures.append("root count mismatch")
    if args.include_root_universe_hash:
        root_count, root_hash = base.root_universe_hash(n)
        if manifest["root_universe"].get("root_stream_hash") != root_hash or root_count != full_root_count:
            failures.append("root universe hash mismatch")

    roots = {row["root_id"]: tuple(row["perm"]) for row in read_jsonl(target_dir / "roots.jsonl")}
    leaves = {row["leaf_id"]: row for row in read_jsonl(target_dir / "leaves.jsonl")}
    unresolved_by_id = {row["root_id"]: row for row in read_jsonl(target_dir / "unresolved.jsonl")}
    counts = {
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
    }

    tree_rows = read_jsonl(target_dir / "tree.jsonl")
    if len(tree_rows) != count:
        failures.append("tree row count mismatch")

    for (expected_index, expected_perm), row in zip(iter_indexed_perms(n, start, count), tree_rows):
        rid = row["root_id"]
        if row.get("root_index") != expected_index:
            failures.append(f"{rid}: root index mismatch")
        if rid not in roots:
            failures.append(f"{rid}: missing root record")
            continue
        if roots[rid] != expected_perm:
            failures.append(f"{rid}: permutation mismatch")
            continue

        rec, pullback = base.root_record(n, rid, roots[rid], p_poly)
        if rec["pullback_hash"] != row["pullback_hash"]:
            failures.append(f"{rid}: pullback hash mismatch")
        if rec["coefficient_summary"] != row["pullback_summary"]:
            failures.append(f"{rid}: pullback summary mismatch")

        status = row["certificate_status"]
        if status == "coefficient_leaf":
            counts["coefficient_leaf_count"] += 1
            if rid not in leaves:
                failures.append(f"{rid}: missing coefficient leaf")
            if rec["coefficient_summary"]["negative_count"] != 0:
                failures.append(f"{rid}: coefficient leaf has negative coefficients")
        elif status == "polya_multiplier_leaf":
            counts["polya_leaf_count"] += 1
            leaf = leaves.get(rid)
            if leaf is None:
                failures.append(f"{rid}: missing polya leaf")
                continue
            k = leaf["polya_power"]
            if k > max_k:
                failures.append(f"{rid}: polya power exceeds requested max")
            current = pullback
            for _ in range(k):
                current = base.mul_linear(current, [(1, i) for i in range(n)])
            summary = base.coeff_summary(current)
            product_hash = pilot.poly_stream_hash(current, n=n, label=f"polya_product_{rid}_k{k}")
            if leaf.get("polya_product_hash_schema") != "stream_terms_v1":
                failures.append(f"{rid}: unsupported polya product hash schema")
            if product_hash != leaf["polya_product_hash"]:
                failures.append(f"{rid}: polya product hash mismatch")
            if summary != leaf["polya_product_summary"]:
                failures.append(f"{rid}: polya product summary mismatch")
            if summary["negative_count"] != 0:
                failures.append(f"{rid}: polya product has negative coefficients")
        elif status == "unresolved":
            counts["unresolved_count"] += 1
            if rid not in unresolved_by_id:
                failures.append(f"{rid}: missing unresolved record")
        else:
            failures.append(f"{rid}: unknown status {status}")

    expected = manifest["pilot_counts"]
    for key, value in counts.items():
        if expected[key] != value:
            failures.append(f"count mismatch for {key}")

    result = {
        "complete_certificate": False,
        "failures": failures,
        "n": n,
        "range": {"count": count, "end_exclusive": start + count, "start": start},
        "status": "PASS" if not failures else "FAIL",
        "summaries": {**counts, "batch_root_count": count},
        "tool": TOOL_VERSION,
    }
    write_json(target_dir / "checker_result.json", result)

    log = [
        "# Vasc Polya Batch Checker Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        f"- Status: `{result['status']}`.",
        "- Complete proof certificate: NO.",
        f"- Target: `n={n}`.",
        f"- Range: `[{start}, {start + count})`.",
        f"- Coefficient leaves: `{counts['coefficient_leaf_count']}`.",
        f"- Polya multiplier leaves: `{counts['polya_leaf_count']}`.",
        f"- Unresolved roots: `{counts['unresolved_count']}`.",
        "",
    ]
    if failures:
        log.append("## Failures")
        log.extend(f"- {failure}" for failure in failures)
    else:
        log.append("All batch root pullbacks and Polya multiplier leaf certificates were recomputed exactly.")
    (WORKSPACE / "logs" / f"polya_batch_n{n}_{start:07d}_{start + count:07d}_check.md").write_text(
        "\n".join(log) + "\n",
        encoding="utf-8",
    )


def merged_measure(intervals: list[tuple[int, int]]) -> tuple[int, list[list[int]], list[list[int]]]:
    if not intervals:
        return 0, [], []
    ordered = sorted(intervals)
    merged: list[list[int]] = []
    overlaps: list[list[int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            if start < merged[-1][1]:
                overlaps.append([start, min(end, merged[-1][1])])
            if end > merged[-1][1]:
                merged[-1][1] = end
    return sum(end - start for start, end in merged), merged, overlaps


def summarize(args: argparse.Namespace) -> None:
    n = args.n
    target_root = CERT_ROOT / f"n{n}"
    full_root_count = math.factorial(n - 1)
    intervals: list[tuple[int, int]] = []
    batches: list[dict[str, object]] = []
    totals = {
        "batch_root_count": 0,
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
    }
    polya_power_histogram: dict[str, int] = {}
    status_counts: dict[str, int] = {}

    for path in sorted(target_root.glob("batch_*")):
        manifest_path = path / "manifest.json"
        checker_path = path / "checker_result.json"
        if not manifest_path.exists():
            continue
        manifest = read_json(manifest_path)
        if checker_path.exists():
            checker = read_json(checker_path)
            status = checker["status"]
            summary = checker["summaries"]
        else:
            status = "NO_CHECKER"
            summary = manifest["pilot_counts"]
        status_counts[status] = status_counts.get(status, 0) + 1
        coverage = manifest["coverage"]
        start = coverage["start"]
        end = coverage["end_exclusive"]
        if status == "PASS":
            intervals.append((start, end))
        if status == "PASS":
            for key in totals:
                totals[key] += int(summary.get(key, 0))
        leaves_path = path / "leaves.jsonl"
        if status == "PASS" and leaves_path.exists():
            for leaf in read_jsonl(leaves_path):
                if leaf.get("certificate_type") == "polya_sum_multiplier":
                    key = str(leaf["polya_power"])
                    polya_power_histogram[key] = polya_power_histogram.get(key, 0) + 1
        batches.append({
            "batch_dir": path.name,
            "checker_status": status,
            "count": end - start,
            "end_exclusive": end,
            "start": start,
            "summary": summary,
        })

    covered_measure, merged, overlaps = merged_measure(intervals)
    coverage_index = {
        "complete_certificate": False,
        "coverage": {
            "covered_root_count_union": covered_measure,
            "coverage_fraction": f"{covered_measure}/{full_root_count}",
            "full_root_count": full_root_count,
            "merged_intervals": merged,
            "missing_root_count_by_union": full_root_count - covered_measure,
            "n": n,
            "next_uncovered_start_after_prefix": merged[0][1] if merged and merged[0][0] == 0 else 0,
            "overlaps": overlaps,
        },
        "polya_power_histogram": polya_power_histogram,
        "reason": "coverage index only; proof use still requires complete zero-unresolved coverage and Computation Auditor acceptance",
        "status_counts": status_counts,
        "totals_by_batch_rows": totals,
        "batches": batches,
        "tool": TOOL_VERSION,
    }
    write_json(target_root / "coverage_index.json", coverage_index)

    log = [
        "# Vasc Polya Batch Coverage Index",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        "- Complete proof certificate: NO.",
        f"- Target: `n={n}`.",
        f"- Batches indexed: `{len(batches)}`.",
        f"- Union covered roots: `{covered_measure}/{full_root_count}`.",
        f"- Checker status counts: `{canonical_json(status_counts)}`.",
        f"- Coefficient leaves across batch rows: `{totals['coefficient_leaf_count']}`.",
        f"- Polya multiplier leaves across batch rows: `{totals['polya_leaf_count']}`.",
        f"- Polya power histogram: `{canonical_json(polya_power_histogram)}`.",
        f"- Unresolved roots across batch rows: `{totals['unresolved_count']}`.",
        "",
    ]
    (WORKSPACE / "logs" / f"polya_batch_n{n}_coverage_index.md").write_text(
        "\n".join(log),
        encoding="utf-8",
    )


def command_args(args: argparse.Namespace, start: int, count: int, max_k: int) -> argparse.Namespace:
    return argparse.Namespace(
        count=count,
        include_root_universe_hash=args.include_root_universe_hash,
        max_polya_power=max_k,
        n=args.n,
        start=start,
    )


def current_prefix_start(n: int) -> int:
    coverage_path = CERT_ROOT / f"n{n}" / "coverage_index.json"
    if not coverage_path.exists():
        return 0
    coverage_index = read_json(coverage_path)
    return int(coverage_index["coverage"].get("next_uncovered_start_after_prefix", 0))


def extend_prefix(args: argparse.Namespace) -> None:
    start = args.start if args.start is not None else current_prefix_start(args.n)
    full_root_count = math.factorial(args.n - 1)
    if start < 0 or start >= full_root_count:
        raise ValueError(f"invalid start {start} for n={args.n}")

    run_rows: list[dict[str, object]] = []
    for batch_no in range(args.batches):
        batch_start = start + batch_no * args.count
        if batch_start >= full_root_count:
            break
        batch_count = min(args.count, full_root_count - batch_start)
        used_max_k = args.max_polya_power

        batch_args = command_args(args, batch_start, batch_count, used_max_k)
        produce(batch_args)
        check(batch_args)
        checker = read_json(batch_dir(args.n, batch_start, batch_count) / "checker_result.json")
        if checker["status"] != "PASS":
            run_rows.append({
                "batch_count": batch_count,
                "end_exclusive": batch_start + batch_count,
                "max_polya_power": used_max_k,
                "start": batch_start,
                "status": checker["status"],
                "summary": checker.get("summaries"),
            })
            break

        unresolved = int(checker["summaries"]["unresolved_count"])
        if unresolved and args.escalate_max_polya_power is not None and args.escalate_max_polya_power > used_max_k:
            used_max_k = args.escalate_max_polya_power
            batch_args = command_args(args, batch_start, batch_count, used_max_k)
            produce(batch_args)
            check(batch_args)
            checker = read_json(batch_dir(args.n, batch_start, batch_count) / "checker_result.json")

        run_rows.append({
            "batch_count": batch_count,
            "end_exclusive": batch_start + batch_count,
            "max_polya_power": used_max_k,
            "start": batch_start,
            "status": checker["status"],
            "summary": checker.get("summaries"),
        })
        if checker["status"] != "PASS" or int(checker["summaries"]["unresolved_count"]):
            break

    summarize(argparse.Namespace(n=args.n))
    final_index = read_json(CERT_ROOT / f"n{args.n}" / "coverage_index.json")
    log = [
        "# Vasc Polya Batch Prefix Extension Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        "- Complete proof certificate: NO.",
        f"- Target: `n={args.n}`.",
        f"- Requested batches: `{args.batches}`.",
        f"- Batch size: `{args.count}`.",
        f"- Initial start: `{start}`.",
        f"- Final prefix start: `{final_index['coverage']['next_uncovered_start_after_prefix']}`.",
        f"- Coverage fraction: `{final_index['coverage']['coverage_fraction']}`.",
        "",
        "## Batches",
    ]
    for row in run_rows:
        log.append(
            "- "
            f"[{row['start']},{row['end_exclusive']}): "
            f"status `{row['status']}`, max k `{row['max_polya_power']}`, "
            f"summary `{canonical_json(row['summary'])}`."
        )
    (WORKSPACE / "logs" / f"polya_batch_n{args.n}_extend_{start:07d}.md").write_text(
        "\n".join(log) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("produce", "check"):
        command = sub.add_parser(name)
        command.add_argument("--n", type=int, required=True, choices=(9, 11))
        command.add_argument("--start", type=int, required=True)
        command.add_argument("--count", type=int, required=True)
        command.add_argument("--max-polya-power", type=int, required=True)
        command.add_argument(
            "--include-root-universe-hash",
            action="store_true",
            help="also recompute the full root-universe stream hash for this n",
        )
    summary_parser = sub.add_parser("summarize")
    summary_parser.add_argument("--n", type=int, required=True, choices=(9, 11))
    extend_parser = sub.add_parser("extend-prefix")
    extend_parser.add_argument("--n", type=int, required=True, choices=(9, 11))
    extend_parser.add_argument("--start", type=int, default=None)
    extend_parser.add_argument("--batches", type=int, required=True)
    extend_parser.add_argument("--count", type=int, required=True)
    extend_parser.add_argument("--max-polya-power", type=int, required=True)
    extend_parser.add_argument("--escalate-max-polya-power", type=int, default=None)
    extend_parser.add_argument(
        "--include-root-universe-hash",
        action="store_true",
        help="also recompute the full root-universe stream hash for this n",
    )
    args = parser.parse_args()
    if args.cmd == "produce":
        produce(args)
    elif args.cmd == "check":
        check(args)
    elif args.cmd == "summarize":
        summarize(args)
    elif args.cmd == "extend-prefix":
        extend_prefix(args)


if __name__ == "__main__":
    main()
