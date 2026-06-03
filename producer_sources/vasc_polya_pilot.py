#!/usr/bin/env python3
"""Exact Polya-style pilot certificate producer/checker for Vasc n=9,11.

This is deliberately a pilot, not a proof certificate.  It computes exact
root-cone pullbacks for selected root cones and certifies each selected leaf
either coefficientwise or by checking that (sum y_i)^k times the pullback has
nonnegative integer coefficients.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
import random
import time
from pathlib import Path


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
CERT_ROOT = WORKSPACE / "certificates" / "polya_pilot_v2"
TOOL_VERSION = "vasc_polya_pilot_v2"
BASE_TOOL = WORKSPACE / "tools" / "vasc_certificate_producer.py"


def load_base():
    spec = importlib.util.spec_from_file_location("vasc_certificate_producer", BASE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BASE_TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base()


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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def poly_stream_hash(poly, n: int, label: str) -> str:
    """Hash a polynomial without materializing a JSON term list."""
    h = hashlib.sha256()
    h.update(canonical_json({
        "hash_schema": "stream_terms_v1",
        "label": label,
        "n": n,
        "term_count": len(poly),
    }).encode("utf-8"))
    h.update(b"\n")
    for exp, coeff in sorted(poly.items()):
        h.update(canonical_json({"coeff": coeff, "exp": list(exp)}).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def poly_sum_power_certificate(poly, n: int, max_k: int):
    terms = [(1, i) for i in range(n)]
    current = poly
    for k in range(max_k + 1):
        summary = base.coeff_summary(current)
        if summary["negative_count"] == 0:
            return k, current, summary
        if k != max_k:
            current = base.mul_linear(current, terms)
    return None, current, base.coeff_summary(current)


def selected_permutations(n: int, sequential: int, random_count: int, seed: int) -> list[tuple[int, ...]]:
    selected: list[tuple[int, ...]] = []
    seen: set[tuple[int, ...]] = set()

    def add(perm: tuple[int, ...]) -> None:
        if perm not in seen:
            seen.add(perm)
            selected.append(perm)

    for _, perm in zip(range(sequential), itertools.permutations(range(1, n))):
        add(tuple(perm))

    for perm in base.pilot_permutations(n):
        add(tuple(perm))

    rng = random.Random(seed + n)
    for _ in range(random_count):
        arr = list(range(1, n))
        rng.shuffle(arr)
        add(tuple(arr))
    return selected


def produce_target(n: int, sequential: int, random_count: int, max_k: int, seed: int) -> dict[str, object]:
    target_dir = CERT_ROOT / f"n{n}"
    target_dir.mkdir(parents=True, exist_ok=True)
    p_poly = base.vasc_polynomial(n)
    root_count, root_hash = base.root_universe_hash(n)
    perms = selected_permutations(n, sequential, random_count, seed)

    roots_rows: list[object] = []
    tree_rows: list[object] = []
    leaves_rows: list[object] = []
    unresolved_rows: list[object] = []
    counts = {
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": 0,
    }
    started = time.time()

    for idx, perm in enumerate(perms):
        root_id = f"pilot_{idx}"
        root_record, pullback = base.root_record(n, root_id, perm, p_poly)
        pullback_hash = root_record["pullback_hash"]
        pullback_summary = root_record["coefficient_summary"]
        polya_k, polya_product, polya_summary = poly_sum_power_certificate(pullback, n, max_k)

        if pullback_summary["negative_count"] == 0:
            status = "coefficient_leaf"
            counts["coefficient_leaf_count"] += 1
            leaf = {
                "certificate_type": "coefficientwise_nonnegative",
                "leaf_id": root_id,
                "pullback_hash": pullback_hash,
                "pullback_summary": pullback_summary,
                "reconstruction_rule": "direct_root_pullback_from_P_n_and_perm",
                "root_id": root_id,
            }
            leaves_rows.append(leaf)
        elif polya_k is not None:
            status = "polya_multiplier_leaf"
            counts["polya_leaf_count"] += 1
            leaf = {
                "certificate_type": "polya_sum_multiplier",
                "leaf_id": root_id,
                "multiplier": "(y1+...+yn)^k",
                "polya_power": polya_k,
                "polya_product_hash": poly_stream_hash(
                    polya_product,
                    n=n,
                    label=f"polya_product_{root_id}_k{polya_k}",
                ),
                "polya_product_hash_schema": "stream_terms_v1",
                "polya_product_summary": polya_summary,
                "pullback_hash": pullback_hash,
                "pullback_summary": pullback_summary,
                "reconstruction_rule": "direct_root_pullback_from_P_n_and_perm_then_exact_sum_power",
                "root_id": root_id,
            }
            leaves_rows.append(leaf)
        else:
            status = "unresolved"
            counts["unresolved_count"] += 1
            unresolved_rows.append({
                "root_id": root_id,
                "perm": list(perm),
                "pullback_hash": pullback_hash,
                "pullback_summary": pullback_summary,
                "last_polya_summary": polya_summary,
                "max_polya_power_tried": max_k,
            })

        roots_rows.append({"n": n, "perm": list(perm), "root_id": root_id})
        tree_rows.append({
            "certificate_status": status,
            "depth": 0,
            "node_id": root_id,
            "parent_id": None,
            "perm": list(perm),
            "pullback_hash": pullback_hash,
            "pullback_summary": pullback_summary,
            "root_id": root_id,
        })

    write_jsonl(target_dir / "roots.jsonl", roots_rows)
    write_jsonl(target_dir / "tree.jsonl", tree_rows)
    write_jsonl(target_dir / "leaves.jsonl", leaves_rows)
    write_jsonl(target_dir / "unresolved.jsonl", unresolved_rows)

    manifest = {
        "complete_certificate": False,
        "coverage": {
            "covered_root_count": len(perms),
            "coverage_type": "selected_pilot_only",
            "full_root_count": root_count,
            "missing_root_count": root_count - len(perms),
            "selection": {
                "lexicographic_prefix": sequential,
                "random_count": random_count,
                "seed": seed,
                "stress_roots": "included from vasc_certificate_producer.pilot_permutations",
            },
        },
        "leaf_rule": {
            "coefficient_leaf": "pullback has nonnegative integer coefficients",
            "polya_multiplier_leaf": "(sum y_i)^k times pullback has nonnegative integer coefficients; sum y_i is positive off the origin",
            "max_polya_power": max_k,
        },
        "n": n,
        "pilot_counts": {
            **counts,
            "selected_root_count": len(perms),
        },
        "root_universe": {
            "fixed_maximum_variable": "x1",
            "root_count": root_count,
            "root_stream_hash": root_hash,
            "type": "cyclic_maximum_then_all_orderings_stream",
        },
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
            f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_polya_pilot.py'} produce",
            f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_polya_pilot.py'} check",
        ],
        "runtime_seconds": round(time.time() - started, 3),
        "tool": TOOL_VERSION,
    }
    write_json(target_dir / "audit_index.json", audit_index)
    return {
        "n": n,
        "runtime_seconds": audit_index["runtime_seconds"],
        **manifest["pilot_counts"],
        "missing_root_count": manifest["coverage"]["missing_root_count"],
    }


def produce(args: argparse.Namespace) -> None:
    CERT_ROOT.mkdir(parents=True, exist_ok=True)
    n9_max_k = args.max_polya_power if args.max_polya_power is not None else args.n9_max_polya_power
    n11_max_k = args.max_polya_power if args.max_polya_power is not None else args.n11_max_polya_power
    summaries = [
        produce_target(9, args.n9_sequential, args.n9_random, n9_max_k, args.seed),
        produce_target(11, args.n11_sequential, args.n11_random, n11_max_k, args.seed),
    ]
    log = [
        "# Vasc Polya Pilot Producer Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        "- Arithmetic: exact integer polynomial arithmetic.",
        "- Scope: selected root-cone pullbacks and Polya multiplier leaves.",
        "- Complete proof certificate: NO.",
        "",
    ]
    for summary in summaries:
        log.extend([
            f"## n={summary['n']}",
            f"- Selected roots: `{summary['selected_root_count']}`.",
            f"- Coefficient leaves: `{summary['coefficient_leaf_count']}`.",
            f"- Polya multiplier leaves: `{summary['polya_leaf_count']}`.",
            f"- Unresolved selected roots: `{summary['unresolved_count']}`.",
            f"- Missing roots outside pilot: `{summary['missing_root_count']}`.",
            f"- Runtime seconds: `{summary['runtime_seconds']}`.",
            "",
        ])
    (WORKSPACE / "logs" / "polya_pilot_generation_v2.md").write_text("\n".join(log), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def check_target(n: int, failures: list[str]) -> dict[str, object]:
    target_dir = CERT_ROOT / f"n{n}"
    manifest = read_json(target_dir / "manifest.json")
    audit_index = read_json(target_dir / "audit_index.json")
    for name, rel in [
        ("roots_jsonl_sha256", "roots.jsonl"),
        ("tree_jsonl_sha256", "tree.jsonl"),
        ("leaves_jsonl_sha256", "leaves.jsonl"),
        ("unresolved_jsonl_sha256", "unresolved.jsonl"),
    ]:
        if sha256_file(target_dir / rel) != audit_index["files"][name]:
            failures.append(f"n={n}: {rel} hash mismatch")
    if hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest() != audit_index["files"]["manifest_sha256"]:
        failures.append(f"n={n}: manifest hash mismatch")

    p_poly = base.vasc_polynomial(n)
    if base.poly_hash(p_poly, n=n, label="P_n") != manifest["target_polynomial_hash"]:
        failures.append(f"n={n}: target polynomial hash mismatch")
    root_count, root_hash = base.root_universe_hash(n)
    if manifest["root_universe"]["root_count"] != root_count:
        failures.append(f"n={n}: root count mismatch")
    if manifest["root_universe"]["root_stream_hash"] != root_hash:
        failures.append(f"n={n}: root hash mismatch")

    roots = {row["root_id"]: tuple(row["perm"]) for row in read_jsonl(target_dir / "roots.jsonl")}
    leaves = {row["leaf_id"]: row for row in read_jsonl(target_dir / "leaves.jsonl")}
    unresolved = read_jsonl(target_dir / "unresolved.jsonl")
    counts = {
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "unresolved_count": len(unresolved),
    }
    for row in read_jsonl(target_dir / "tree.jsonl"):
        rid = row["root_id"]
        if rid not in roots:
            failures.append(f"n={n} {rid}: missing root record")
            continue
        rec, pullback = base.root_record(n, rid, roots[rid], p_poly)
        if rec["pullback_hash"] != row["pullback_hash"]:
            failures.append(f"n={n} {rid}: pullback hash mismatch")
        if rec["coefficient_summary"] != row["pullback_summary"]:
            failures.append(f"n={n} {rid}: pullback summary mismatch")
        if row["certificate_status"] == "coefficient_leaf":
            counts["coefficient_leaf_count"] += 1
            leaf = leaves.get(rid)
            if leaf is None:
                failures.append(f"n={n} {rid}: missing coefficient leaf")
            elif rec["coefficient_summary"]["negative_count"] != 0:
                failures.append(f"n={n} {rid}: coefficient leaf has negative coefficients")
        elif row["certificate_status"] == "polya_multiplier_leaf":
            counts["polya_leaf_count"] += 1
            leaf = leaves.get(rid)
            if leaf is None:
                failures.append(f"n={n} {rid}: missing polya leaf")
                continue
            k = leaf["polya_power"]
            current = pullback
            for _ in range(k):
                current = base.mul_linear(current, [(1, i) for i in range(n)])
            summary = base.coeff_summary(current)
            product_hash = poly_stream_hash(current, n=n, label=f"polya_product_{rid}_k{k}")
            if leaf.get("polya_product_hash_schema") != "stream_terms_v1":
                failures.append(f"n={n} {rid}: unsupported polya product hash schema")
            if product_hash != leaf["polya_product_hash"]:
                failures.append(f"n={n} {rid}: polya product hash mismatch")
            if summary != leaf["polya_product_summary"]:
                failures.append(f"n={n} {rid}: polya product summary mismatch")
            if summary["negative_count"] != 0:
                failures.append(f"n={n} {rid}: polya product has negative coefficients")
        elif row["certificate_status"] != "unresolved":
            failures.append(f"n={n} {rid}: unknown status {row['certificate_status']}")

    expected = manifest["pilot_counts"]
    for key, value in counts.items():
        if expected[key] != value:
            failures.append(f"n={n}: count mismatch for {key}")
    return {"n": n, **counts, "selected_root_count": expected["selected_root_count"]}


def check(args: argparse.Namespace) -> None:
    failures: list[str] = []
    summaries = [check_target(9, failures), check_target(11, failures)]
    result = {
        "complete_certificate": False,
        "failures": failures,
        "status": "PASS" if not failures else "FAIL",
        "summaries": summaries,
        "tool": TOOL_VERSION,
    }
    write_json(CERT_ROOT / "checker_result.json", result)
    log = [
        "# Vasc Polya Pilot Checker Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        f"- Status: `{result['status']}`",
        "- Complete proof certificate: NO.",
        "",
    ]
    if failures:
        log.append("## Failures")
        log.extend(f"- {failure}" for failure in failures)
    else:
        log.append("All selected root pullbacks and Polya multiplier leaf certificates were recomputed exactly.")
    (WORKSPACE / "logs" / "polya_pilot_checker_v2.md").write_text("\n".join(log) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    produce_parser = sub.add_parser("produce")
    produce_parser.add_argument("--n9-sequential", type=int, default=8)
    produce_parser.add_argument("--n9-random", type=int, default=2)
    produce_parser.add_argument("--n11-sequential", type=int, default=3)
    produce_parser.add_argument("--n11-random", type=int, default=0)
    produce_parser.add_argument("--max-polya-power", type=int, default=None)
    produce_parser.add_argument("--n9-max-polya-power", type=int, default=6)
    produce_parser.add_argument("--n11-max-polya-power", type=int, default=8)
    produce_parser.add_argument("--seed", type=int, default=20260525)
    sub.add_parser("check")
    args = parser.parse_args()
    if args.cmd == "produce":
        produce(args)
    elif args.cmd == "check":
        check(args)


if __name__ == "__main__":
    main()
