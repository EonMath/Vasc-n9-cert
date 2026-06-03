#!/usr/bin/env python3
"""Frozen hard-root packet producer/checker for unresolved Vasc Polya roots.

This tool is a local certificate producer for named hard roots only.  It does
not produce a full proof certificate.  The current extra leaf rule is a
two-term AM-GM midpoint circuit applied after a fixed Polya multiplier.
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
BATCH_TOOL = WORKSPACE / "tools" / "vasc_polya_batch.py"
CERT_ROOT = WORKSPACE / "certificates" / "polya_packets"
TOOL_VERSION = "vasc_hardroot_packet_v1"


def load_batch():
    spec = importlib.util.spec_from_file_location("vasc_polya_batch", BATCH_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BATCH_TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


batch = load_batch()
pilot = batch.pilot
base = batch.base


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


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[object]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packet_dir(n: int, packet_id: str) -> Path:
    return CERT_ROOT / f"n{n}" / packet_id


def parse_root_index(root_id: str) -> int:
    prefix = "root_"
    if not root_id.startswith(prefix):
        raise ValueError(f"unsupported root_id {root_id!r}")
    return int(root_id[len(prefix):])


def polya_product_for_root(n: int, root_id: str, perm: tuple[int, ...], power: int):
    p_poly = base.vasc_polynomial(n)
    root_record, pullback = base.root_record(n, root_id, perm, p_poly)
    current = pullback
    for _ in range(power):
        current = base.mul_linear(current, [(1, i) for i in range(n)])
    return root_record, current


def exp_add(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(x + y for x, y in zip(a, b))


def exp_double(a: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(2 * x for x in a)


def exp_shift(beta: tuple[int, ...], i: int, j: int, step: int) -> tuple[int, ...] | None:
    out = list(beta)
    out[i] += step
    out[j] -= step
    if out[j] < 0:
        return None
    return tuple(out)


def direction_candidates(beta: tuple[int, ...], max_step: int):
    n = len(beta)
    for step in range(1, max_step + 1):
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                alpha = exp_shift(beta, i, j, step)
                gamma = exp_shift(beta, j, i, step)
                if alpha is None or gamma is None:
                    continue
                yield step, i, j, alpha, gamma


def find_midpoint_circuits(poly: dict[tuple[int, ...], int], max_step: int) -> tuple[list[dict[str, object]], dict[tuple[int, ...], int]]:
    """Greedy exact two-term AM-GM cover for negative coefficients.

    A row with amount m proves
        m*y^alpha + m*y^gamma - 2m*y^beta >= 0
    on the nonnegative orthant whenever alpha+gamma=2 beta.  Subtracting all
    such nonnegative circuits from the product must leave a coefficientwise
    nonnegative residual.
    """
    residual = dict(poly)
    rows: list[dict[str, object]] = []
    negative_terms = sorted((exp, coeff) for exp, coeff in residual.items() if coeff < 0)
    for beta, coeff in negative_terms:
        needed = -residual.get(beta, 0)
        if needed <= 0:
            continue
        amount = (needed + 1) // 2
        chosen = None
        for step, i, j, alpha, gamma in direction_candidates(beta, max_step):
            if residual.get(alpha, 0) >= amount and residual.get(gamma, 0) >= amount:
                chosen = step, i, j, alpha, gamma
                break
        if chosen is None:
            break
        step, i, j, alpha, gamma = chosen
        residual[alpha] = residual.get(alpha, 0) - amount
        residual[gamma] = residual.get(gamma, 0) - amount
        residual[beta] = residual.get(beta, 0) + 2 * amount
        rows.append({
            "amount_each_positive_term": amount,
            "certified_negative_abs_coeff": needed,
            "dominance_coeff": 2 * amount,
            "direction": {"from_var": j + 1, "step": step, "to_var": i + 1},
            "midpoint_exp": list(beta),
            "negative_coeff_before": -needed,
            "positive_exp_a": list(alpha),
            "positive_exp_b": list(gamma),
            "rule": "m*y^alpha + m*y^gamma >= 2*m*y^beta when alpha+gamma=2*beta",
        })
    return rows, {exp: coeff for exp, coeff in residual.items() if coeff}


def load_unresolved_rows(n: int, source_batch: str | None, root_ids: set[str] | None) -> list[dict[str, object]]:
    if source_batch is None:
        raise ValueError("--source-batch is required in this version")
    path = WORKSPACE / "certificates" / "polya_batches" / f"n{n}" / source_batch / "unresolved.jsonl"
    rows = read_jsonl(path)
    if root_ids is not None:
        rows = [row for row in rows if row["root_id"] in root_ids]
    if not rows:
        raise ValueError("no unresolved rows selected")
    return rows


def make_packet(args: argparse.Namespace) -> dict[str, object]:
    n = args.n
    packet_id = args.packet_id
    out_dir = packet_dir(n, packet_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()

    root_ids = set(args.root_id or []) or None
    unresolved_rows = load_unresolved_rows(n, args.source_batch, root_ids)
    p_poly = base.vasc_polynomial(n)
    root_count, root_hash = base.root_universe_hash(n)

    roots_rows: list[object] = []
    product_rows: list[object] = []
    leaf_rows: list[object] = []
    unresolved_out: list[object] = []
    counts = {
        "amgm_midpoint_leaf_count": 0,
        "unresolved_count": 0,
    }

    for source in unresolved_rows:
        root_id = str(source["root_id"])
        perm = tuple(int(x) for x in source["perm"])
        root_index = parse_root_index(root_id)
        expected_perm = batch.lexicographic_perm_at(n, root_index)
        root_record, product = polya_product_for_root(n, root_id, perm, args.polya_power)
        product_summary = base.coeff_summary(product)
        product_hash = pilot.poly_stream_hash(product, n=n, label=f"hardroot_polya_product_{root_id}_k{args.polya_power}")
        negative_terms = [
            {"coeff": coeff, "exp": list(exp)}
            for exp, coeff in sorted(product.items())
            if coeff < 0
        ]
        circuits, residual = find_midpoint_circuits(product, args.max_direction_step)
        residual_summary = base.coeff_summary(residual)

        roots_rows.append({
            "expected_lexicographic_perm": list(expected_perm),
            "lexicographic_perm_match": tuple(perm) == expected_perm,
            "n": n,
            "perm": list(perm),
            "root_id": root_id,
            "root_index": root_index,
            "source_batch": args.source_batch,
            "source_pullback_hash": source["pullback_hash"],
        })
        product_rows.append({
            "negative_terms": negative_terms,
            "polya_power": args.polya_power,
            "polya_product_hash": product_hash,
            "polya_product_hash_schema": "stream_terms_v1",
            "polya_product_summary": product_summary,
            "pullback_hash": root_record["pullback_hash"],
            "pullback_summary": root_record["coefficient_summary"],
            "root_id": root_id,
        })

        if circuits and residual_summary["negative_count"] == 0:
            counts["amgm_midpoint_leaf_count"] += 1
            leaf_rows.append({
                "certificate_type": "amgm_midpoint_circuit_polya_leaf",
                "circuits": circuits,
                "domain": "nonnegative gap variables; positive root cone is in the interior",
                "leaf_id": root_id,
                "multiplier": f"(y1+...+y{n})^{args.polya_power}",
                "polya_power": args.polya_power,
                "polya_product_hash": product_hash,
                "polya_product_hash_schema": "stream_terms_v1",
                "polya_product_summary": product_summary,
                "pullback_hash": root_record["pullback_hash"],
                "residual_summary_after_subtracting_circuits": residual_summary,
                "root_id": root_id,
                "soundness_rule": "product = residual + sum midpoint AM-GM circuits; residual has nonnegative coefficients and each circuit is nonnegative on y_i>=0",
            })
        else:
            counts["unresolved_count"] += 1
            unresolved_out.append({
                "circuits_found": circuits,
                "last_residual_summary": residual_summary,
                "negative_terms": negative_terms,
                "polya_power": args.polya_power,
                "polya_product_hash": product_hash,
                "polya_product_summary": product_summary,
                "root_id": root_id,
                "status": "unresolved_by_amgm_midpoint_search",
            })

    write_jsonl(out_dir / "roots.jsonl", roots_rows)
    write_jsonl(out_dir / "polya_products.jsonl", product_rows)
    write_jsonl(out_dir / "leaves.jsonl", leaf_rows)
    write_jsonl(out_dir / "unresolved.jsonl", unresolved_out)

    manifest = {
        "complete_certificate": False,
        "coverage": {
            "coverage_type": "named_hard_root_packet",
            "full_root_count": math.factorial(n - 1),
            "n": n,
            "root_count": len(roots_rows),
            "root_ids": [row["root_id"] for row in roots_rows],
            "source_batch": args.source_batch,
        },
        "full_problem_certificate": False,
        "leaf_rule": {
            "amgm_midpoint_circuit_polya_leaf": "After the stated Polya multiplier, subtract exact two-term midpoint AM-GM circuits and verify the residual is coefficientwise nonnegative.",
            "polya_power": args.polya_power,
        },
        "n": n,
        "packet_counts": {
            **counts,
            "root_count": len(roots_rows),
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
    write_json(out_dir / "manifest.json", manifest)

    audit_index = {
        "complete_certificate": False,
        "files": {
            "leaves_jsonl_sha256": sha256_file(out_dir / "leaves.jsonl"),
            "manifest_sha256": hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
            "polya_products_jsonl_sha256": sha256_file(out_dir / "polya_products.jsonl"),
            "roots_jsonl_sha256": sha256_file(out_dir / "roots.jsonl"),
            "unresolved_jsonl_sha256": sha256_file(out_dir / "unresolved.jsonl"),
        },
        "n": n,
        "packet_counts": manifest["packet_counts"],
        "reproduction_commands": [
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_hardroot_packet.py'} "
                f"produce --n {n} --packet-id {packet_id} --source-batch {args.source_batch} "
                f"--polya-power {args.polya_power} --max-direction-step {args.max_direction_step}"
                + "".join(f" --root-id {rid}" for rid in (args.root_id or []))
            ),
            (
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_hardroot_packet.py'} "
                f"check --n {n} --packet-id {packet_id}"
            ),
        ],
        "runtime_seconds": round(time.time() - started, 3),
        "tool": TOOL_VERSION,
    }
    write_json(out_dir / "audit_index.json", audit_index)
    return {
        "out_dir": str(out_dir),
        "status": "PASS" if counts["unresolved_count"] == 0 else "NEEDS_MORE_EVIDENCE",
        **manifest["packet_counts"],
    }


def check_packet(args: argparse.Namespace) -> dict[str, object]:
    n = args.n
    out_dir = packet_dir(n, args.packet_id)
    failures: list[str] = []
    manifest = read_json(out_dir / "manifest.json")
    audit_index = read_json(out_dir / "audit_index.json")
    for key, rel in [
        ("roots_jsonl_sha256", "roots.jsonl"),
        ("polya_products_jsonl_sha256", "polya_products.jsonl"),
        ("leaves_jsonl_sha256", "leaves.jsonl"),
        ("unresolved_jsonl_sha256", "unresolved.jsonl"),
    ]:
        if sha256_file(out_dir / rel) != audit_index["files"][key]:
            failures.append(f"{rel} hash mismatch")
    if hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest() != audit_index["files"]["manifest_sha256"]:
        failures.append("manifest hash mismatch")

    p_poly = base.vasc_polynomial(n)
    if base.poly_hash(p_poly, n=n, label="P_n") != manifest["target_polynomial_hash"]:
        failures.append("target polynomial hash mismatch")
    root_count, root_hash = base.root_universe_hash(n)
    if manifest["root_universe"]["root_count"] != root_count or manifest["root_universe"]["root_stream_hash"] != root_hash:
        failures.append("root universe hash mismatch")

    roots = {row["root_id"]: row for row in read_jsonl(out_dir / "roots.jsonl")}
    products = {row["root_id"]: row for row in read_jsonl(out_dir / "polya_products.jsonl")}
    leaves = {row["leaf_id"]: row for row in read_jsonl(out_dir / "leaves.jsonl")}
    unresolved = {row["root_id"]: row for row in read_jsonl(out_dir / "unresolved.jsonl")}
    counts = {
        "amgm_midpoint_leaf_count": 0,
        "unresolved_count": len(unresolved),
        "root_count": len(roots),
    }

    for root_id, root in roots.items():
        perm = tuple(int(x) for x in root["perm"])
        root_index = parse_root_index(root_id)
        if batch.lexicographic_perm_at(n, root_index) != perm:
            failures.append(f"{root_id}: lexicographic permutation mismatch")
        root_record, product = polya_product_for_root(n, root_id, perm, manifest["leaf_rule"]["polya_power"])
        product_summary = base.coeff_summary(product)
        product_hash = pilot.poly_stream_hash(product, n=n, label=f"hardroot_polya_product_{root_id}_k{manifest['leaf_rule']['polya_power']}")
        stored_product = products.get(root_id)
        if stored_product is None:
            failures.append(f"{root_id}: missing product row")
            continue
        if root_record["pullback_hash"] != stored_product["pullback_hash"]:
            failures.append(f"{root_id}: pullback hash mismatch")
        if product_hash != stored_product["polya_product_hash"]:
            failures.append(f"{root_id}: product hash mismatch")
        if product_summary != stored_product["polya_product_summary"]:
            failures.append(f"{root_id}: product summary mismatch")

        leaf = leaves.get(root_id)
        if leaf is None:
            continue
        counts["amgm_midpoint_leaf_count"] += 1
        residual = dict(product)
        for idx, circuit in enumerate(leaf["circuits"]):
            amount = int(circuit["amount_each_positive_term"])
            alpha = tuple(int(x) for x in circuit["positive_exp_a"])
            beta = tuple(int(x) for x in circuit["midpoint_exp"])
            gamma = tuple(int(x) for x in circuit["positive_exp_b"])
            if exp_add(alpha, gamma) != exp_double(beta):
                failures.append(f"{root_id}: circuit {idx} is not midpoint")
            if amount <= 0:
                failures.append(f"{root_id}: circuit {idx} has nonpositive amount")
            if residual.get(alpha, 0) < amount:
                failures.append(f"{root_id}: circuit {idx} overspends alpha")
            if residual.get(gamma, 0) < amount:
                failures.append(f"{root_id}: circuit {idx} overspends gamma")
            residual[alpha] = residual.get(alpha, 0) - amount
            residual[gamma] = residual.get(gamma, 0) - amount
            residual[beta] = residual.get(beta, 0) + 2 * amount
        residual = {exp: coeff for exp, coeff in residual.items() if coeff}
        residual_summary = base.coeff_summary(residual)
        if residual_summary != leaf["residual_summary_after_subtracting_circuits"]:
            failures.append(f"{root_id}: residual summary mismatch")
        if residual_summary["negative_count"] != 0:
            failures.append(f"{root_id}: residual still has negative coefficients")

    for key, value in counts.items():
        if manifest["packet_counts"].get(key) != value:
            failures.append(f"count mismatch for {key}")

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

    produce = sub.add_parser("produce")
    produce.add_argument("--n", type=int, required=True, choices=(9, 11))
    produce.add_argument("--packet-id", required=True)
    produce.add_argument("--source-batch", required=True)
    produce.add_argument("--root-id", action="append", default=[])
    produce.add_argument("--polya-power", type=int, default=14)
    produce.add_argument("--max-direction-step", type=int, default=3)

    check = sub.add_parser("check")
    check.add_argument("--n", type=int, required=True, choices=(9, 11))
    check.add_argument("--packet-id", required=True)

    args = parser.parse_args()
    if args.command == "produce":
        print(canonical_json(make_packet(args)))
    elif args.command == "check":
        print(canonical_json(check_packet(args)))
    else:
        raise AssertionError(args.command)


if __name__ == "__main__":
    main()
