#!/usr/bin/env python3
"""Exact artifact producer/checker for the Vasc n=9,11 certificate route.

This tool intentionally produces a *pilot* certificate bundle, not a proof.
All arithmetic is integer arithmetic.  The generated artifacts are meant to be
audited by InformalProver's Computation Auditor before any proof route can use
them.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
from collections import defaultdict
from pathlib import Path
from typing import Iterable


WORKSPACE = Path(os.environ.get("VASC_WORKSPACE", Path(__file__).resolve().parents[1])).resolve()
CERT_ROOT = WORKSPACE / "certificates"
TOOL_VERSION = "vasc_certificate_producer_v1"


Poly = dict[tuple[int, ...], int]


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_obj(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: Path, rows: Iterable[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")


def monomial(n: int, var: int, coeff: int = 1) -> Poly:
    exp = [0] * n
    exp[var] = 1
    return {tuple(exp): coeff}


def add_to(dst: Poly, src: Poly, scale: int = 1) -> None:
    for exp, coeff in src.items():
        new = dst.get(exp, 0) + scale * coeff
        if new:
            dst[exp] = new
        elif exp in dst:
            del dst[exp]


def mul(p: Poly, q: Poly) -> Poly:
    if not p or not q:
        return {}
    n = len(next(iter(p)))
    out: dict[tuple[int, ...], int] = defaultdict(int)
    for a, ca in p.items():
        for b, cb in q.items():
            out[tuple(a[i] + b[i] for i in range(n))] += ca * cb
    return {exp: coeff for exp, coeff in out.items() if coeff}


def mul_linear(p: Poly, terms: list[tuple[int, int]]) -> Poly:
    """Multiply by sum coeff*x_var in the same variable space."""
    if not p:
        return {}
    n = len(next(iter(p)))
    out: dict[tuple[int, ...], int] = defaultdict(int)
    for exp, coeff in p.items():
        for c, var in terms:
            e = list(exp)
            e[var] += 1
            out[tuple(e)] += coeff * c
    return {exp: coeff for exp, coeff in out.items() if coeff}


def linear_poly(n: int, terms: list[tuple[int, int]]) -> Poly:
    out: Poly = {}
    for coeff, var in terms:
        if coeff:
            add_to(out, monomial(n, var, coeff))
    return out


def diff_linear_terms(a: int, b: int) -> list[tuple[int, int]]:
    """Terms of L_a-L_b where L_p=sum_{k=p}^{n-1} y_k."""
    if a == b:
        return []
    if a < b:
        return [(1, k) for k in range(a, b)]
    return [(-1, k) for k in range(b, a)]


def sum_linear_terms(n: int, a: int, b: int) -> list[tuple[int, int]]:
    """Terms of L_a+L_b where L_p=sum_{k=p}^{n-1} y_k."""
    coeffs: dict[int, int] = defaultdict(int)
    for k in range(a, n):
        coeffs[k] += 1
    for k in range(b, n):
        coeffs[k] += 1
    return [(coeff, var) for var, coeff in sorted(coeffs.items()) if coeff]


def poly_pow_linear(n: int, terms: list[tuple[int, int]], power: int) -> Poly:
    p: Poly = {tuple([0] * n): 1}
    for _ in range(power):
        p = mul_linear(p, terms)
    return p


def poly_to_terms(poly: Poly) -> list[dict[str, object]]:
    return [
        {"exp": list(exp), "coeff": coeff}
        for exp, coeff in sorted(poly.items())
    ]


def poly_hash(poly: Poly, *, n: int, label: str) -> str:
    return sha256_obj({"label": label, "n": n, "terms": poly_to_terms(poly)})


def vasc_polynomial(n: int) -> Poly:
    """Return P_n = sum_i (x_i-x_{i+1}) prod_{j != i}(x_{j+1}+x_{j+2})."""
    total: Poly = {}
    for i in range(n):
        term: Poly = {}
        add_to(term, monomial(n, i, 1))
        add_to(term, monomial(n, (i + 1) % n, -1))
        for j in range(n):
            if j == i:
                continue
            term = mul_linear(term, [(1, (j + 1) % n), (1, (j + 2) % n)])
        add_to(total, term)
    return total


def denominator_polynomial(n: int) -> Poly:
    p: Poly = {tuple([0] * n): 1}
    for i in range(n):
        p = mul_linear(p, [(1, (i + 1) % n), (1, (i + 2) % n)])
    return p


def cyclic_permute_poly(poly: Poly, shift: int) -> Poly:
    n = len(next(iter(poly)))
    out: dict[tuple[int, ...], int] = defaultdict(int)
    for exp, coeff in poly.items():
        new = [0] * n
        for i, e in enumerate(exp):
            new[(i + shift) % n] = e
        out[tuple(new)] += coeff
    return {exp: coeff for exp, coeff in out.items() if coeff}


def root_substitution(n: int, perm: tuple[int, ...]) -> dict[int, list[int]]:
    """Map x variables to cumulative gap-variable supports.

    The cone is x_0 >= x_perm[0] >= ... >= x_perm[-1] >= 0.  With gap
    variables y_0,...,y_{n-1}, x_order[m] = y_m+...+y_{n-1}.
    """
    order = (0,) + tuple(perm)
    mapping: dict[int, list[int]] = {}
    for pos, xvar in enumerate(order):
        mapping[xvar] = list(range(pos, n))
    return mapping


def substitute(poly: Poly, mapping: dict[int, list[int]], n: int) -> Poly:
    powers: dict[tuple[int, int], Poly] = {}
    for xvar, support in mapping.items():
        terms = [(1, y) for y in support]
        for power in range(n + 1):
            powers[(xvar, power)] = poly_pow_linear(n, terms, power)

    total: Poly = {}
    zero_exp = tuple([0] * n)
    for exp, coeff in poly.items():
        piece: Poly = {zero_exp: coeff}
        for xvar, power in enumerate(exp):
            if power:
                piece = mul(piece, powers[(xvar, power)])
        add_to(total, piece)
    return total


def direct_root_pullback(n: int, perm: tuple[int, ...]) -> Poly:
    """Expand P_n after a root difference substitution without pre-expanding in x.

    On a root cone with order x_order[0] >= ... >= x_order[n-1] >= 0, write
    x_order[pos] = L_pos = y_pos + ... + y_{n-1}.  Expanding the defining
    product formula for P_n in these L_pos factors avoids the much slower path
    of expanding P_n in x first and then substituting each monomial.
    """
    order = (0,) + tuple(perm)
    pos_of_var = [0] * n
    for pos, xvar in enumerate(order):
        pos_of_var[xvar] = pos

    total: Poly = {}
    for i in range(n):
        term = linear_poly(n, diff_linear_terms(pos_of_var[i], pos_of_var[(i + 1) % n]))
        for j in range(n):
            if j == i:
                continue
            factor = sum_linear_terms(n, pos_of_var[(j + 1) % n], pos_of_var[(j + 2) % n])
            term = mul_linear(term, factor)
        add_to(total, term)
    return total


def coeff_summary(poly: Poly) -> dict[str, int]:
    term_count = 0
    negative_count = 0
    positive_count = 0
    min_coeff = None
    max_coeff = None
    for coeff in poly.values():
        term_count += 1
        if coeff < 0:
            negative_count += 1
        elif coeff > 0:
            positive_count += 1
        min_coeff = coeff if min_coeff is None else min(min_coeff, coeff)
        max_coeff = coeff if max_coeff is None else max(max_coeff, coeff)
    return {
        "term_count": term_count,
        "negative_count": negative_count,
        "zero_count": 0,
        "positive_count": positive_count,
        "min_coeff": min_coeff if min_coeff is not None else 0,
        "max_coeff": max_coeff if max_coeff is not None else 0,
    }


def root_universe_hash(n: int) -> tuple[int, str]:
    h = hashlib.sha256()
    count = 0
    for perm in itertools.permutations(range(1, n)):
        row = {"root_id": count, "perm": list(perm)}
        h.update(canonical_json(row).encode("utf-8"))
        h.update(b"\n")
        count += 1
    return count, h.hexdigest()


def pilot_permutations(n: int) -> list[tuple[int, ...]]:
    base = list(range(1, n))
    candidates: list[tuple[int, ...]] = [
        tuple(base),
        tuple(reversed(base)),
        tuple(base[::2] + base[1::2]),
        tuple(base[1::2] + base[::2]),
    ]
    # Stress roots from displayed tuples in blocked route artifacts: sort
    # variables 1..n-1 by decreasing value, keeping index order on ties.
    stress_values = {
        9: [20, 18, 16, 8, 6, 4, 2, 14, 1],
        11: [20, 18, 16, 8, 6, 4, 2, 12, 10, 14, 1],
    }
    vals = stress_values[n]
    sorted_rest = sorted(range(1, n), key=lambda i: (-vals[i], i))
    candidates.append(tuple(sorted_rest))
    seen = set()
    out = []
    for perm in candidates:
        if perm not in seen:
            seen.add(perm)
            out.append(perm)
    return out


def root_record(n: int, root_id: str, perm: tuple[int, ...], p_poly: Poly) -> tuple[dict, Poly]:
    mapping = root_substitution(n, perm)
    pulled = direct_root_pullback(n, perm)
    summary = coeff_summary(pulled)
    status = "coefficient_leaf" if summary["negative_count"] == 0 else "unresolved"
    record = {
        "n": n,
        "root_id": root_id,
        "perm": list(perm),
        "substitution": {
            f"x{i + 1}": [f"y{j + 1}" for j in mapping[i]]
            for i in range(n)
        },
        "status": status,
        "pullback_hash": poly_hash(pulled, n=n, label=f"pullback_{root_id}"),
        "coefficient_summary": summary,
    }
    return record, pulled


def produce(args: argparse.Namespace) -> None:
    CERT_ROOT.mkdir(parents=True, exist_ok=True)
    (CERT_ROOT / "vasc").mkdir(parents=True, exist_ok=True)

    specs = []
    polys: dict[int, Poly] = {}
    denoms: dict[int, Poly] = {}
    for n in (9, 11):
        p = vasc_polynomial(n)
        d = denominator_polynomial(n)
        polys[n] = p
        denoms[n] = d
        cyclic_ok = all(cyclic_permute_poly(p, s) == p for s in range(n))
        specs.append({
            "n": n,
            "variables": [f"x{i + 1}" for i in range(n)],
            "cyclic_indexing": "x_{n+i}=x_i",
            "C_n": "sum_i (x_i-x_{i+1})/(x_{i+1}+x_{i+2})",
            "D_n": "prod_i (x_{i+1}+x_{i+2})",
            "P_n": "sum_i (x_i-x_{i+1}) prod_{j != i}(x_{j+1}+x_{j+2})",
            "bridge": "D_n*C_n=P_n on positive variables; D_n>0 there",
            "degree_P": n,
            "term_count_P": len(p),
            "term_count_D": len(d),
            "P_hash": poly_hash(p, n=n, label="P_n"),
            "D_hash": poly_hash(d, n=n, label="D_n"),
            "cyclic_invariance_checked": cyclic_ok,
        })

    polynomial_spec = {
        "tool": TOOL_VERSION,
        "complete_certificate": False,
        "reason": "polynomial/root-universe artifacts and deferred pilot substitutions only; no leaf cover",
        "targets": specs,
    }
    write_json(CERT_ROOT / "vasc" / "polynomial_spec.json", polynomial_spec)

    basis_dir = CERT_ROOT / "lp_basis"
    write_json(basis_dir / "basis_manifest.json", {
        "tool": TOOL_VERSION,
        "basis_count": 0,
        "status": "no_lp_basis_used_in_pilot",
    })
    append_jsonl(basis_dir / "basis_polynomials.jsonl", [])

    generation_log = [
        "# Vasc Certificate Producer Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        "- Arithmetic: exact integer polynomial arithmetic.",
        "- Scope: polynomial specs, root universe hashes, and deferred pilot substitutions.",
        "- Complete proof certificate: NO.",
        "",
    ]

    for n in (9, 11):
        target_dir = CERT_ROOT / "sds_lp" / f"n{n}"
        target_dir.mkdir(parents=True, exist_ok=True)
        root_count, root_hash = root_universe_hash(n)
        pilot = pilot_permutations(n)

        root_rows = []
        tree_rows = []
        leaf_rows = []
        unresolved = 0
        coefficient_leaves = 0
        for idx, perm in enumerate(pilot):
            rid = f"pilot_{idx}"
            # Full pullbacks for degree 11 sorted cones can be very large.
            # The default producer therefore records exact deferred pilot
            # nodes.  Passing --full-pullbacks enables expensive exact
            # expansion for local experiments; absence of full pullbacks is
            # deliberately marked non-proof in the manifests.
            if args.full_pullbacks:
                rec, pulled = root_record(n, rid, perm, polys[n])
            else:
                mapping = root_substitution(n, perm)
                subst_obj = {
                    f"x{i + 1}": [f"y{j + 1}" for j in mapping[i]]
                    for i in range(n)
                }
                rec = {
                    "n": n,
                    "root_id": rid,
                    "perm": list(perm),
                    "substitution": subst_obj,
                    "status": "deferred_uncomputed",
                    "pullback_hash": None,
                    "substitution_hash": sha256_obj(subst_obj),
                    "coefficient_summary": None,
                }
                pulled = {}
            root_rows.append({"n": n, "root_id": rid, "perm": list(perm)})
            tree_rows.append({
                "node_id": rid,
                "parent_id": None,
                "root_id": rid,
                "depth": 0,
                "status": rec["status"],
                "pullback_hash": rec["pullback_hash"],
                "substitution_hash": rec.get("substitution_hash"),
                "coefficient_summary": rec["coefficient_summary"],
            })
            if rec["status"] == "coefficient_leaf":
                coefficient_leaves += 1
                leaf_rows.append({
                    "leaf_id": rid,
                    "root_id": rid,
                    "certificate_type": "coefficientwise_nonnegative",
                    "pullback_hash": rec["pullback_hash"],
                    "terms": poly_to_terms(pulled),
                })
            elif rec["status"] == "unresolved":
                unresolved += 1

        append_jsonl(target_dir / "roots.jsonl", root_rows)
        append_jsonl(target_dir / "tree.jsonl", tree_rows)
        append_jsonl(target_dir / "leaves.jsonl", leaf_rows)

        manifest = {
            "tool": TOOL_VERSION,
            "n": n,
            "complete_certificate": False,
            "target_polynomial_hash": specs[0 if n == 9 else 1]["P_hash"],
            "root_universe": {
                "type": "cyclic_maximum_then_all_orderings_stream",
                "fixed_maximum_variable": "x1",
                "root_count": root_count,
                "root_stream_hash": root_hash,
                "root_record_schema": {"root_id": "stream index", "perm": "ordering of x2..xn by decreasing value"},
            },
            "pilot": {
                "pilot_root_count": len(pilot),
                "coefficient_leaf_count": coefficient_leaves,
                "unresolved_count": unresolved,
                "deferred_uncomputed_count": len(pilot) if not args.full_pullbacks else 0,
                "roots_file": "roots.jsonl",
                "tree_file": "tree.jsonl",
                "leaves_file": "leaves.jsonl",
            },
            "sds_substitution_family": "none_applied_beyond_root_difference_substitution_in_pilot",
            "lp_basis_manifest": "../../lp_basis/basis_manifest.json",
        }
        write_json(target_dir / "manifest.json", manifest)
        write_json(target_dir / "audit_index.json", {
            "tool": TOOL_VERSION,
            "n": n,
            "complete_certificate": False,
            "files": {
                "manifest": sha256_obj(manifest),
                "roots_jsonl_sha256": hashlib.sha256((target_dir / "roots.jsonl").read_bytes()).hexdigest(),
                "tree_jsonl_sha256": hashlib.sha256((target_dir / "tree.jsonl").read_bytes()).hexdigest(),
                "leaves_jsonl_sha256": hashlib.sha256((target_dir / "leaves.jsonl").read_bytes()).hexdigest(),
            },
            "root_count": root_count,
            "pilot_root_count": len(pilot),
            "coefficient_leaf_count": coefficient_leaves,
            "unresolved_count": unresolved,
            "deferred_uncomputed_count": len(pilot) if not args.full_pullbacks else 0,
            "reproduction_commands": [
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_certificate_producer.py'} produce",
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_certificate_producer.py'} produce --full-pullbacks",
                f"VASC_WORKSPACE={WORKSPACE} uv run python {WORKSPACE / 'tools' / 'vasc_certificate_producer.py'} check",
            ],
        })
        generation_log.extend([
            f"## n={n}",
            f"- Root universe count: `{root_count}`.",
            f"- Root universe stream hash: `{root_hash}`.",
            f"- Pilot roots: `{len(pilot)}`.",
            f"- Coefficient leaves: `{coefficient_leaves}`.",
            f"- Unresolved pilot roots: `{unresolved}`.",
            f"- Deferred pilot roots: `{len(pilot) if not args.full_pullbacks else 0}`.",
            "",
        ])

    log_path = WORKSPACE / "logs" / "certificate_generation_v1.md"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(generation_log), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def check(args: argparse.Namespace) -> None:
    failures: list[str] = []
    spec_path = CERT_ROOT / "vasc" / "polynomial_spec.json"
    if not spec_path.exists():
        failures.append(f"missing {spec_path}")
    else:
        spec = read_json(spec_path)
        for entry in spec["targets"]:
            n = entry["n"]
            p = vasc_polynomial(n)
            d = denominator_polynomial(n)
            if poly_hash(p, n=n, label="P_n") != entry["P_hash"]:
                failures.append(f"n={n}: P hash mismatch")
            if poly_hash(d, n=n, label="D_n") != entry["D_hash"]:
                failures.append(f"n={n}: D hash mismatch")
            if not all(cyclic_permute_poly(p, s) == p for s in range(n)):
                failures.append(f"n={n}: cyclic invariance failed")

            target_dir = CERT_ROOT / "sds_lp" / f"n{n}"
            manifest = read_json(target_dir / "manifest.json")
            count, h = root_universe_hash(n)
            if manifest["root_universe"]["root_count"] != count:
                failures.append(f"n={n}: root count mismatch")
            if manifest["root_universe"]["root_stream_hash"] != h:
                failures.append(f"n={n}: root hash mismatch")

            with (target_dir / "tree.jsonl").open(encoding="utf-8") as handle:
                tree_rows = [json.loads(line) for line in handle if line.strip()]
            roots_lines = (target_dir / "roots.jsonl").read_text(encoding="utf-8").splitlines()
            for row in tree_rows:
                perm = tuple(json.loads(roots_lines[int(row["node_id"].split("_")[1])])["perm"])
                if row["status"] == "deferred_uncomputed":
                    mapping = root_substitution(n, perm)
                    subst_obj = {
                        f"x{i + 1}": [f"y{j + 1}" for j in mapping[i]]
                        for i in range(n)
                    }
                    if sha256_obj(subst_obj) != row["substitution_hash"]:
                        failures.append(f"n={n} {row['node_id']}: substitution hash mismatch")
                    continue
                rec, _ = root_record(n, row["node_id"], perm, p)
                if rec["pullback_hash"] != row["pullback_hash"]:
                    failures.append(f"n={n} {row['node_id']}: pullback hash mismatch")
                if rec["coefficient_summary"] != row["coefficient_summary"]:
                    failures.append(f"n={n} {row['node_id']}: coefficient summary mismatch")

    result = {
        "tool": TOOL_VERSION,
        "status": "PASS" if not failures else "FAIL",
        "complete_certificate": False,
        "failures": failures,
    }
    write_json(CERT_ROOT / "checker_result.json", result)
    log = [
        "# Vasc Certificate Checker Log",
        "",
        f"- Tool: `{TOOL_VERSION}`",
        f"- Status: `{result['status']}`",
        "- Complete proof certificate: NO.",
        "",
    ]
    if failures:
        log.append("## Failures")
        log.extend(f"- {f}" for f in failures)
    else:
        log.append("All generated polynomial/root-universe hashes and deferred pilot substitutions were recomputed exactly.")
    (WORKSPACE / "logs" / "certificate_checker_v1.md").write_text("\n".join(log) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    produce_parser = sub.add_parser("produce")
    produce_parser.add_argument(
        "--full-pullbacks",
        action="store_true",
        help="compute exact pilot pullbacks; can be expensive for n=11",
    )
    sub.add_parser("check")
    args = parser.parse_args()
    if args.cmd == "produce":
        produce(args)
    elif args.cmd == "check":
        check(args)


if __name__ == "__main__":
    main()
