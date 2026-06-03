#!/usr/bin/env python3
"""Independent checker for the Vasc n=9 finite certificate.

This script intentionally imports no project-local vasc_* modules.  It verifies
an existing certificate; it does not search for Polya powers or AM-GM circuits.

Checked facts:
- the final packet covers the lexicographic fixed-maximum stream [0, 40320);
- every source row has the expected permutation and direct pullback hash;
- coefficient leaves have coefficientwise nonnegative pullbacks;
- ordinary Polya leaves use the recorded k and have coefficientwise
  nonnegative (sum y_i)^k times the pullback;
- AM-GM overlay leaves use the recorded circuits, each satisfying
  alpha + gamma = 2 beta, and leave a coefficientwise nonnegative residual.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable


Poly = dict[tuple[int, ...], int]


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_obj(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def poly_to_terms(poly: Poly) -> list[dict[str, object]]:
    return [{"exp": list(exp), "coeff": coeff} for exp, coeff in sorted(poly.items())]


def poly_hash(poly: Poly, *, n: int, label: str) -> str:
    return sha256_obj({"label": label, "n": n, "terms": poly_to_terms(poly)})


def poly_stream_hash(poly: Poly, *, n: int, label: str) -> str:
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


def coeff_summary(poly: Poly) -> dict[str, int]:
    if not poly:
        return {
            "term_count": 0,
            "negative_count": 0,
            "zero_count": 0,
            "positive_count": 0,
            "min_coeff": 0,
            "max_coeff": 0,
        }
    vals = poly.values()
    return {
        "term_count": len(poly),
        "negative_count": sum(1 for c in vals if c < 0),
        "zero_count": 0,
        "positive_count": sum(1 for c in poly.values() if c > 0),
        "min_coeff": min(poly.values()),
        "max_coeff": max(poly.values()),
    }


def add_to(dst: Poly, src: Poly, scale: int = 1) -> None:
    for exp, coeff in src.items():
        new = dst.get(exp, 0) + scale * coeff
        if new:
            dst[exp] = new
        else:
            dst.pop(exp, None)


def monomial(n: int, var: int, coeff: int = 1) -> Poly:
    exp = [0] * n
    exp[var] = 1
    return {tuple(exp): coeff}


def mul_linear(poly: Poly, terms: list[tuple[int, int]]) -> Poly:
    if not poly or not terms:
        return {}
    out: dict[tuple[int, ...], int] = defaultdict(int)
    for exp, coeff in poly.items():
        for c, var in terms:
            new_exp = list(exp)
            new_exp[var] += 1
            out[tuple(new_exp)] += coeff * c
    return {exp: coeff for exp, coeff in out.items() if coeff}


def linear_poly(n: int, terms: list[tuple[int, int]]) -> Poly:
    out: Poly = {}
    for coeff, var in terms:
        if coeff:
            add_to(out, monomial(n, var, coeff))
    return out


def diff_linear_terms(a: int, b: int) -> list[tuple[int, int]]:
    """Terms of L_a - L_b, where L_p = y_p + ... + y_{n-1}."""
    if a == b:
        return []
    if a < b:
        return [(1, k) for k in range(a, b)]
    return [(-1, k) for k in range(b, a)]


def sum_linear_terms(n: int, a: int, b: int) -> list[tuple[int, int]]:
    """Terms of L_a + L_b, where L_p = y_p + ... + y_{n-1}."""
    coeffs: dict[int, int] = defaultdict(int)
    for k in range(a, n):
        coeffs[k] += 1
    for k in range(b, n):
        coeffs[k] += 1
    return [(coeff, var) for var, coeff in sorted(coeffs.items()) if coeff]


def direct_root_pullback(n: int, perm: tuple[int, ...]) -> Poly:
    """Compute P_n on the fixed-maximum cone for a permutation.

    The cone order is x_0 >= x_perm[0] >= ... >= x_perm[-1] >= 0 and
    x_order[pos] = L_pos = y_pos + ... + y_{n-1}.
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


def polya_product(poly: Poly, n: int, k: int) -> Poly:
    terms = [(1, i) for i in range(n)]
    current = poly
    for _ in range(k):
        current = mul_linear(current, terms)
    return current


def lexicographic_perm_at(n: int, index: int) -> tuple[int, ...]:
    elems = list(range(1, n))
    out: list[int] = []
    remaining = index
    for length in range(n - 1, 0, -1):
        block = math.factorial(length - 1)
        pos, remaining = divmod(remaining, block)
        out.append(elems.pop(pos))
    return tuple(out)


def root_stream_hash(n: int) -> tuple[int, str]:
    h = hashlib.sha256()
    count = 0
    for perm in itertools.permutations(range(1, n)):
        h.update(canonical_json({"root_id": count, "perm": list(perm)}).encode("utf-8"))
        h.update(b"\n")
        count += 1
    return count, h.hexdigest()


def expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def by_root(rows: Iterable[dict], *, what: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in rows:
        root_id = row["root_id"]
        expect(root_id not in out, f"duplicate {what} for {root_id}")
        out[root_id] = row
    return out


def load_source_batches(workspace: Path, n: int, batch_names: set[str]) -> dict[str, dict[str, dict]]:
    root = workspace / "certificates" / "polya_batches" / f"n{n}"
    out: dict[str, dict[str, dict]] = {}
    for name in sorted(batch_names):
        path = root / name
        manifest = read_json(path / "manifest.json")
        out[name] = {
            "manifest": manifest,
            "roots": by_root(read_jsonl(path / "roots.jsonl"), what=f"{name} root"),
            "tree": by_root(read_jsonl(path / "tree.jsonl"), what=f"{name} tree row"),
            "leaves": by_root(read_jsonl(path / "leaves.jsonl"), what=f"{name} leaf"),
            "unresolved": by_root(read_jsonl(path / "unresolved.jsonl"), what=f"{name} unresolved row"),
        }
    return out


def load_overlay_packets(workspace: Path, n: int, packet_ids: set[str]) -> dict[str, dict[str, dict]]:
    root = workspace / "certificates" / "polya_packets" / f"n{n}"
    out: dict[str, dict[str, dict]] = {}
    for packet_id in sorted(packet_ids):
        path = root / packet_id
        out[packet_id] = {
            "manifest": read_json(path / "manifest.json"),
            "roots": by_root(read_jsonl(path / "roots.jsonl"), what=f"{packet_id} root"),
            "products": by_root(read_jsonl(path / "polya_products.jsonl"), what=f"{packet_id} product"),
            "leaves": by_root(read_jsonl(path / "leaves.jsonl"), what=f"{packet_id} leaf"),
            "unresolved": by_root(read_jsonl(path / "unresolved.jsonl"), what=f"{packet_id} unresolved row"),
        }
    return out


def check_manifest_hashes(packet_manifest: dict, source_batches: dict, overlay_packets: dict, n: int) -> None:
    root_count, stream_hash = root_stream_hash(n)
    p_hash = poly_hash(vasc_polynomial(n), n=n, label="P_n")
    expect(root_count == math.factorial(n - 1), "internal root count mismatch")
    cov = packet_manifest["coverage"]
    expect(cov["root_count"] == root_count, "packet root count mismatch")
    expect(cov["start"] == 0 and cov["end_exclusive"] == root_count, "packet is not full [0, root_count)")
    for name, data in source_batches.items():
        manifest = data["manifest"]
        expect(manifest["target_polynomial_hash"] == p_hash, f"{name}: target polynomial hash mismatch")
        expect(manifest["root_universe"]["root_stream_hash"] == stream_hash, f"{name}: root stream hash mismatch")
    for packet_id, data in overlay_packets.items():
        manifest = data["manifest"]
        expect(manifest["target_polynomial_hash"] == p_hash, f"{packet_id}: target polynomial hash mismatch")
        expect(manifest["root_universe"]["root_stream_hash"] == stream_hash, f"{packet_id}: root stream hash mismatch")


def check_polya_leaf(root_id: str, pullback: Poly, leaf: dict, n: int) -> None:
    expect(leaf["certificate_type"] == "polya_sum_multiplier", f"{root_id}: wrong Polya leaf type")
    k = leaf["polya_power"]
    expect(isinstance(k, int) and k >= 0, f"{root_id}: invalid Polya power")
    product = polya_product(pullback, n, k)
    summary = coeff_summary(product)
    expect(summary == leaf["polya_product_summary"], f"{root_id}: Polya product summary mismatch")
    expect(summary["negative_count"] == 0, f"{root_id}: Polya product has negative coefficients")
    expect(
        poly_stream_hash(product, n=n, label=f"polya_product_{root_id}_k{k}") == leaf["polya_product_hash"],
        f"{root_id}: Polya product hash mismatch",
    )


def circuit_exponents(circuit: dict, n: int) -> tuple[int, tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    amount = circuit["amount_each_positive_term"]
    alpha = tuple(circuit["positive_exp_a"])
    gamma = tuple(circuit["positive_exp_b"])
    beta = tuple(circuit["midpoint_exp"])
    expect(isinstance(amount, int) and amount > 0, "AM-GM circuit has nonpositive amount")
    for name, exp in (("alpha", alpha), ("gamma", gamma), ("beta", beta)):
        expect(len(exp) == n and all(isinstance(e, int) and e >= 0 for e in exp), f"bad {name} exponent")
    expect(all(alpha[i] + gamma[i] == 2 * beta[i] for i in range(n)), "AM-GM exponent identity failed")
    expect(circuit["dominance_coeff"] == 2 * amount, "AM-GM dominance coefficient mismatch")
    return amount, alpha, gamma, beta


def spend(residual: Poly, exp: tuple[int, ...], delta: int) -> None:
    new = residual.get(exp, 0) + delta
    if new:
        residual[exp] = new
    else:
        residual.pop(exp, None)


def check_amgm_leaf(root_id: str, pullback: Poly, leaf: dict, packet_product: dict, n: int) -> None:
    expect(leaf["certificate_type"] == "amgm_midpoint_circuit_polya_leaf", f"{root_id}: wrong AM-GM leaf type")
    k = leaf["polya_power"]
    expect(isinstance(k, int) and k >= 0, f"{root_id}: invalid AM-GM Polya power")
    product = polya_product(pullback, n, k)
    product_summary = coeff_summary(product)
    expect(product_summary == leaf["polya_product_summary"], f"{root_id}: AM-GM product summary mismatch")
    expect(product_summary == packet_product["polya_product_summary"], f"{root_id}: packet product summary mismatch")
    product_hash = poly_stream_hash(product, n=n, label=f"hardroot_polya_product_{root_id}_k{k}")
    expect(product_hash == leaf["polya_product_hash"], f"{root_id}: AM-GM product hash mismatch")
    expect(product_hash == packet_product["polya_product_hash"], f"{root_id}: packet product hash mismatch")

    residual = dict(product)
    for index, circuit in enumerate(leaf["circuits"]):
        amount, alpha, gamma, beta = circuit_exponents(circuit, n)
        before_beta = residual.get(beta, 0)
        if "negative_coeff_before" in circuit:
            expect(before_beta == circuit["negative_coeff_before"], f"{root_id}: circuit {index} beta coeff mismatch")
        if "certified_negative_abs_coeff" in circuit:
            expect(circuit["certified_negative_abs_coeff"] == -before_beta, f"{root_id}: circuit {index} abs coeff mismatch")
        expect(residual.get(alpha, 0) >= amount, f"{root_id}: circuit {index} overspends alpha")
        expect(residual.get(gamma, 0) >= amount, f"{root_id}: circuit {index} overspends gamma")
        spend(residual, alpha, -amount)
        spend(residual, gamma, -amount)
        spend(residual, beta, 2 * amount)

    residual_summary = coeff_summary(residual)
    expect(
        residual_summary == leaf["residual_summary_after_subtracting_circuits"],
        f"{root_id}: AM-GM residual summary mismatch",
    )
    expect(residual_summary["negative_count"] == 0, f"{root_id}: AM-GM residual has negative coefficients")


def verify(args: argparse.Namespace) -> None:
    workspace = args.workspace.resolve()
    n = 9
    packet_dir = workspace / "certificates" / "polya_packets" / f"n{n}" / args.packet_id
    packet_manifest = read_json(packet_dir / "manifest.json")
    root_status = read_jsonl(packet_dir / "root_status.jsonl")
    expect(packet_manifest["n"] == n, "packet n mismatch")
    expect(len(root_status) == math.factorial(n - 1), "root_status length mismatch")

    batch_names = {row["source_batch"] for row in root_status}
    overlay_packet_ids = {row["overlay_packet"] for row in root_status if row.get("overlay_packet")}
    source_batches = load_source_batches(workspace, n, batch_names)
    overlay_packets = load_overlay_packets(workspace, n, overlay_packet_ids)
    check_manifest_hashes(packet_manifest, source_batches, overlay_packets, n)

    counts = {
        "coefficient_leaf_count": 0,
        "polya_leaf_count": 0,
        "amgm_midpoint_overlay_leaf_count": 0,
        "unresolved_count": 0,
    }
    started = time.time()
    last_report = started

    if args.root_index:
        indices = args.root_index
    elif args.limit is not None:
        indices = list(range(args.limit))
    else:
        indices = list(range(len(root_status)))
    full_run = args.limit is None and not args.root_index

    for expected_index in indices:
        expect(0 <= expected_index < len(root_status), f"root index out of range: {expected_index}")
        packet_row = root_status[expected_index]
        root_id = f"root_{expected_index:07d}"
        expected_perm = lexicographic_perm_at(n, expected_index)
        expect(packet_row["root_id"] == root_id, f"{root_id}: packet root id mismatch")
        expect(packet_row["root_index"] == expected_index, f"{root_id}: packet root index mismatch")

        batch = source_batches[packet_row["source_batch"]]
        tree = batch["tree"][root_id]
        expect(tree["root_index"] == expected_index, f"{root_id}: source root index mismatch")
        expect(tuple(tree["perm"]) == expected_perm, f"{root_id}: source permutation mismatch")
        expect(tree["certificate_status"] == packet_row["source_status"], f"{root_id}: source status mismatch")

        root_record = batch["roots"][root_id]
        expect(root_record["root_index"] == expected_index, f"{root_id}: root record index mismatch")
        expect(tuple(root_record["perm"]) == expected_perm, f"{root_id}: root record permutation mismatch")

        pullback = direct_root_pullback(n, expected_perm)
        pullback_summary = coeff_summary(pullback)
        pullback_hash = poly_hash(pullback, n=n, label=f"pullback_{root_id}")
        expect(tree["pullback_summary"] == pullback_summary, f"{root_id}: pullback summary mismatch")
        expect(tree["pullback_hash"] == pullback_hash, f"{root_id}: pullback hash mismatch")

        source_status = packet_row["source_status"]
        if source_status == "coefficient_leaf":
            counts["coefficient_leaf_count"] += 1
            expect(packet_row["packet_status"] == "coefficient_leaf", f"{root_id}: packet status mismatch")
            leaf = batch["leaves"][root_id]
            expect(leaf["certificate_type"] == "coefficientwise_nonnegative", f"{root_id}: wrong coefficient leaf type")
            expect(leaf["pullback_hash"] == pullback_hash, f"{root_id}: coefficient leaf pullback hash mismatch")
            expect(leaf["pullback_summary"] == pullback_summary, f"{root_id}: coefficient leaf summary mismatch")
            expect(pullback_summary["negative_count"] == 0, f"{root_id}: coefficient leaf has negative coefficients")
        elif source_status == "polya_multiplier_leaf":
            counts["polya_leaf_count"] += 1
            expect(packet_row["packet_status"] == "polya_multiplier_leaf", f"{root_id}: packet status mismatch")
            leaf = batch["leaves"][root_id]
            expect(leaf["pullback_hash"] == pullback_hash, f"{root_id}: Polya leaf pullback hash mismatch")
            expect(leaf["pullback_summary"] == pullback_summary, f"{root_id}: Polya leaf pullback summary mismatch")
            check_polya_leaf(root_id, pullback, leaf, n)
        elif source_status == "unresolved":
            unresolved = batch["unresolved"][root_id]
            expect(unresolved["pullback_hash"] == pullback_hash, f"{root_id}: unresolved pullback hash mismatch")
            expect(unresolved["pullback_summary"] == pullback_summary, f"{root_id}: unresolved pullback summary mismatch")
            overlay_id = packet_row.get("overlay_packet")
            if overlay_id is None:
                counts["unresolved_count"] += 1
                raise AssertionError(f"{root_id}: unresolved row has no overlay")
            counts["amgm_midpoint_overlay_leaf_count"] += 1
            expect(packet_row["packet_status"] == "amgm_midpoint_circuit_polya_leaf", f"{root_id}: overlay status mismatch")
            overlay = overlay_packets[overlay_id]
            overlay_root = overlay["roots"][root_id]
            expect(overlay_root["root_index"] == expected_index, f"{root_id}: overlay root index mismatch")
            expect(tuple(overlay_root["perm"]) == expected_perm, f"{root_id}: overlay permutation mismatch")
            leaf = overlay["leaves"][root_id]
            expect(leaf["pullback_hash"] == pullback_hash, f"{root_id}: overlay pullback hash mismatch")
            check_amgm_leaf(root_id, pullback, leaf, overlay["products"][root_id], n)
            expect(root_id not in overlay["unresolved"], f"{root_id}: overlay still unresolved")
        else:
            raise AssertionError(f"{root_id}: unsupported source status {source_status}")

        now = time.time()
        if not args.quiet and now - last_report >= args.progress_seconds:
            done = sum(counts.values())
            print(f"checked {done}/{len(indices)} selected roots in {now - started:.1f}s", flush=True)
            last_report = now

    if full_run:
        expected_counts = packet_manifest["packet_counts"]
        for key, value in counts.items():
            expect(expected_counts[key] == value, f"packet count mismatch for {key}")
        expect(expected_counts["root_count"] == sum(counts.values()), "packet root count does not equal status counts")

    elapsed = time.time() - started
    print("PASS")
    print(json.dumps({"checked_roots": sum(counts.values()), "counts": counts, "elapsed_seconds": round(elapsed, 3)}, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_workspace = Path(__file__).resolve().parents[1]
    parser.add_argument("--workspace", type=Path, default=default_workspace)
    parser.add_argument("--packet-id", default="prefix_0000000_0040320_with_hardroots")
    parser.add_argument("--limit", type=int, default=None, help="debug option: verify only the first N roots")
    parser.add_argument("--root-index", type=int, action="append", help="debug option: verify one selected root index")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--progress-seconds", type=float, default=30.0)
    return parser.parse_args()


def main() -> None:
    verify(parse_args())


if __name__ == "__main__":
    main()
