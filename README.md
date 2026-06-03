# Vasc n=9 Certificate Verification Artifact

This directory is a self-contained reviewer package for the finite
certificate of the `n=9` case.

The checker is intentionally minimal: it uses only the Python standard
library, imports no project-local `vasc_*` modules, and only verifies the
included certificate files. It does not search for Polya powers, AM-GM
circuits, or new proof data.

## Directory Contents

- `tools/verify_n9_certificate_minimal.py`: independent Python checker.
- `tools/rebuild_n9_certificate_from_sources.py`: optional rebuild driver for
  regenerating the certificate files from producer sources.
- `producer_sources/`: producer/checker sources used by the rebuild driver.
- `rebuild/n9_rebuild_plan.json`: deterministic generation plan for the
  reviewer certificate files.
- `certificates/polya_batches/n9/batch_*`: base certificate batches.
- `certificates/polya_packets/n9/prefix_0000000_0040320_with_hardroots`: final
  packet for all `40320 = 8!` fixed-maximum cones.
- `certificates/polya_packets/n9/hardroots_*`: AM-GM overlay packets used by
  the final packet.
- `SHA256SUMS`: SHA256 hashes for the files in this package.

See `REPRODUCE.md` for the optional from-source rebuild workflow.  The
independent checker remains the recommended reviewer verification path.

## Requirements

- Python 3.10 or newer is recommended.
- The independent checker uses only the Python standard library.
- `sha256sum` is optional and is used only for the file integrity check.
- The full independent verification is CPU-intensive and single-threaded.  On
  the preparation machine it was estimated to take about 24-35 hours; the
  largest AM-GM overlay roots may use a few GB of memory.

## Optional File Integrity Check

From this directory, run:

```bash
sha256sum -c SHA256SUMS
```

This checks that the packaged files have not changed after packaging or
transfer. It is not the mathematical verification itself.

## Full Verification

From this directory, run:

```bash
python3 tools/verify_n9_certificate_minimal.py
```

To save a structured run record for the paper artifact, add `--run-log`:

```bash
python3 tools/verify_n9_certificate_minimal.py \
  --run-log logs/verify_full.json
```

This writes `logs/verify_full.json` and `logs/verify_full.json.sha256`.  The
JSON record includes the command, Python/platform information, key certificate
file hashes, root counts, elapsed time, and final PASS/FAIL status.

If your environment uses `uv`, the equivalent command is:

```bash
uv run python tools/verify_n9_certificate_minimal.py
```

Expected final output:

```text
PASS
{"checked_roots": 40320, "counts": {"amgm_midpoint_overlay_leaf_count": 1269, "coefficient_leaf_count": 36815, "polya_leaf_count": 2236, "unresolved_count": 0}, "elapsed_seconds": ...}
```

The elapsed time depends heavily on CPU speed. The checker is single-threaded;
on the preparation machine, a full run is estimated to take about 24-35 hours.
The largest AM-GM roots may use a few GB of memory.

## Quick Smoke Tests

To verify that Python and the package layout are working before starting the
full run:

```bash
python3 tools/verify_n9_certificate_minimal.py --limit 32 --quiet
python3 tools/verify_n9_certificate_minimal.py --root-index 5952 --quiet
```

The same run-log option can be used for smoke tests:

```bash
python3 tools/verify_n9_certificate_minimal.py \
  --limit 32 \
  --quiet \
  --run-log logs/verify_limit32.json
```

The first command checks the first 32 roots. The second checks one AM-GM
overlay root.

Expected output for each smoke command begins with:

```text
PASS
```

## What Is Verified

For each of the `40320` fixed-maximum cones, the checker recomputes the
permutation, the direct pullback of the `n=9` Vasc polynomial, and the relevant
certificate claim:

- coefficient leaves: the pullback has no negative coefficients;
- ordinary Polya leaves: the recorded `(y_0 + ... + y_8)^k` product has no
  negative coefficients;
- AM-GM overlay leaves: the recorded Polya product hash matches, every AM-GM
  circuit satisfies `alpha + gamma = 2 beta`, the positive terms are not
  overspent, and the final residual has no negative coefficients.

The full run also checks the final packet counts:

```text
coefficient leaves: 36815
ordinary Polya leaves: 2236
AM-GM overlay leaves: 1269
unresolved leaves: 0
total roots: 40320
```
