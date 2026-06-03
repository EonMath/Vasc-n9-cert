# Rebuilding the n=9 Certificate Files

This package has two reproducibility layers.

1. `tools/verify_n9_certificate_minimal.py` independently checks the included
   certificate files.  This is the recommended reviewer check.
2. `tools/rebuild_n9_certificate_from_sources.py` regenerates the certificate
   files from the producer sources in `producer_sources/` and the deterministic
   build plan in `rebuild/n9_rebuild_plan.json`.

The rebuild layer is intentionally separate from the independent checker.  The
producer scripts may search for Polya multipliers and AM-GM midpoint circuits;
the minimal checker does not.

## Requirements

- Python 3.10 or newer is recommended.
- The independent checker uses only the Python standard library.
- The rebuild driver uses only the Python standard library, but the full
  rebuild is long-running and CPU-intensive.
- `sha256sum` is optional for manual integrity checks; the rebuild driver has
  its own Python SHA256 comparison against `SHA256SUMS`.
- Use a fresh build workspace with enough disk space for regenerated
  certificate files.

## Files Added for Rebuilds

- `producer_sources/`: exact producer/checker sources used by the rebuild
  driver.
- `rebuild/n9_rebuild_plan.json`: frozen schedule for the 633 raw Polya
  batches, 281 hardroot overlay packets, and the final overlay packet.  The plan
  stores only build parameters and hardroot identifiers, not certificate
  leaves or AM-GM circuit data.
- `tools/rebuild_n9_certificate_from_sources.py`: top-level rebuild driver.

## Quick Plan Check

From this directory:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py --mode plan
```

This prints the frozen plan summary and the recommended smoke/full commands.
It should report 633 batches, 281 hardroot overlay packets, and final packet
`prefix_0000000_0040320_with_hardroots`.

## Smoke Rebuild

Use a fresh output directory:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode smoke \
  --build-workspace /tmp/vasc_n9_rebuild_smoke \
  --run-log logs/rebuild_smoke.json
```

This regenerates the first raw Polya batch, builds a small smoke overlay, and
compares the regenerated listed certificate files against `SHA256SUMS`.
The smoke rebuild succeeds if the command exits with status 0 and prints a
successful listed-certificate hash comparison.
The `--run-log` option writes a structured JSON record and a
`logs/rebuild_smoke.json.sha256` sidecar.

To also exercise one AM-GM hardroot overlay packet:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode smoke \
  --include-hardroot-smoke \
  --build-workspace /tmp/vasc_n9_rebuild_smoke_hardroot \
  --run-log logs/rebuild_smoke_hardroot.json
```

The hardroot smoke chooses a small hardroot overlay packet from the frozen plan,
but it is still much heavier than the default smoke because it must regenerate the
corresponding 64-root source batch first.  Depending on the machine, this can
take many minutes; it is not part of the quick path.

## Full Rebuild

The full rebuild is long-running.  It regenerates all 633 raw batches, all 281
hardroot overlay packets, and the final packet
`prefix_0000000_0040320_with_hardroots`, then compares every generated
certificate file listed in `SHA256SUMS`.

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode full \
  --build-workspace /path/to/fresh/vasc_n9_rebuild \
  --run-log logs/rebuild_full.json
```

If a run is interrupted, resume it with:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode full \
  --resume \
  --build-workspace /path/to/fresh/vasc_n9_rebuild \
  --run-log logs/rebuild_full_resume.json
```

The rebuild driver is non-destructive: it refuses to use a non-empty build
workspace unless `--resume` is supplied.

The rebuild run log records the frozen plan hash, `SHA256SUMS` hash, selected
mode/options, every producer/checker subprocess command and return code, hash
comparison summary, and final PASS/FAIL status.  The `.sha256` sidecar is the
hash to cite when archiving a completed run log.

## Optional Independent Verification After Rebuild

After the full rebuild and hash comparison, the independent checker can also be
run against the regenerated workspace:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode full \
  --resume \
  --run-independent-verifier \
  --build-workspace /path/to/fresh/vasc_n9_rebuild \
  --run-log logs/rebuild_full_with_verifier.json
```

The independent full verification is single-threaded and can take about
24-35 hours on the preparation machine.  For a short post-rebuild sanity check,
use:

```bash
python3 tools/rebuild_n9_certificate_from_sources.py \
  --mode full \
  --resume \
  --run-independent-verifier \
  --verifier-limit 32 \
  --build-workspace /path/to/fresh/vasc_n9_rebuild \
  --run-log logs/rebuild_full_with_verifier_limit32.json
```

When `--run-independent-verifier` is used, the rebuild driver also asks the
child verifier to write its own run log under the selected build workspace.

## Portability Note

The producer sources honor `VASC_WORKSPACE`.  The rebuild driver copies them
into the selected build workspace and sets this environment variable for every
producer/checker subprocess, so generated certificates are written under the
chosen build directory rather than under the original research workspace.
