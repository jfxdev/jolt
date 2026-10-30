# Load and fault-injection acceptance

The acceptance suite exercises the same durable job, filesystem, checkpoint,
parallel-file, and parallel-chunk paths used in production. It is opt-in so the
normal unit-test suite remains fast and does not unexpectedly consume large
amounts of disk space.

The consolidated go/no-go record is [RELEASE_V1.md](RELEASE_V1.md). Besides the
profiles below, the final dated images must pass:

```sh
python3 scripts/container-smoke.py --expected-version VERSION
python3 scripts/browser-integration.py --expected-version VERSION
python3 scripts/release-lifecycle.py \
  --node-image ghcr.io/jfxdev/jolt-node@sha256:CANDIDATE \
  --control-image ghcr.io/jfxdev/jolt-control@sha256:CANDIDATE
```

Replace `VERSION` with the exact allocated image version, `YYYY-MM-DD` or
`YYYY-MM-DD.N` when a numeric collision suffix was allocated.

Browser integration uses two real nodes, HTTPS and desktop/mobile journeys.
Lifecycle covers snapshot, empty restore, diagnostics and operation; passing both
`--previous-node-image` and `--previous-control-image` also covers upgrade and
rollback with the previous version's snapshot. These scripts were added for this
release, but their final-container evidence remains pending until explicitly
recorded in RELEASE_V1. Do not infer a pass from compilation or CI wiring.

A production claim also requires `make acceptance-full` on representative
Linux/amd64 infrastructure and a separate two-host transfer/failure rehearsal.
Two containers on one development machine do not replace that rehearsal.

## Profiles

Run the CI/development profile:

```sh
make acceptance
```

The `quick` profile covers:

- one 64 MiB file copied with four parallel chunks;
- a forced worker shutdown after a durable checkpoint;
- explicit post-restart validation and resume;
- final source/destination SHA-256 equality;
- a 128 MiB directory containing 1,024 files;
- eight parallel files and two parallel chunks per file;
- aggregate byte/file progress and sampled SHA-256 equality.

Run the half-scale profile on a disposable host with at least 60 GiB of free
disk space:

```sh
make acceptance-half
```

The `half` profile covers:

- one 5 GiB file;
- one 25 GiB directory;
- 2,500 files.

## Verified runs

| Date | Profile | Result | Duration | Environment note |
| --- | --- | --- | --- | --- |
| 2026-07-26 | `quick` | Passed | 14.837 s | Local APFS development host |
| 2026-07-26 | `half` (legacy 5 GiB/50 GiB configuration) | Passed | 559.746 s | Local APFS development host; temporary data cleaned and free space restored |
| 2026-10-22 | `quick` (YAML) | Passed | 230.657 s | Local APFS; concurrent race-test and image-build workload |
| 2026-10-30 | `full` | Passed | 4,842.680 s | Local macOS 27.0.1 ARM64/APFS; temporary data cleaned; representative Linux/amd64 run remains pending |

Run the production-scale profile only on a disposable host with sufficient
time and at least 100 GiB of free disk space:

```sh
make acceptance-full
```

The `full` profile raises the same scenarios to:

- one 10 GiB file;
- one 35 GiB directory;
- 5,000 files.

The source and destination coexist during validation, and temporary partials
may also be present. The default `full` profile is capped at 90 GiB of nominal
source/destination data, leaving 10 GiB of its 100 GiB budget for partials and
metadata.

## Overrides

Exact decimal byte counts and file counts can be overridden without changing
the test:

```sh
cd node
JOLT_ACCEPTANCE_PROFILE=quick \
JOLT_ACCEPTANCE_FILE_BYTES=1073741824 \
JOLT_ACCEPTANCE_DIRECTORY_BYTES=4294967296 \
JOLT_ACCEPTANCE_DIRECTORY_FILES=2000 \
JOLT_ACCEPTANCE_BANDWIDTH_BYTES_PER_SECOND=67108864 \
go test -tags=acceptance -run '^TestAcceptance' -timeout 1h \
  ./backend/internal/services/jobs
```

Supported variables:

| Variable | Meaning |
| --- | --- |
| `JOLT_ACCEPTANCE_PROFILE` | `quick`, `half`, or `full` |
| `JOLT_ACCEPTANCE_FILE_BYTES` | Individual large-file size |
| `JOLT_ACCEPTANCE_DIRECTORY_BYTES` | Aggregate source directory size |
| `JOLT_ACCEPTANCE_DIRECTORY_FILES` | Number of files in the directory |
| `JOLT_ACCEPTANCE_BANDWIDTH_BYTES_PER_SECOND` | Per-job limit used by the interrupted file scenario |

## Fault matrix

The always-on automated suite complements the opt-in load profiles:

| Fault | Expected invariant |
| --- | --- |
| Remote response truncated during a parallel range batch | Automatic retry starts at the previous synced batch checkpoint |
| Source ETag changes between metadata and Range requests | Batch fails and destination is never published |
| Worker stops after a local durable checkpoint | Job enters `waiting_validation`; explicit resume retains the checkpoint |
| Pause during a copy | Partial remains unpublished and resume continues from its checkpoint |
| Cancel with a persisted partial | Partial is removed and item progress is reset |
| Mount disappears | Job waits without spending retry budget and wakes after validation |
| Peer becomes unavailable | Job waits without spending retry budget and wakes after authenticated heartbeat |
| Restored state contains active jobs/partials | Diagnostics report them and restored jobs require explicit validation |

The `quick` profile is suitable for continuous integration. A release that
claims the 10 GiB/35 GiB limits should also record a successful
`make acceptance-full` run on the target filesystem and deployment class.

## Encrypted YAML persistence profile

`make acceptance` also measures state checkpoint latency, opening time and
retained heap with 4,096 historical events containing 32 MiB of payload.
The 2026-10-22 run measured 52.4 ms per durable checkpoint, 1.224 s to reopen,
1,055,480 bytes of retained heap for indexes, and a 1,076,017-byte payload cache
when fetching 17 events. This run shared the host with race tests and image
builds; these measurements are not a production throughput guarantee.
The active journal held 101 transactions after consolidation. Normal state tests
exercise the automatic 1,024-transaction boundary and verify history pagination,
idempotency, authenticated sequence continuity and crash boundaries for journal,
head, snapshot pages and manifest publication. Payload cache is capped at 16 MiB.

The container smoke test verifies immutable YAML resources, identity and partial
upload recovery after a container restart, no node database files, and existing
RBAC protections. The node production build uses `CGO_ENABLED=0`; CI rejects SQL
runtime dependencies. The Control Tower retains its SQLCipher build.
