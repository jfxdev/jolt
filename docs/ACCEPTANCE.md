# Load and fault-injection acceptance

The acceptance suite exercises the same durable job, filesystem, checkpoint,
parallel-file, and parallel-chunk paths used in production. It is opt-in so the
normal unit-test suite remains fast and does not unexpectedly consume large
amounts of disk space.

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

Run the half-scale profile on a disposable host with at least 110 GiB of free
disk space:

```sh
make acceptance-half
```

The `half` profile covers:

- one 5 GiB file;
- one 50 GiB directory;
- 2,500 files.

## Verified runs

| Date | Profile | Result | Duration | Environment note |
| --- | --- | --- | --- | --- |
| 2026-07-26 | `quick` | Passed | 14.837 s | Local APFS development host |
| 2026-07-26 | `half` | Passed | 559.746 s | Local APFS development host; temporary data cleaned and free space restored |
| — | `full` | Pending | — | Must run on representative target infrastructure |

Run the production-scale profile only on a disposable host with sufficient
time and at least 220 GiB of free disk space:

```sh
make acceptance-full
```

The `full` profile raises the same scenarios to:

- one 10 GiB file;
- one 100 GiB directory;
- 5,000 files.

The source and destination coexist during validation, and temporary partials
may also be present, so available disk space must exceed the nominal dataset
size.

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
| Restored database contains active jobs/partials | Diagnostics report them and restored jobs require explicit validation |

The `quick` profile is suitable for continuous integration. A release that
claims the 10 GiB/100 GiB limits should also record a successful
`make acceptance-full` run on the target filesystem and deployment class.
