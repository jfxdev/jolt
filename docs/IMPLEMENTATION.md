# Implementation status

Last updated: 2026-07-26.

Status legend:

- **Implemented**: available in the current code and validated by the relevant
  automated tests and/or production build.
- **Partial**: a usable vertical slice exists, but requirements in the same area
  are still open.
- **Pending**: not implemented beyond interfaces, documentation, or preparatory
  plumbing.

## Summary

| Area | Status | Main remaining work |
| --- | --- | --- |
| Repository and Docker boundaries | Implemented | Production deployment validation |
| Local API filesystem | Implemented | Mutable runtime configuration and recent-log API |
| Durable local jobs | Implemented | Persisted resumable upload chunks |
| Pairing and Transfer Path Grants | Implemented | Remote grant discovery |
| mTLS identity and certificate lifecycle | Implemented | Operational hardening and post-MVP external certificate import |
| Peer heartbeat | Implemented | Backoff tuning and broader idle-event diagnostics |
| Direct node-to-node file transfer | Implemented | Remote `ask` decisions and peer data-plane discovery |
| Direct node-to-node directory transfer | Implemented | Peer data-plane discovery |
| Control Tower authentication | Implemented | Extend route coverage as new resources are added |
| Disaster recovery and hardening | Partial | Execute and record the full 10 GiB/100 GiB acceptance profile on target infrastructure |

## Recent progress

### 2026-07-25 — transfer execution hardening

- Added separate configurable connection, idle-read, chunk, validation, and
  no-progress deadlines without imposing a global timeout on long-running jobs.
- Added shared node-wide and persisted per-job bandwidth limits for streaming
  uploads, local copies, and direct remote pulls.
- Added pacing-aware progress heartbeats so intentional low bandwidth does not
  look like a stalled chunk.
- Added persisted per-job file parallelism for local and remote directory jobs,
  with ordered directory creation, independent item checkpoints, aggregate
  progress, and sequential fallback for interactive conflicts.

### 2026-07-26 — local parallel chunks

- Added persisted and configurable local `max_parallel_chunks`, bounded from
  `1` to `16`.
- Local copies now execute non-overlapping `ReadAt`/`WriteAt` ranges in bounded
  batches while keeping a single contiguous durable checkpoint.
- A batch is synced completely before its checkpoint advances. Process
  interruption therefore discards only the unfinished batch and never publishes
  a destination containing holes.
- SHA-256 verification, source-change validation, resumable partials, bandwidth
  limits, cancellation, retry, and atomic publication remain active in the
  parallel path.
- Added Control Tower controls in MiB/s, parallel files, and local parallel
  chunks, plus matching Docker configuration and OpenAPI fields.
- Verified the complete node and Control Tower test suites, the production
  frontend build, and race-enabled filesystem/job/transfer tests.

### 2026-07-26 — direct remote parallel chunks

- Extended persisted `max_parallel_chunks` to direct remote file and directory
  pulls, including both Control Tower transfer workflows.
- Remote files are fetched with bounded concurrent mTLS Range requests grouped
  into contiguous batches. The destination checkpoint advances only after every
  range in a batch passes validation and the batch is fully synced.
- Every range revalidates the current exact trusted peer and destination grant;
  the source node independently revalidates the exact client identity and source
  grant. Requests also use `If-Match` and require the same ETag, total size,
  exact `Content-Range`, bounded response length, and final trailer ETag.
- Any failed or divergent range cancels its batch and returns its initial
  checkpoint. Incomplete bytes remain unpublished and are truncated back to
  that checkpoint on retry.
- SHA-256 verification, shared node/job bandwidth limits, resumable partials,
  cancellation, retry, and atomic publication remain active in the multi-range
  path.

### 2026-07-26 — load and fault-injection acceptance matrix

- Added opt-in `quick` and `full` acceptance profiles using production durable
  job, filesystem, parallel-file, and parallel-chunk paths.
- The verified `quick` profile copies a 64 MiB file through a forced worker
  shutdown, explicit validation, checkpointed resume, and final SHA-256
  comparison. It also copies a 128 MiB directory containing 1,024 files with
  parallel files/chunks and validates aggregate progress plus sampled checksums.
- The `full` profile raises the same scenarios to the required 10 GiB file and
  100 GiB/5,000-file directory. It is intentionally opt-in and requires a
  disposable host with sufficient disk and time.
- Added and verified a `half` profile with a 5 GiB interrupted/resumed file and
  a 50 GiB/2,500-file directory. The complete run passed on a local APFS host in
  559.746 seconds, including checksum validation and automatic temporary-data
  cleanup.
- Added deterministic remote fault injection that truncates a response during
  the second concurrent Range batch. The automatic retry resumes from the
  previous synced checkpoint without fetching the first batch again.
- Documented the acceptance profiles, size overrides, resource expectations,
  and the complete always-on fault matrix in `docs/ACCEPTANCE.md`.

### Next milestone

- Execute and record `make acceptance-full` on representative target
  filesystems/deployment infrastructure. The profile performs real 10 GiB and
  100 GiB I/O and is not appropriate for the default development test run.

## Implemented

### Repository and deployment boundaries

- `node/` builds an API-only node image.
- `control/` builds the separate Control Tower Go backend and Vue 3 frontend.
- The root Compose file connects both products without merging persistence.
- Nodes remain the source of truth for identity, mounts, peers, grants, files,
  jobs, job items, checkpoints, and transfer history.
- The Control Tower stores only its own users, sessions, encrypted node tokens,
  node registry, connection orchestration state, preferences, and audit data.
- Node and Control Tower containers support privilege drop, `PUID`, `PGID`, and
  `UMASK`.
- Node data and cryptographic keys use separate persistent directories.

### Node API filesystem

- Single Go binary with bearer-token authentication and OpenAPI/Swagger.
- Stable logical `node_id`, versioned Ed25519 identity, and human-checkable
  fingerprint.
- SQLite-backed mounts, jobs, job items, events, peers, grants, pairing state,
  idempotency, and durable checkpoints.
- Safe relative paths with path-traversal and symlink-escape protection.
- Key and data directories cannot be registered as transfer mounts.
- Read-only/read-write enforcement and mount permission diagnostics.
- Directory listing, metadata, Range download, streaming upload, atomic publish,
  mkdir, local copy, move/rename, and delete.
- Large request bodies and files are streamed rather than loaded fully in memory.
- Uploads use temporary files and atomic rename before publication.

### Control Tower operational slice

- Separate Go service and mobile-first Vue 3 interface.
- First-boot admin creation with Argon2id password hashing.
- Persistent, revocable, HTTP-only, SameSite browser sessions.
- Admin-only user creation, editing, enable/disable, password reset, and deletion.
- User password changes and disable operations revoke existing sessions.
- The last enabled administrator and the current administrator session are
  protected against accidental lockout.
- User mutations are correlation-audited, while user deletion preserves prior
  audit history.
- Admin-managed service accounts with descriptions, enabled state, optional
  credential expiry, independently revocable credentials, and rotation.
- Service-account credentials are opaque bearer tokens, shown only at issuance,
  and stored only as SHA-256 digests.
- Service-account authentication preserves `actor_type=service_account` in
  audit records. Accounts without an assigned policy fail closed for node
  discovery and node API calls.
- Persistent Node Path policies with `read`, `list`, `create`, `update`,
  `delete`, `write`, `execute`, `sudo`, and precedence-enforced `deny`.
- Canonical Control Tower node contracts use `node_id`, `/api/v1/nodes/...`,
  and `nodes/...` RBAC paths. Existing `workers/...` policy paths and legacy
  connection columns are migrated automatically. The legacy
  `/api/v1/workers/...` route is no longer exposed.
- Policy assignment to users and service accounts, with administrative API and
  visual policy/rule editor.
- Reusable roles containing one or more policies, with administrative CRUD,
  visual role editor, and many-to-many assignment to users.
- Effective user authorization combines direct policies with policies inherited
  from every assigned role, deduplicating repeated policies while preserving
  global `deny` precedence.
- Node proxy authorization is evaluated before any request reaches a node.
- Direct file operations are authorized at
  `nodes/{node}/files/mounts/{mount}` without using the relative filesystem
  path in the RBAC decision.
- The `files` and `transfers` domains are independent. Remote transfer requests
  additionally resolve both node-owned grants and require source read and
  destination create capability on the exact mount-level file paths.
- Permission introspection lets the frontend hide unauthorized actions and
  avoid loading unauthorized mounts, jobs, peers, grants, and pairing data.
- RBAC decision audits preserve actor type, applied policy IDs, evaluated path,
  requested capability, decision, and correlation ID.
- The administrative audit API and Activity view expose those decision details
  with cursor pagination and exact actor type, action, result, and correlation
  filters. Audit reads require `sudo` on `control-tower/audit`.
- Mandatory external encryption key and AES-GCM encryption for stored node
  operational tokens.
- The entire Control Tower SQLite database is encrypted page-by-page with
  SQLCipher using the mandatory external 32-byte key. Incorrect keys fail
  before schema access, snapshots remain encrypted, and legacy plaintext
  databases require an explicit, integrity-checked offline migration.
- Two-phase node operational-token rotation keeps the new credential valid
  across intermediate failures, stores only its SHA-256 digest on the node,
  updates the AES-GCM-encrypted Control Tower copy, and invalidates the old
  token only after new-token authentication succeeds.
- Authenticated node registration and online/offline/untrusted classification.
- Admin-only node removal from the Control Tower, with explicit confirmation,
  preserved audit history, and transactional cleanup of connection orchestration
  secrets. Removing a registration never mutates the node or its filesystem.
- Node API proxy for mounts, files, uploads, downloads, jobs, pairing, peers,
  grants, transfers, and safe mTLS lifecycle operations.
- Mount creation from the selected node; absolute paths remain write-only
  administrative input validated by the node.
- Job history, live resumable SSE events, progress, speed, ETA, controls,
  item-level results, and manual local-copy conflict decisions.
- Correlation-aware audit records for Control Tower operations.

### Pairing, trust, clusters, and grants

- Expiring `one_sided` and `dual_channel` pairing requests with roles, purpose,
  optional cluster ID, issuer identity, control endpoint, and mTLS endpoint.
- Revocable, one-time invites.
- Incoming requests begin at `pending_review`.
- Approval requires exact human fingerprint confirmation and creates bilateral
  trusted-peer records.
- Rejection resolves the target request and revokes the issuer invite.
- Pending invite secrets remain encrypted in the Control Tower and are not
  returned to the browser.
- Pairing establishes identity trust only; it never creates mounts or grants.
- Cluster membership is persisted but never creates transitive trust.
- Transfer Path Grants are node-owned SQLite resources bound to:
  - one exact trusted peer identity;
  - one existing local mount;
  - one safe relative path inside that mount.
- Grants support `send`, `receive`, and `send_receive`, granular read/write/
  delete/rename permissions, visibility, enabled state, and allowed conflict
  policies.
- Grant direction is validated against mount mode and one-sided peer roles.
- Grant create, update, and revoke operations persist immutable audit snapshots
  with correlation IDs.
- Explicit peer revocation preserves the peer history with `revoked` state,
  atomically disables every related grant, cancels related active or pending
  jobs, and blocks subsequent mTLS trust validation.
- Peer control and mTLS endpoints can be updated without changing the trusted
  identity. Updates reject unsafe schemes and revoked peers, reset health to
  `unknown`, and require a fresh identity-authenticated heartbeat.
- Stable-identity rotation preserves `node_id`, advances a monotonic identity
  epoch, requires exact current fingerprint confirmation, and archives the
  previous private identity.
- Every rotation emits a durable handover envelope containing the consecutive
  epochs, both public keys and fingerprints, a nonce, and signatures from both
  the previous and next Ed25519 identities. A peer accepts it only when its
  current trusted `node_id`, epoch, and fingerprint match the envelope exactly.
- The Control Tower distributes the signed handover to registered peers during
  rotation, reports acknowledgements and pending offline peers, and can replay
  the persisted chain later for reconciliation. Applying the chain changes
  neither `node_id` nor grants/jobs; fresh mTLS validation is still required.
- During restart overlap, only the adjacent old/new fingerprints authorized by
  that envelope are accepted. The previous fingerprint is retired
  automatically and cannot be used again as soon as an authenticated heartbeat
  proves the new epoch is active.
- Missing, invalid, non-consecutive, tampered, replayed, or revoked handovers
  fail closed. Manual `identity_changed` confirmation remains the recovery path
  when the previous private key or a required link in the chain was lost.
- Mount deletion is blocked while a grant references the mount.
- The Control Tower proxies grant management without copying ownership away from
  the node.

### Durable asynchronous jobs

- Persistent SQLite queue with atomic claims and bounded node concurrency
  configured by `MAX_CONCURRENT_JOBS`.
- Durable jobs for mkdir, local copy, move, delete, and direct remote file pull.
- Recovery converts jobs left in executing/requested states to
  `waiting_validation`; explicit validation/resume is required.
- Every queued durable job revalidates its destination mount immediately before
  execution.
- Jobs whose required mount is disabled, missing, unreadable, or unwritable enter
  `waiting_mount` without consuming retry budget.
- A lightweight mount monitor automatically returns `waiting_mount` jobs to
  validation after mount diagnostics pass again.
- Resumed local jobs re-check source metadata and deterministic partial prefixes;
  resumed remote jobs additionally re-check exact peer identity, both grants,
  allowed conflict policy, source ETags, and destination partial checkpoints.
- Pause, resume, cancel, automatic retry with exponential backoff, and manual
  retry.
- Attempt limits configured by `JOB_MAX_ATTEMPTS`.
- Separate configurable connection, idle-read, chunk, and validation timeouts.
- Configurable no-progress detection cancels stalled work without imposing a
  global duration limit on long-running jobs.
- A shared node-wide bandwidth limiter caps aggregate traffic across concurrent
  upload, local-copy, and remote-pull jobs.
- Optional per-job bandwidth limits are validated, persisted with durable jobs,
  survive retries/restarts, and are exposed in the Control Tower copy workflows.
- Intentional bandwidth pacing emits worker heartbeats so low configured rates
  do not trigger false chunk/no-progress timeouts.
- Directory jobs use a persisted, bounded per-job file worker pool for local and
  direct remote copies. Directory creation is completed before file workers
  start, each item keeps an independent checkpoint, and conflict flows that
  require ordered decisions safely fall back to sequential execution.
- Local file copies support persisted `max_parallel_chunks` with bounded
  concurrent `ReadAt`/`WriteAt` ranges. Publication remains atomic and the
  durable checkpoint advances only after a complete contiguous batch is synced;
  interruption discards at most the unfinished batch.
- Direct remote pulls support the same persisted parallelism with bounded
  concurrent mTLS Range requests. Each request revalidates the exact peer and
  grants, enforces the persisted source ETag through `If-Match`, validates its
  exact range metadata and final ETag, and commits only complete synced batches.
- Persistent lifecycle and progress events.
- Resumable SSE at `GET /api/v1/jobs/events`, including `Last-Event-ID`, optional
  job filtering, heartbeat frames, and Control Tower proxy streaming.
- Byte progress, transfer rate, ETA, and `low`/`medium`/`high` ETA confidence.
- Directory manifests and itemized plans for local copies.
- Local copy preview at
  `POST /api/v1/mounts/{mountID}/files/copy/plan`, with aggregate counts and a
  500-item response cap.
- Paginated per-item results at `GET /api/v1/jobs/{jobID}/items`.
- Directory resume at file granularity; completed and skipped items are preserved.
- Configurable local chunks through `COPY_CHUNK_SIZE_BYTES`, defaulting to 16 MiB.
- Every fully synced chunk advances a durable checkpoint.
- Retry truncates bytes written beyond the last persisted checkpoint.
- Local resumed partials are validated against the source prefix.
- Internal partial files are hidden from the API filesystem and removed on
  cancellation.
- `completed_with_warnings` and retry of failed items without re-copying completed
  items.
- Source-change policies `fail`, `retry`, and `copy_anyway` for local manifest
  items.
- Conflict policies `skip`, `overwrite`, `rename`, `fail`, `ask`, and `checksum`
  for itemized local copies.
- SHA-256 verification before atomic publication.
- Local `ask` jobs enter `waiting_user_decision` without consuming retry budget.
- Item overrides support `skip`, `overwrite`, `rename`, or `fail`, optionally
  applying to following unresolved conflicts.

### mTLS listener and certificate lifecycle

- Separate peer/data listener on `MTLS_ADDRESS`.
- TLS 1.3 with mandatory client certificates.
- Certificates are accepted only when signed by the stable Ed25519 identity of
  an exact trusted peer.
- Dedicated `JOLT_KEYS_DIR/mtls` material with restrictive permissions.
- Safe certificate metadata without exposing private keys.
- `active`, `next`, and `previous` certificate slots.
- Atomic promotion, configurable grace window, rollback during grace, and
  persistent serial revocation.
- Preparing a certificate creates a durable per-peer rollout with `pending`,
  `acknowledged`, and `failed` delivery diagnostics.
- Only the identity-bound public certificate is exported for distribution;
  private key material never leaves the source node.
- Peers validate the public certificate against the exact trusted `node_id` and
  stable Ed25519 fingerprint before recording a durable acceptance.
- The Control Tower distributes pending certificates directly to registered
  peers, records acknowledgements or safe failure reasons back on the source
  node, and reports peers still awaiting delivery.
- The Control Tower UI shows rollout totals and requires both `sudo` and
  `execute` on the node mTLS key path for prepare, distribute, and promote
  actions. Promotion warns when acknowledgements are still pending.
- Correlation-aware certificate lifecycle events.
- Authenticated lifecycle API:
  - `GET /api/v1/crypto/mtls`
  - `GET /api/v1/crypto/mtls/rollout`
  - `POST /api/v1/crypto/mtls/rollout/deliveries`
  - `POST /api/v1/crypto/mtls/rotate`
  - `POST /api/v1/crypto/mtls/promote`
  - `POST /api/v1/crypto/mtls/rollback`
  - `POST /api/v1/crypto/mtls/revoke`
  - `PATCH /api/v1/peers/{peerNodeID}/mtls/rollout`

### Peer heartbeat

- Identity-authenticated `GET /peer/v1/heartbeat` on the mTLS listener.
- Periodic direct heartbeat for trusted peers.
- Public peer endpoint advertised through `MTLS_PUBLIC_ENDPOINT` and persisted
  during pairing.
- Configurable interval, timeout, and failure threshold through:
  - `PEER_HEARTBEAT_INTERVAL`
  - `PEER_HEARTBEAT_TIMEOUT`
  - `PEER_FAILURE_THRESHOLD`
- Successful checks persist `online`, reset consecutive failures, and update
  `last_seen_at`.
- Transient failures become `degraded` before reaching `offline`.
- Certificate mismatch and revocation are classified separately as
  `identity_changed` and `untrusted`.
- A single temporary network failure does not immediately mark a peer offline.
- Remote jobs that encounter an offline/degraded peer or a connection failure
  enter durable `waiting_peer` without consuming retry budget.
- A successful authenticated heartbeat atomically returns matching
  `waiting_peer` jobs to validation and wakes the local node queue.

### Direct node-to-node file transfer

- Destination-owned durable `transfer_pull` jobs.
- Control endpoint:
  `POST /api/v1/transfers/pull`.
- Source data endpoint:
  `GET /peer/v1/grants/{grantID}/content`.
- The destination connects directly to the source mTLS endpoint; file bytes do
  not pass through the Control Tower.
- Source and destination grants are revalidated against the exact certificate
  identity before each operation.
- Source paths and destination paths remain relative to their grants and mounts.
- Range requests resume from the last fully synced destination checkpoint.
- Deterministic partial files survive pause, interruption, and retry.
- Source size/mtime ETags are persisted and checked before resumed requests.
- A final streamed ETag trailer detects source changes during the transfer before
  the partial is published.
- Optional SHA-256 is obtained over the authenticated channel and checked against
  the complete destination partial before atomic rename.
- Direct file jobs support `skip`, `overwrite`, `rename`, `fail`, and `checksum`
  conflict policies when permitted by the destination grant.
- `checksum` skips equal destination content and replaces differing content.
- Job idempotency prevents duplicate transfer jobs after repeated client requests.
- Pause, resume, cancel, retry, byte progress, rate, ETA, events, and cleanup use
  the same durable job engine as local copies.

### Direct node-to-node directory transfer

- Peer-facing grant-scoped manifests are available only over the authenticated
  mTLS listener.
- Manifest responses are paginated and include safe relative paths, type, size,
  modification time, and optional SHA-256 checksums.
- The destination fetches all manifest pages directly from the source and
  produces an itemized comparison before queueing a transfer.
- Remote directory previews expose aggregate bytes, file counts, copy/skip/
  rename/conflict counts, and at most 500 item details through the HTTP API.
- Job creation atomically persists the job, idempotency key, and every planned
  item before nodes can claim it.
- Files are streamed directly between nodes, while directory creation and
  conflict decisions execute from the durable item plan.
- Completed and skipped files are preserved across retry and resume; incomplete
  files continue from per-item, fully synced chunk checkpoints.
- Failed remote jobs retry only unfinished items, and cancellation removes only
  incomplete deterministic partials.
- Remote directory conflicts support `ask`, durable
  `waiting_user_decision`, per-item overrides, and applying a decision to later
  conflicts.
- Remote directory progress reports aggregate bytes, completed files, failed
  files, speed, ETA, events, and item-level results.
- The Control Tower node proxy and frontend API client expose both preview and
  execution endpoints without proxying file bytes.

## Partially implemented

### Streaming uploads

- Upload bodies are streamed, written to temporary files, atomically published,
  and represented in durable history.
- The incoming request body is not persisted as resumable chunks.
- An interrupted upload must currently be restarted from the beginning.

### Direct remote transfer UX and protocol

- The Control Tower provides a visual peer/grant source browser and destination
  picker for direct file and directory pulls.
- The regular file-browser `Copy` action also exposes the destination node and
  authorized destination mount, so local and node-to-node copies share one
  operator workflow.
- The picker is constrained to enabled, peer-matched grants and only exposes
  conflict policies allowed by the destination grant.
- Directory transfers show the itemized aggregate preview before the job is
  queued; file transfers can be queued directly from the same workflow.
- Direct transfer currently supports one regular file per job.
- Remote mount/grant discovery through the peer data plane is not implemented.

### Configuration and observability

- Effective immutable configuration can be read without exposing secrets.
- Environment variables configure the current runtime.
- Mutable configuration update APIs, persisted desired/effective/observed layers,
  and file-based configuration precedence are not complete.
- Health, job events, peer state, mount diagnostics, and structured request logs
  exist.
- A recent-log query API and richer Control Tower diagnostics are pending.

### Disaster recovery

- Recovery behavior for interrupted jobs and deterministic partials exists.
- Operational recovery guidance exists in `docs/DISASTER_RECOVERY.md`.
- Offline `snapshot` subcommands are available in both binaries.
- Both services hold an exclusive instance lock and refuse an offline snapshot
  while the corresponding process is active.
- Snapshots run SQLite integrity checks, consolidate the database without
  transient WAL/SHM files, and atomically publish a mode-`0600` tar.gz archive.
- Node snapshots keep data and cryptographic keys in one backup set and record
  the `node_id`, fingerprint, file modes, sizes, and SHA-256 hashes in a
  manifest.
- Control Tower snapshots explicitly exclude the external encryption key and
  record that fact in their manifest.
- Offline node restore diagnostics validate SQLite integrity, identity
  public/private correspondence, optional expected identity, mounts, peers,
  grants, non-terminal jobs, durable checkpoints, and bounded partial-file
  discovery without mutating restored state.
- Missing mounts, target-type divergence, unreadable paths, and read-write
  mounts that are no longer writable receive explicit unavailable, divergent,
  or degraded diagnostics.
- Offline Control Tower restore diagnostics validate SQLite integrity, foreign
  keys, the external encryption key, enabled Argon2id administrators, encrypted
  node credentials, and unresolved connection secrets without exposing their
  plaintext.
- Both diagnostic commands require the service instance lock, emit structured
  JSON, and return a non-zero status for blocking inconsistencies.
- Offline emergency credential recovery atomically replaces a node operational
  token, updates the matching encrypted Control Tower credential, or restores a
  named Control Tower administrator. Commands require explicit target
  confirmation and the exclusive service lock, validate the Control Tower
  encryption key, revoke browser sessions during admin recovery, emit only
  secret-free JSON, and persist correlation-aware recovery state or audit.

### Control Tower database encryption

- Admin passwords use Argon2id.
- Node tokens and pending invite material retain field-level AES-GCM protection.
- SQLCipher encrypts the full SQLite database, including schema, indexes,
  sessions, policies, roles, and audit records.
- The external key is supplied as raw 256-bit key material and is applied before
  the first database page access. SQLCipher memory security is enabled.
- New databases are encrypted from creation. Existing plaintext databases fail
  closed until the offline `encrypt-database` command exports, verifies, and
  atomically replaces them.
- Consistent snapshots and restore diagnostics unlock with the external key;
  snapshot database files remain encrypted and wrong keys fail closed.

## Remaining work

### Priority 1 — remote directories and peer-aware jobs

- Completed. Further remote discovery work is tracked under Priority 5.

### Priority 2 — Control Tower authorization

- Roles containing policies and role assignment to users are complete.
- Exact grant-to-mount authorization for remote transfer planning and execution
  is complete. The Control Tower resolves both grants from their owning nodes,
  validates their peer binding, direction, enabled state, and read/write
  permission, then evaluates source read and destination create against the
  exact mount-level Node Paths before forwarding the request.
- Extend route-to-Node-Path coverage as new node resources are added.
- Applied policy context is exposed by the paginated Control Tower audit API
  and visual Activity view, including evaluated Node Path, capability, decision,
  actor type, correlation ID, and every policy ID used by the decision.

### Priority 3 — peer and credential lifecycle

- Explicit peer removal/revocation and immediate communication blocking are
  complete, including Control Tower RBAC and UI confirmation.
- Peer address and mTLS endpoint updates are complete, including validation,
  Control Tower RBAC/UI, and authenticated health revalidation.
- Signed stable-identity handover is complete: monotonic epochs, old/new
  dual-signatures, exact-state conditional application, replay rejection,
  bounded old/new overlap with automatic previous-key retirement, automatic
  Control Tower distribution, pending-peer reporting, later chain
  redistribution, restart-safe mTLS regeneration, and manual
  `identity_changed` recovery when continuity proof is unavailable.
- Coordinated operational-token rotation is complete. The node prepares a
  SHA-256-only staged credential, the Control Tower atomically replaces its
  AES-GCM-encrypted token, and a commit authenticated by the new token
  invalidates the previous environment credential without exposing either
  token through API responses.
- Peer-facing certificate rollout/acknowledgement diagnostics are complete,
  including durable source status, exact-identity validation on the receiving
  peer, Control Tower orchestration, RBAC, and UI visibility.

### Priority 4 — recovery and hardening

- Consistent node and Control Tower snapshot commands are complete, including
  active-instance exclusion, SQLite integrity validation, atomic archives,
  restricted output permissions, and per-file SHA-256 manifests.
- Restore diagnostics for identity, mounts, grants, jobs, and partial files are
  complete for both node and Control Tower.
- Missing/divergent mount detection after restore is complete for missing
  paths, changed target type, readability, and requested writability.
- Full Control Tower SQLCipher encryption is complete, including encrypted
  creation, wrong-key rejection, encrypted snapshots, restore diagnostics, and
  explicit offline migration from legacy plaintext SQLite.
- Emergency operational-token and Control Tower administrator recovery are
  complete, including coordinated offline node/Control Tower token replacement,
  exact target confirmation, session revocation, and audit-safe output.
- **Partial:** the scalable load suite and its 64 MiB/128 MiB quick and
  5 GiB/50 GiB half profiles are implemented and verified. The opt-in 10 GiB
  file and 100 GiB/5,000-file full profile still requires execution and
  evidence on target infrastructure.
- **Implemented:** deterministic network interruption, controlled node-worker
  shutdown/restart, explicit validation/resume, pause, cancel, retry, missing
  peer/mount wake-up, and restore/partial diagnostics are covered across the
  acceptance and always-on automated suites.
- **Implemented:** configurable bandwidth limits per node/job for streaming
  uploads, local copies, and direct file/directory pulls.
- **Implemented:** configurable per-job file parallelism is complete for local
  and direct remote directory jobs. Per-file chunk parallelism is complete for
  both local copies and coordinated direct remote multi-range pulls.
- **Implemented:** no-progress detection and separate
  connect/read-idle/chunk/validation timeouts. Long-running jobs retain no
  global timeout by default.

### Priority 5 — API and operational completeness

- Recent structured logs through the node API and Control Tower.
- Mutable configuration API with audit, idempotency, atomic persistence, and
  secret masking.
- Richer node capability and diagnostics views.
- Remote files/grants discovery suitable for automation and agents.
- Complete OpenAPI schemas and examples for all error and event payloads.

## Future roadmap — post-MVP

- Import externally issued or pre-provisioned mTLS certificates, including
  secure private-key ingestion, chain validation, renewal ownership, and
  compatibility with the existing rollout, grace, rollback, and revocation
  lifecycle.

## Current verification

Current automated tests and build verification cover:

- traversal and symlink escape protection;
- mount permissions and protected internal directories;
- atomic upload and local copy behavior;
- local manifests, conflict policies, overrides, checksums, and durable resume;
- job queue recovery, controls, retries, progress, ETA, SSE, and events;
- stalled-job cancellation and configurable connection, idle-read, chunk, and
  validation deadlines without a global job timeout;
- persisted per-job and shared node-wide bandwidth enforcement, including
  concurrent limiter composition and pacing-aware progress watchdogs;
- bounded local/remote directory file workers with persisted parallelism,
  independent item checkpoints, aggregate progress, and restart-safe fallback;
- bounded local and direct-remote parallel chunk batches with concurrent ranges,
  contiguous durable checkpoints, checksum verification, and atomic
  publication;
- the opt-in quick load profile with a checkpointed 64 MiB interrupted file and
  a 128 MiB/1,024-file parallel directory, plus a verified 5 GiB/50 GiB
  half-profile and configurable 10 GiB/100 GiB full-profile targets;
- truncated remote multi-range responses with automatic retry from the previous
  completely synced batch, without re-fetching earlier ranges;
- pairing, exact fingerprint confirmation, grants, and cluster isolation;
- peer revocation, atomic grant disabling, related-job cancellation, and
  Control Tower delete-capability enforcement;
- peer control/mTLS endpoint updates with safe URL validation and heartbeat
  revalidation;
- stable node identity rotation, previous-key archival, signed epoch handover,
  tamper/replay rejection, Control Tower delivery, mTLS regeneration, and
  manual `identity_changed` recovery;
- mTLS certificate persistence, exact-peer handshake, rotation, rollback, and
  revocation;
- mTLS public-certificate rollout validation, durable peer acceptance,
  acknowledgement persistence, and Control Tower distribution;
- consistent node and Control Tower snapshot creation, active-instance locking,
  SQLite consolidation, and archive manifest validation;
- offline node and Control Tower restore diagnostics, including identity/key
  validation, mount/grant/job/partial checks, external-key verification, and
  non-zero blocking reports;
- heartbeat failure tolerance;
- `waiting_peer` transitions, retry-budget preservation, and heartbeat wake-up;
- direct two-node mTLS file transfer with exact source/destination grants;
- resumable remote destination chunks, concurrent bounded mTLS ranges, exact
  per-request ETag/range validation, and atomic final publication;
- paginated remote directory manifests, itemized plans, nested directory
  execution, durable per-file results, and aggregate progress;
- remote directory `ask` conflicts and item override continuation;
- exact source/destination grant-to-mount RBAC enforcement before remote
  transfer planning and execution;
- Control Tower authentication/security primitives and frontend production build.
- SQLCipher encrypted creation, wrong-key rejection, plaintext migration,
  encrypted snapshot verification, and keyed restore diagnostics.
- Linux/arm64 Alpine production-image compilation with the SQLCipher CGO
  toolchain and final-image runtime loading.
- Control Tower audit query authorization, filtering, cursor pagination, and
  applied-policy decision context.
- offline emergency node-token replacement, matching Control Tower credential
  recovery, and administrator password recovery with instance-lock enforcement.
