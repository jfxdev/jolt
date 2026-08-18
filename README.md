# jolt

`jolt` is split into two independent products:

```text
node/       API-only filesystem node and transfer engine
control/    authenticated web Control Tower and node orchestrator
docs/       product requirements and operational documentation
```

The node owns mounts, files, jobs, identity, and operational state. The Control
Tower never reads a node database or host filesystem; it only calls the node's
authenticated API.

## Overview

`jolt` is a self-hostable platform for managing files across a fleet of storage
nodes and moving data **directly between them** over authenticated, mutually
verified connections. Think of it as a NAS control plane with first-class,
resumable node-to-node transfers.

Two products, one boundary:

- **Node** — a single Go binary that exposes a token-authenticated HTTP API over
  its mounts. It owns the source of truth: mounts, files, durable jobs,
  checkpoints, its own Ed25519 identity, trusted peers, and transfer grants. It
  runs a second TLS 1.3 listener for direct peer traffic and never trusts the
  Control Tower with host paths or private keys.
- **Control Tower** — a Go service with a React web UI that authenticates
  operators, enforces RBAC, registers nodes, orchestrates pairing and transfers,
  and proxies node APIs. It stores only its own state (users, sessions, encrypted
  node tokens, audit) in a full-page SQLCipher-encrypted database, and never
  proxies file bytes for direct node-to-node transfers.

### Core capabilities

- **Filesystem API** — traversal/symlink-safe listing, metadata, Range downloads,
  atomic streaming uploads, mkdir, copy, move/rename, delete, with read-only
  enforcement and mount diagnostics.
- **Durable jobs** — a persistent SQLite queue with atomic claims, resumable
  16 MiB checkpoints, pause/resume/cancel/retry with backoff, per-file and
  per-chunk parallelism, node- and job-level bandwidth limits, and live SSE
  progress with ETA.
- **Direct node-to-node transfers** — destination-pull over mTLS with exact-peer
  grants, Range resume, per-range ETag/`If-Match` revalidation, optional SHA-256,
  atomic publish, and paginated directory manifests with conflict decisions.
- **Trust and identity** — human-confirmed fingerprint pairing, revocable
  one-time invites, bilateral trusted peers, signed stable-identity rotation
  (dual-signed epoch handover) propagated by the Control Tower, and rotating
  mTLS certificates with rollout diagnostics.
- **Authorization** — Argon2id logins, sessions, service accounts and API keys,
  reusable access groups, and Node Path RBAC policies with `deny` precedence
  evaluated before any request reaches a node.
- **Recovery** — offline consistent snapshots with integrity checks and SHA-256
  manifests, restore diagnostics, and emergency credential/admin recovery.

### Tech stack

- **Backend:** Go 1.24 (node and Control Tower), SQLite (node), SQLCipher
  (Control Tower), Ed25519 identities, TLS 1.3 mTLS.
- **Frontend:** React 19 + Vite, Radix UI / shadcn components, Tailwind CSS,
  React Router.
- **Deployment:** Docker images with LinuxServer-style `PUID`/`PGID`/`UMASK`
  privilege drop; root Compose stack wiring both products.

### Documentation

- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) — product requirements.
- [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) — implementation status.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — findings, gaps, and prioritized roadmap.
- [`docs/REMEDIATION.md`](docs/REMEDIATION.md) — code-level fixes for findings.
- [`docs/DISCOVERY.md`](docs/DISCOVERY.md) — analysis backlog for the next pass.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — attack surface and unauthenticated threat analysis.
- [`docs/ACCESS_CENTER.md`](docs/ACCESS_CENTER.md) — design for a dedicated authorization/access page.
- [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) — load and fault-injection profiles.
- [`docs/DISASTER_RECOVERY.md`](docs/DISASTER_RECOVERY.md),
  [`docs/REVERSE_PROXY.md`](docs/REVERSE_PROXY.md) — operations.

## Start both services

Create a `.env` file or export three secrets:

```sh
export CONTROL_TOWER_TOKEN='replace-with-a-long-random-node-token'
export CONTROL_TOWER_ADMIN_PASSWORD='replace-with-a-long-admin-password'
export CONTROL_TOWER_DB_ENCRYPTION_KEY='replace-with-at-least-32-random-characters'
docker compose up --build
```

Open `http://localhost:8090`, sign in as `admin`, and connect the example node:

- Name: `NAS home`
- Endpoint: `http://jolt-node:8080`
- Token: the value of `CONTROL_TOWER_TOKEN`

The node API and Swagger remain available separately at `http://localhost:8080`
and `http://localhost:8080/docs`.

## Docker ownership

Both images follow the LinuxServer-style ownership settings: `PUID`, `PGID`,
and `UMASK`. On startup, the entrypoint prepares its internal volumes as root,
then runs the application with the requested numeric UID and GID. New files
created by the node therefore belong to the configured host account.

Set the values in `.env` before starting the stack. On Linux hosts, the usual
values are available with `id -u` and `id -g`:

```dotenv
PUID=1000
PGID=1000
UMASK=002
```

The default Compose mount at `/mnt/files` is reconciled recursively at startup
using `JOLT_OWNED_PATHS`. If you bind additional directories that will become
node mounts, include each container path as a colon-separated list:

```dotenv
JOLT_OWNED_PATHS=/mnt/files:/mnt/archive
```

Do not set Docker's `user:` override: it prevents the entrypoint from fixing
ownership. A non-root launch must already match `PUID:PGID`, otherwise the
container fails immediately with a configuration error. For NFS root-squash or
other filesystems that reject `chown`, set the ownership on the host first.

For local multi-node testing, start three isolated nodes with:

```sh
make nodes
```

They run as `nodeA`, `nodeB`, and `nodeC` on ports `18081`, `18082`, and
`18083`, using independent state under [`node/testdata`](node/testdata/README.md).

## Node

The implementation under [`node/`](node/) provides:

- stable Ed25519 identity and fingerprint;
- token-authenticated HTTP API;
- SQLite persistence for mounts, jobs, and idempotency;
- traversal- and symlink-safe API filesystem;
- range downloads and atomic streaming uploads;
- mkdir, local copy, move, rename, and delete as persistent jobs;
- resumable local copies with durable 16 MiB chunk checkpoints, configurable
  through `COPY_CHUNK_SIZE_BYTES`;
- separate connection, idle-read, chunk, and validation deadlines, plus
  no-progress detection without a global timeout for long-running jobs;
- shared node-wide and persisted per-job bandwidth limits for uploads, local
  copies, and direct node-to-node pulls;
- configurable per-job file worker pools for local and remote directory copies,
  while directory creation and interactive conflicts remain ordered;
- direct node-to-node file pulls over mTLS, with exact-peer grants, range resume,
  durable chunk checkpoints, optional SHA-256, and atomic destination publish;
- paginated, memory-bounded remote directory manifests, destination-side
  previews, durable per-file plans, chunk resume, retries, and manual conflict
  decisions;
- periodic authenticated peer heartbeat with persisted online/degraded/offline
  state and consecutive-failure tolerance;
- durable `waiting_peer` jobs that wake after an authenticated heartbeat without
  consuming their retry budget;
- durable `waiting_mount` jobs that wake after lightweight mount diagnostics
  pass again, also without consuming retry budget;
- restored jobs held in `waiting_validation` until an operator explicitly
  requests revalidation and resume;
- conflict previews, checksum decisions, and manual per-item overrides for
  copy jobs that require operator input;
- mount permission diagnostics and read-only enforcement;
- offline, lock-protected consistent snapshots with SQLite integrity checks,
  atomic archives, and SHA-256 manifests;
- read-only post-restore diagnostics for identity, mounts, grants, peers, jobs,
  and resumable partial files;
- separate data and key volumes, `PUID`, `PGID`, and `UMASK`.

Long-running transfer safeguards can be tuned with
`TRANSFER_CONNECT_TIMEOUT`, `TRANSFER_IDLE_READ_TIMEOUT`,
`TRANSFER_CHUNK_TIMEOUT`, `JOB_VALIDATION_TIMEOUT`, and
`JOB_NO_PROGRESS_TIMEOUT`. Their defaults are `10s`, `60s`, `5m`, `2m`, and
`10m`, respectively. A job has no global duration limit by default; only a
stalled phase or chunk is canceled and retried according to the job policy.

Set `NODE_BANDWIDTH_LIMIT_BYTES_PER_SECOND` to cap aggregate incoming copy and
upload traffic across concurrent jobs (`0` disables the node-wide cap). Copy
and transfer request payloads may additionally set
`bandwidth_limit_bytes_per_second`; streaming uploads accept the same value as
a query parameter. When both limits are present, both are enforced.

`MAX_PARALLEL_FILES_PER_JOB` sets the default number of files copied
concurrently inside each directory job (default `2`, maximum `32`). Local-copy
and remote-pull request payloads can override it with `max_parallel_files`.
The selected value is persisted with the job and reused after retries or
restarts.

`MAX_PARALLEL_CHUNKS_PER_FILE` controls concurrent local or direct-remote
ranges within each file (default `1`, maximum `16`). Copy and remote-pull
requests may override it with `max_parallel_chunks`. Parallel chunks are
executed in bounded batches; the partial file is synced and its durable
checkpoint advances only after the entire contiguous batch completes. Remote
ranges repeat exact-peer mTLS, grant, size, `Content-Range`, and ETag validation
before a destination can be published.

Run it without Docker:

```sh
cd node
CONTROL_TOWER_TOKEN=development-token go run ./backend/cmd/jolt-node
```

Run the opt-in load and fault-injection acceptance profile:

```sh
make acceptance
```

Use `make acceptance-half` or `make acceptance-full` only on a disposable host
with sufficient time and disk space. They perform 5 GiB/50 GiB and
10 GiB/100 GiB scenarios, respectively. See
[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) for profiles, overrides, and the fault
matrix.

For multi-node operation, set `MTLS_PUBLIC_ENDPOINT` to the HTTPS endpoint peers
can reach, for example `https://nas-home.example.test:8443`. Heartbeat behavior
can be tuned with `PEER_HEARTBEAT_INTERVAL`, `PEER_HEARTBEAT_TIMEOUT`, and
`PEER_FAILURE_THRESHOLD`.

## Control Tower

The implementation under [`control/`](control/) provides:

- separate Go service and responsive React 19 interface;
- first-boot admin bootstrap;
- Argon2id password hashing;
- persistent HTTP-only, SameSite sessions;
- administrative user lifecycle management with session revocation, last-admin
  protection, and preserved audit history;
- API Keys (service accounts) with opaque bearer credentials, one-time token
  disclosure, optional expiry, rotation, individual revocation, immediate
  disable, and actor-aware audit records;
- reusable access groups, managed in the Control Tower, that bind API Keys to
  an explicit set of nodes and shared Node Path policies for filesystem, jobs,
  grants, and direct node-to-node transfers;
- Node Path policies with explicit capabilities, deny precedence, assignments
  to users and service accounts, pre-proxy enforcement, permission-aware UI
  actions, and detailed authorization audit context;
- mandatory external encryption key and full-page SQLCipher encryption;
- additional AES-256-GCM field protection for persisted node tokens and pending
  connection secrets;
- node registry, online/offline/untrusted status, and diagnostics;
- admin-only removal of node registrations, without deleting files, mounts,
  jobs, peers, or grants from the node itself;
- creation of node mounts from the Control Tower, with path and permission validation
  still enforced by the node;
- delivery of expiring `one_sided` or `dual_channel` pairing requests between
  registered nodes;
- human review with exact fingerprint confirmation, rejection, one-time invite
  consumption, and bilateral peer persistence;
- node-owned Transfer Path Grants bound to existing mounts and exact trusted
  peers, managed from the Control Tower without copying grant state into it;
- a grant-scoped visual source browser, destination picker, and directory
  preview for direct node-to-node transfers;
- destination node and authorized mount selection directly in the regular file
  browser copy workflow;
- navigation of remote mounts and files through node API routes;
- streaming upload/download and local file operations through nodes;
- job history and correlation-aware audit records.
- offline consistent Control Tower snapshots that keep the database encrypted
  and explicitly exclude the external database encryption key.
- offline restore diagnostics for database integrity, the external encryption
  key, enabled administrators, and encrypted operational credentials.

Run it for development:

```sh
cd control/frontend
npm install
npm run build

cd ..
CGO_ENABLED=1 \
CONTROL_TOWER_ADMIN_PASSWORD=development-password \
CONTROL_TOWER_DB_ENCRYPTION_KEY=development-encryption-key-32chars \
go run ./cmd/jolt-control
```

The Control Tower defaults to `http://localhost:8090`.
Legacy plaintext Control Tower databases must be migrated offline before boot;
see [disaster recovery](docs/DISASTER_RECOVERY.md#encrypting-an-existing-control-tower-database).

### API Keys and access groups

An API Key is the bearer credential of a **service account**. The service
account is the automation identity that owns the key, and it must be associated
with one or more active access groups. A key does not have independent groups:
all keys issued to the same service account use the same effective access.

Each access group defines two reusable boundaries:

- **Nodes**: the explicit allow-list of nodes that its associated API Keys may
  address through the Control Tower proxy.
- **Policies**: Node Path RBAC rules for files, jobs, grants, peers, and
  transfers.

The effective access of a service account is the **union** of nodes and
policies from all of its active groups, plus any policies assigned directly to
the service account. A request must still satisfy both the node allow-list and
an applicable policy. Therefore, a policy that permits `nodes/node-a/...` does
not grant access if no associated group includes `node-a`.

An API Key without an active group is rejected during authentication. Disabling
or removing a group removes only that group's grants. If it was the final active
group of a service account, all of that account's API Keys stop authenticating
until another active group is associated.

Typical setup in the Control Tower:

1. Create policies for the intended filesystem and transfer actions.
2. Create one or more groups, assign their nodes and policies.
3. Create a service account and select its groups.
4. Copy the issued API Key once and use it as `Authorization: Bearer <key>`.
5. Rotate or revoke individual keys without changing the service account's
   group memberships.

The Control Tower exposes complete CRUD for this model under
`/api/v1/control-tower`:

- `GET`, `POST`, `PATCH`, `DELETE /access-groups`
- `GET`, `PUT /access-groups/{groupID}/nodes`
- `GET`, `PUT /access-groups/{groupID}/policies`
- `GET`, `POST`, `PATCH`, `DELETE /service-accounts` and the nested `/tokens`
- `GET`, `PUT /service-accounts/{serviceAccountID}/groups`

Policies remain the operation boundary. For a key that copies files between two
group nodes, grant `execute` on `nodes/<destination>/transfers`, `read` on the
precise source mount, and `create` or `write` on the destination mount. File
capabilities alone never authorize a transfer. The Control Tower validates the
API Key's active groups, policies, source and destination nodes, mounts, and
transfer grants before forwarding a request to either node.

## Security boundaries

- Absolute host paths are accepted only when an administrator registers a mount
  directly with a node; they are never returned to Control Tower clients.
- Node tokens are encrypted before persistence and never returned by the API.
- The Control Tower refuses to boot without an admin password and encryption key.
- The keys directory cannot overlap a configured filesystem mount.
- The peer port is a separate TLS 1.3 listener and requires an mTLS certificate
  cryptographically bound to an exact trusted node identity.
- Rotating mTLS material is stored under `JOLT_KEYS_DIR/mtls` with
  `active`/`next`/`previous` metadata and persistent serial revocation. Safe
  lifecycle metadata and rotate/promote/rollback/revoke operations are exposed
  through the authenticated node API.
- Browser mutations use strict same-site cookies and origin validation.
- Pairing requests do not create trust before explicit approval. Approval creates
  peers on both nodes, but never creates mounts or Transfer Path Grants.
- In production behind HTTPS, set `CONTROL_TOWER_SECURE_COOKIES=true`.

The Control Tower database schema, sessions, policies, audit records, indexes,
and encrypted credential fields are stored inside a full-page SQLCipher
database. The external key is never stored in the database or its snapshots.

See [implementation status](docs/IMPLEMENTATION.md), [reverse proxy](docs/REVERSE_PROXY.md),
and [disaster recovery](docs/DISASTER_RECOVERY.md).
