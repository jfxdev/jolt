# Node configuration and encrypted YAML state

The node has no SQL runtime. The Control Tower retains its existing database.
This release requires a new node installation: `jolt.db`, `jolt.db-wal`,
`jolt.db-shm` or `jolt.db-journal` in the data directory stop startup. No legacy
files are deleted or converted. Keep previous installations and their backups
separate; reverting to an old binary requires its old data, not the YAML state.

## Configuration

The mandatory file is selected by `--config`, then `JOLT_CONFIG_FILE`, then
`./node.yaml`. Docker uses `/etc/jolt/node.yaml`, mounted read-only. See
`node/node.docker.yaml` and `node/node.yaml` for container and local examples.
Parameters use the existing environment names in lowercase, except
`data_dir` and `keys_dir`. Durations are strings such as `10s` or `5m`.
Runtime parameter environment variables no longer override the file.
`CONTROL_TOWER_TOKEN`, optional `METRICS_TOKEN` and the encryption key remain
external. Docker ownership variables remain deployment settings.

The parser accepts one document, version 1, with known fields only. Duplicate
keys, anchors, aliases, merges, invalid ranges and unknown fields fail startup.
Mount paths must be absolute and must not overlap configuration, data or keys.
The node never creates a missing mount directory. It reports it as unavailable
and pending jobs wait for their destination mount to return.

Mounts require `id`, `name`, `local_path` and `mode` (`read_only`/`read_write`).
Optional `hidden_patterns` contains up to 64 case-insensitive basename globs,
such as `['.env', '*.pem', 'private-keys']`. Patterns apply to every path
component, including directories, and are validated at startup. Matching
entries are excluded from listings, searches, archives and transfer manifests;
direct reads return 404 and destinations with hidden names are rejected.
Recursive deletes and moves fail if a protected descendant exists. Existing
destinations containing protected descendants cannot be overwritten. This is
name-based filtering, not content inspection; host-side access is unaffected.
Moving a directory between nodes requires both peers to support protected-move
validation. Older peers must be upgraded before a move; copy remains available.

Optional `canary_paths` contains up to 64 normalized, mount-relative file paths
that the operator has populated with decoy data. Reads and metadata requests,
including archives containing a decoy, produce an internal signal consumed by
the Control Tower. A canary does not override hidden patterns or access policy;
never place real credentials in a decoy.

Optional `trash: {enabled: true, retention_days: 30}` on a `read_write` mount makes a
delete (a file, or a folder with `recursive`) move the entry to a hidden `.jolt-trash`
folder inside the mount instead of removing it. The move is one atomic rename on the
same filesystem; an entry on another filesystem than the mount (a nested mount point)
is refused rather than deleted. `retention_days` defaults to 30 and goes up to 365; the
node purges what is older, checking every ten minutes. The folder is invisible to
listings, searches, archives, disk usage and direct reads, and the entries are restored
or purged through `/api/v1/mounts/{id}/trash` (the Control Tower exposes them in the
interface). Restoring puts the entry back at its old path and refuses if the name is
taken, if the folder it was in is gone, or if the name has since become hidden. An empty folder
deleted without `recursive` is removed for good. Records live in the encrypted state, which an older node
refuses to open once it holds one; after a crash the node finishes or undoes whichever
step was interrupted at startup. `max_bytes` (optional, 0 or omitted means no cap) bounds the bytes of file content the trash holds; a
delete that would go over it fails with `trash_full` instead of purging anything early. Trashed entries
still use disk until purged, and a
hard-linked file frees no space until then. The trash is not a backup: host-side access
is unaffected, and an entry purged or past its retention is gone.

Use explicit `enabled: true` and `published: true` when desired. Grants require
`id`, `peer_node_id`, `mount_id`, a mount-relative `path`, `direction` and compatible
`permissions`. Omitted `enabled`/`published`/permission booleans are false.
Receiving grants default to conflict policy `fail`; send grants have no conflict
policy. Grants can be declared before pairing and become effective only after
trust and filesystem checks succeed. Trust never grants access by itself.

An optional grant `exclude` lists up to 64 case-insensitive basename globs.
Sending grants omit matching files and directories before manifest pagination
and refuse direct reads or moves of protected content. Receiving grants filter
excluded destination entries from copies, refuse moves involving them, and
revalidate persisted job destinations on resume and before publication. Upgrade
nodes before adding this field; older versions do not enforce the restriction
and may refuse the configuration.

IDs bind permanently to the mount root or the grant's peer/mount/path/direction.
Changing that identity requires a new ID. Removing and readding the same ID does
not erase its binding. A revoked peer's existing grant IDs remain blocked even
after restart or another pairing. Reauthorize deliberately with a new grant ID.

Changes apply only on restart. A valid configuration is applied as one audited
transaction. The node never edits the operator's file. The Control Tower shows
“Gerenciado por arquivo”; resource mutation APIs respond with HTTP 409 and code
`configuration_managed_by_file`. Reads include effective authorization, and grants
include `configured_enabled` and `inactive_reason`.

## Managed certificates

By default (`tls_mode: manual`) the operator brings the node's API certificate
(`api_tls_*`) and its signing keys (`authorization_public_keys`). With
`tls_mode: managed` the Control Tower's own certificate authority does both:

```yaml
tls_mode: managed
api_public_endpoint: https://node.example:8080   # what the Control Tower reaches this node at
```

`api_public_endpoint` must be an absolute `https` URL with no path, user or query.
Managed mode refuses `api_tls_cert_file`, `api_tls_key_file` and
`api_tls_client_ca_file`, and `api_public_endpoint` without it. The node needs no
`CONTROL_TOWER_TOKEN`: it chooses an operational token when it enrolls.

The first start needs `JOLT_JOIN_TOKEN` (or `JOLT_JOIN_TOKEN_FILE`), a token an
administrator made in the Control Tower. The node fetches the root without
trusting the connection, continues only if its SHA-256 is the one in the token,
and sends the secret over a connection that must chain to that root. It then
keeps in its encrypted state the trust bundle it verified, its API certificate and
key, and the hash of its operational token, in one write; the first write raises
the state's security version, so an older binary cannot open it. Later starts
ignore the token.

An enrolled node serves HTTPS with its certificate, renews it when the Control
Tower asks (the key is made on the node and never leaves it), adopts a trust
bundle only if it is newer, keeps a root it already had and is signed by a key the
previous bundle listed, and merges the bundle's signing keys with
`authorization_public_keys` (the YAML wins on a clash). It advertises
`managed_tls_v1` and exposes `/api/v1/crypto/trust-bundle` and `/api/v1/crypto/api-cert`.
A client certificate, if offered, must come from that authority, be named
`Jolt Control Tower` and not be revoked.

### `managed-only`

```yaml
tls_mode: managed-only
api_public_endpoint: https://node.example:8080
```

Everything in `managed` applies. In addition the Control Tower is authenticated by its
client certificate **alone**: a request needs a certificate that chains to the authority,
is named `Jolt Control Tower`, has client-auth usage and whose serial, and the serial of
anything in its chain, is not in the bundle's revoked list. The bearer token is
refused, even the correct one. The certificate is judged on every request against the
bundle in use, so a revocation reaches a connection that is already open. The routes
that rotate the operational token answer `409 operational_token_disabled`. `/metrics`
keeps its own token and `/health` keeps `public_health`.

Switch a node by changing `tls_mode` and restarting; switch back the same way, and the
operational token it chose when it enrolled works again. `GET /api/v1/crypto/trust-bundle`
reports `auth_mode` (`token` or `certificate`) and the serial, issuer serial and SHA-256
of the API certificate, which the Control Tower records.

## State and keys

The in-progress signed-authorization integration accepts a list of trusted
Ed25519 public keys in `node.yaml`, using a unique `id` and a standard Base64
encoding of the 32-byte public key. Multiple keys allow a rotation overlap:

```yaml
authorization_public_keys:
  - id: current
    key: "BASE64_ENCODED_32_BYTE_PUBLIC_KEY"
```

The Control Tower can load the corresponding unencrypted PKCS#8 PEM private
key from `CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE` with its matching
`CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID`. Both values must be supplied
together. The node can verify signed contexts for local listing, metadata,
content, search, disk usage, and ZIP reads and plans. Once all relevant nodes
have the correct public keys, `CONTROL_TOWER_SIGNED_LOCAL_READS=true` enables
signed contexts for these proxy reads. The option defaults to false and requires
the signing key; enabled reads fail closed if the node lacks the capability or
does not confirm enforcement. Public share listings, content and archives also
use signed contexts based on the creator's current permissions when this option
is enabled. Each signed response expires within 30 seconds,
including for a slow client. Other node operations reject signed contexts.
`CONTROL_TOWER_SIGNED_LOCAL_JOBS=true` makes local copies signed jobs: the
Control Tower derives the actor and policy context when the copy is created and
renews the lease every 10 seconds, rechecking the credential, groups and
policies each time. The node runs the copy under that lease, applies the filter
to every source and destination, and stops within 30 seconds of the last
renewal, keeping its checkpoints; a newer lease resumes it. Entries the filter
hides are skipped and reported only as a count. The `ask` conflict policy is
not supported for these copies. Deleting or moving a directory needs a plan the
operator confirms: the node counts what would change and, when the job runs,
checks the tree is unchanged before touching it. A node-to-node copy created through the logical transfer is planned by the
destination node under the same signed policy, so source entries the policy hides
are left out (and counted), the destination is checked for every item and again
right before a file is published, and the pull stops within 30 seconds of the
last renewal. It needs `authorization_public_keys` on the destination node and
node identities that match their registered IDs. Direct pulls are refused while
this mode is on. A move between nodes runs the same way but needs a plan: the
preview records a one-use confirmation, creating the move must present it, and a
fresh plan must still match it exactly. A move refuses a selection that has an
entry hidden from the actor, and its source cleanup deletes only what the lease
lets the actor delete. `CONTROL_TOWER_SIGNED_UPLOADS=true` separately
enables signed resumable upload creation, chunks, completion and abort. The
node requires fresh signed contexts for bound sessions and enforces filtering
before publication. An explicit resume or discard reauthorizes an old unbound
session or a new credential for the original actor after checking current
permissions. A stale reauthorization cannot replace a newer binding. The same
option also signs simple uploads, binding their destination, query and
idempotency key; streams must finish before authorization expires. The remaining
operations do not yet enforce these contexts. File-type policies remain
disabled until all required operations are integrated.

Generate a random key with `openssl rand -base64 32`, save it outside the data,
identity and configuration files, and supply exactly one of
`JOLT_STATE_ENCRYPTION_KEY` or `JOLT_STATE_ENCRYPTION_KEY_FILE`. Passphrases and
non-32-byte keys are rejected. Reuse the same key after restart. Losing the key
makes the encrypted state unrecoverable.

The state directory contains an authenticated `store.yaml`, a durable `head.yaml`, an optional
`manifest.yaml`, snapshot pages and immutable transaction files in `journal/`.
Each YAML envelope has a version, storage identity, kind, sequence, nonce and
AES-256-GCM ciphertext. Operational records and snapshots are serialized as YAML
inside the ciphertext. Identity JSON and certificate/key PEM files retain their
existing formats in the separate keys directory.

The first upload session persisted with an authorization identity upgrades the
authenticated state header to version 2 before writing that session. Nodes
that only understand version 1 refuse to open the upgraded state; existing
version 1 records remain readable by version 2. Signed upload admission is
disabled by default. Explicit reauthorization raises the header to version 3
before persisting its replay-protection revision, so version 2 readers also
refuse that state. Before activating these features, upgrade nodes and keep a
compatible pre-upgrade backup for rollback; older binaries that do not check
the envelope version cannot be made safe by this marker alone.

A transaction is acknowledged only after file synchronization, atomic rename
and directory synchronization, followed by a durable authenticated sequence head.
Missing confirmed transactions fail startup instead of silently reverting state. A single writer serializes mutations; a process
lock prevents concurrent instances. Jobs/items/idempotency, invite consumption,
peer revocation and token changes retain their atomic boundaries. An uncertain
write stops the node; it must reopen and authenticate persisted state.

After 1,024 transactions or 64 MiB the writer consolidates the current records
into encrypted pages and commits a new authenticated manifest before deleting
superseded journal files. Audit and job events use immutable snapshot segments
listed in the manifest: later compactions reuse those files and only encrypt
new history. No history is purged; idempotency is preserved. Each compaction
logs its duration and outcome. Ordered indexes by bucket, group and job state
avoid scanning lifetime history for event cursors and queued-job claims.
Payload caching is bounded to 16 MiB; indexes keep record locations, not the full
history. History and events are read in pages. Smaller copy chunks cause more
durable writes; the default remains 16 MiB.

## Backup and recovery

Stop the node before these commands:

```sh
jolt-node snapshot --config /etc/jolt/node.yaml --output /backups/node.tar.gz
jolt-node restore-diagnostics --config /etc/jolt/node.yaml
JOLT_RECOVERY_OPERATIONAL_TOKEN='<new random token>' \
  jolt-node recover-operational-token --config /etc/jolt/node.yaml \
  --confirm replace-operational-token
```

The same external state key is required. Snapshots contain public configuration,
committed encrypted state and existing identity/certificates. They exclude locks,
temporary files and unrelated files in the data directory. Keep the encryption
key separate. The contents of mounts still require their own backups.

Restore the data and keys directories and provision the saved public YAML;
`--data-dir`/`--keys-dir` overrides support inspecting a restored location.
Diagnostics open state read-only without creating directories or lock files,
changing permissions, or repairing the committed head. A directory lock excludes
concurrent runtime access even when a restored copy has no `.state.lock`.
Diagnostics authenticate every committed envelope, inspect mounts, peers, grants,
jobs and partials, and report unsafe conditions. Interrupted jobs require explicit
validation before resuming. The Control Tower credential must also be updated
when recovering the node operational token.

## Operational continuity

Upload sessions include publication intents and completion receipts in encrypted
state. Receipts follow `upload_session_ttl`, remain queryable by ID, and do not
reserve an active upload slot. Recovery compares SHA-256 content before accepting
a previously published destination. See [sharing and browsing](SHARING_AND_BROWSING.md)
for verification pages, directory cursors and job summaries.

Optional `upload_inspection` is disabled by default. When enabled, the node
inspects bytes before publishing both ordinary and resumable uploads:

```yaml
upload_inspection:
  enabled: true
  block_executables: true
  allowed_media_types: ["text/plain", "application/pdf"]
```

`block_executables` defaults to true and checks common executable and script
signatures. The optional MIME allowlist uses content sniffing; an empty list
allows any detected type. A rejection returns `upload_content_rejected`, removes
the partial and upload session, and preserves an existing destination. These
checks have false positives and negatives; they do not inspect contents inside
archives or guarantee that a file is safe. Configuration takes effect only
after restart. Rejection is persisted before cleanup; after an interruption,
the next request for that session or a new upload on the mount completes cleanup
without treating the rejected partial as a published file.

Control Tower node-token rotation records its encrypted candidate before calling
the node. Retrying after a lost response reconciles that same candidate. A node
rejects a different preparation while one is pending; repeating the committed
candidate is idempotent. This adds a Control Tower table and optional YAML state
fields, without changing the node configuration contract or encryption keys.
