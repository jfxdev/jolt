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
Use explicit `enabled: true` and `published: true` when desired. Grants require
`id`, `peer_node_id`, `mount_id`, a mount-relative `path`, `direction` and compatible
`permissions`. Omitted `enabled`/`published`/permission booleans are false.
Receiving grants default to conflict policy `fail`; send grants have no conflict
policy. Grants can be declared before pairing and become effective only after
trust and filesystem checks succeed. Trust never grants access by itself.

IDs bind permanently to the mount root or the grant's peer/mount/path/direction.
Changing that identity requires a new ID. Removing and readding the same ID does
not erase its binding. A revoked peer's existing grant IDs remain blocked even
after restart or another pairing. Reauthorize deliberately with a new grant ID.

Changes apply only on restart. A valid configuration is applied as one audited
transaction. The node never edits the operator's file. The Control Tower shows
“Gerenciado por arquivo”; resource mutation APIs respond with HTTP 409 and code
`configuration_managed_by_file`. Reads include effective authorization, and grants
include `configured_enabled` and `inactive_reason`.

## State and keys

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
