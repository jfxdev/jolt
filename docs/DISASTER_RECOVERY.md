# Disaster recovery

The node's data and keys volumes must be backed up together while the process is
stopped. The keys volume preserves the node identity; the data volume preserves
mount registrations, idempotency records, jobs, grants, and peers.

## Encrypting an existing Control Tower database

New Control Tower databases are created as SQLCipher databases and require the
external `CONTROL_TOWER_DB_ENCRYPTION_KEY` before the first page is written.
The service refuses to open a legacy plaintext SQLite database until it has
been migrated offline.

Create and verify a backup first, stop the Control Tower, then run:

```sh
docker compose run --rm --no-deps \
  -e CONTROL_TOWER_DB_ENCRYPTION_KEY \
  jolt-control \
  /usr/local/bin/jolt-control encrypt-database \
  --data-dir /var/lib/jolt-control \
  --confirm encrypt-control-database
```

The command requires the exclusive instance lock, exports the complete schema
and data into a temporary SQLCipher database, runs an integrity check with the
external key, synchronizes the encrypted file, atomically replaces
`control.db`, and removes the plaintext migration source. It refuses to run
against a database that is already encrypted.

Do not change the external key during this operation. Losing it after migration
makes the database, snapshots, node credentials, and pending connection secrets
unrecoverable.

## Consistent node snapshot

Stop the node and run the snapshot subcommand against the same data and keys
volumes:

```sh
mkdir -p backups
docker compose stop jolt-node
docker compose run --rm --no-deps \
  -e CONTROL_TOWER_DB_ENCRYPTION_KEY \
  -v "$PWD/backups:/backup" \
  jolt-node \
  /usr/local/bin/jolt-node snapshot \
  --data-dir /var/lib/jolt \
  --keys-dir /var/lib/jolt-keys \
  --output /backup/jolt-node.tar.gz
docker compose start jolt-node
```

The command:

- refuses to run while the node holds its instance lock;
- runs `PRAGMA integrity_check` and creates a consistent SQLite copy without
  transient WAL/SHM files;
- archives the data and keys directories as one atomic `.tar.gz`;
- writes `manifest.json` with the `node_id`, fingerprint, file modes, sizes, and
  SHA-256 digests;
- creates the final archive with mode `0600` and refuses to overwrite an
  existing output.

The archive contains private identity and mTLS keys and must be treated as a
secret. The command does not back up files inside published mounts; back those
up with the storage system's native tooling.

The equivalent local binary command is:

```sh
jolt-node snapshot \
  --data-dir /path/to/node/data \
  --keys-dir /path/to/node/keys \
  --output /secure/backups/jolt-node.tar.gz
```

## Consistent Control Tower snapshot

Stop the Control Tower before running:

```sh
mkdir -p backups
docker compose stop jolt-control
docker compose run --rm --no-deps \
  -v "$PWD/backups:/backup" \
  jolt-control \
  /usr/local/bin/jolt-control snapshot \
  --data-dir /var/lib/jolt-control \
  --output /backup/jolt-control.tar.gz
docker compose start jolt-control
```

The Control Tower snapshot contains its consistent encrypted SQLCipher database and other
files from its data directory. It intentionally does **not** contain
`CONTROL_TOWER_DB_ENCRYPTION_KEY`; back up that key separately and never store it
beside the database archive. The manifest records
`external_encryption_key_included=false`.

## Restore

1. Keep the node stopped.
2. Restore data and keys to empty directories with the same ownership.
3. Restore external mounts and update container bind-mount paths if the host changed.
4. Start the node with the same `PUID`, `PGID`, token, data path, and keys path.
5. Compare `node_id` and fingerprint with the pre-backup values.
6. Inspect mount states before allowing writes.

## Post-restore diagnostics

Before starting a restored node, run:

```sh
docker compose run --rm --no-deps \
  jolt-node \
  /usr/local/bin/jolt-node restore-diagnostics \
  --data-dir /var/lib/jolt \
  --keys-dir /var/lib/jolt-keys \
  --expected-node-id NODE_ID_FROM_BACKUP_RECORD \
  --expected-fingerprint FINGERPRINT_FROM_BACKUP_RECORD
```

The node report checks:

- SQLite integrity and foreign-key references;
- identity file permissions, public/private key correspondence, `node_id`,
  fingerprint, and identity epoch;
- registered mount existence, target type, readability, and requested
  writability;
- grant references, peer trust state, and grant-path containment;
- non-terminal jobs that must pass safe restore validation;
- local destination-grant references;
- resumable partial files, their durable checkpoints, unexpected/orphan
  partials, and missing partials referenced by checkpoints.

The partial scan is intentionally bounded to 200,000 filesystem entries. A
truncated scan is reported as a warning instead of silently presenting an
incomplete result.

Before starting a restored Control Tower, provide the external key through its
normal environment variable and run:

```sh
docker compose run --rm --no-deps \
  jolt-control \
  /usr/local/bin/jolt-control restore-diagnostics \
  --data-dir /var/lib/jolt-control
```

The Control Tower report first unlocks SQLCipher with the external encryption
key, checks SQLite integrity and references, verifies the persisted key check, confirms that an enabled
administrator with an Argon2id hash exists, and verifies every stored node
credential and unresolved connection secret without printing decrypted values.

Both commands print a JSON report. `status=error` also returns a non-zero exit
status and blocks startup until the inconsistency is understood. `warning`
requires operator review but represents a condition with a defined safe path,
such as truncating bytes beyond a durable partial checkpoint. The commands are
read-only and refuse to run while the corresponding service owns its instance
lock.

Restoring data without keys creates a new identity and must require new peer
pairing. Never copy an identity to two running nodes: that creates an identity
collision.

The Control Tower is not a source of truth for node jobs or mounts. Its backup
contains only its own database, node endpoints, encrypted operational
credentials, sessions, policies, roles, and audit data. The external encryption
key remains a separate backup item.

## Emergency credential recovery

All emergency credential commands are offline-only. They acquire the same
exclusive instance lock as the services and fail if the corresponding process
is still running. Secrets are read from environment variables and are never
included in JSON output, audit snapshots, or error messages.

### Lost or compromised node operational token

Stop both the affected node and the Control Tower. Generate or obtain a new
random token of at least 32 characters, then provide the same value to the two
offline commands:

```sh
read -r -s JOLT_RECOVERY_OPERATIONAL_TOKEN
export JOLT_RECOVERY_OPERATIONAL_TOKEN

docker compose run --rm --no-deps \
  -e JOLT_RECOVERY_OPERATIONAL_TOKEN \
  jolt-node \
  /usr/local/bin/jolt-node recover-operational-token \
  --data-dir /var/lib/jolt \
  --confirm replace-operational-token

export CONTROL_TOWER_RECOVERY_NODE_TOKEN="$JOLT_RECOVERY_OPERATIONAL_TOKEN"
docker compose run --rm --no-deps \
  -e CONTROL_TOWER_DB_ENCRYPTION_KEY \
  -e CONTROL_TOWER_RECOVERY_NODE_TOKEN \
  jolt-control \
  /usr/local/bin/jolt-control recover-node-token \
  --data-dir /var/lib/jolt-control \
  --node-id NODE_ID \
  --confirm-node-id NODE_ID

unset JOLT_RECOVERY_OPERATIONAL_TOKEN CONTROL_TOWER_RECOVERY_NODE_TOKEN
```

The node operation atomically removes any staged token, stores only the SHA-256
digest of the replacement, and permanently disables the previous environment
token for that database. The Control Tower operation validates its external
encryption key, replaces only the selected node's AES-GCM-encrypted credential,
marks that node `unknown`, and records an offline recovery audit event. Restart
both services and confirm an authenticated health check before resuming
operations.

Store the replacement token in the approved secret manager or recovery record.
Do not leave it in shell startup files or Compose YAML.

### Lost Control Tower administrator password

Keep the Control Tower stopped and provide a new password of at least 12
characters:

```sh
read -r -s CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD
export CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD

docker compose run --rm --no-deps \
  -e CONTROL_TOWER_DB_ENCRYPTION_KEY \
  -e CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD \
  jolt-control \
  /usr/local/bin/jolt-control recover-admin \
  --data-dir /var/lib/jolt-control \
  --username admin \
  --confirm-username admin

unset CONTROL_TOWER_RECOVERY_ADMIN_PASSWORD
```

The command validates the external encryption key before changing credentials.
It resets and enables the named user as an administrator, or creates that
administrator when the username does not exist. Every existing browser session
is revoked, an audit event with a correlation ID is persisted, and neither the
password nor its Argon2id hash is printed.
