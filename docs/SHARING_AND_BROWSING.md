# Sharing, browsing and uploads

This document covers the file-manager surface added for day-to-day use:
subpath authorization, folder downloads, search, resumable uploads, public
share links, and metrics.

## Subpath authorization

Node Path policies used to stop at the mount:
`nodes/<nodeID>/files/mounts/<mountID>`. File operations are now evaluated
against the **exact path** being touched, so a policy can scope a subject to a
folder without registering that folder as its own mount.

Two pattern forms exist:

| Pattern | Matches |
| --- | --- |
| `nodes/*/files/mounts/media/fotos` | exactly that folder |
| `nodes/*/files/mounts/media/fotos/**` | that folder and everything under it |

`**` is a recursive wildcard and is only valid as the **last** segment, so a
rule can never read as broader than it looks. `*` still matches exactly one
segment.

Rules are ranked by specificity, and an exact rule outranks a recursive one at
the same depth. `deny` continues to win globally: a `deny` anywhere in the
subject's policy set refuses the request regardless of specificity.

Copy and move evaluate each side separately. A copy needs `read` on the source
subtree and `create` on the destination subtree; a move needs `update` on both.

### Existing policies keep working

A policy written before subpaths existed — one ending exactly at a mount —
previously authorized every path inside that mount. On evaluation such a rule is
automatically also applied in its recursive form, so the access it already
granted is preserved. Deny rules expand the same way, so narrowing an old policy
never loosens it. The expansion is scoped to the file family
(`nodes/<id>/files/mounts/<id>`) and never touches `jobs`, `transfers` or any
other resource.

### Policy paths versus real paths

Authored policy paths reject the URL metacharacters `\ / ? # & = % *` inside a
segment, so a rule cannot be mistaken for a URL with a query string. Real file
names are user data and may contain them, so a *concrete* path being authorized
is validated more permissively: only empty segments, `.`, `..`, wildcards and
control characters are refused. A folder named `Vendas 50% off` is therefore
reachable, even though it cannot be named literally in a policy rule — target it
with a wildcard or a parent `**` rule instead.

### Whole-subtree reads and deny rules

A ZIP of a folder and a recursive search both read an entire subtree from a
single named root. Authorizing only that root would let the node read
descendants the subject is denied, and the node cannot filter them itself
because it does not know the subject's policies.

Both operations are therefore refused with `deny_rule_within_scope` while any
`deny` rule applies at or below the requested path, and the subject narrows the
request to an allowed subfolder. Each `name=` selection is authorized on its
own rather than riding on the base path's decision. The same check guards a
public share of a folder, so a share can never archive past a deny rule.

## Folder downloads (ZIP)

`GET /api/v1/mounts/{mountID}/files/archive?path=…` streams a ZIP. Add one or
more `name=` parameters to archive only those direct children; each selected
root keeps its own directory inside the archive so extracting a multi-selection
does not scatter files.

- Entries are **stored, not deflated** by default. Media and archives on a NAS
  are already compressed, so Store saturates the link instead of a CPU core.
  Pass `compress=true` for compressible trees.
- Symlinks are **skipped and counted**, never followed: following one could copy
  data from outside the mount into a download. The count comes back in
  `X-Jolt-Archive-Skipped-Symlinks`.
- The size is measured before streaming starts, so an oversized selection is
  refused with a real status code. Once bytes are on the wire the status is
  already committed, and a failure can only appear as a truncated download.
  `ARCHIVE_MAX_ENTRIES` (default 50 000) and `ARCHIVE_MAX_BYTES` (default
  100 GiB) set the limits; `…/archive/plan` reports the same numbers without
  writing anything, which is what the UI confirms against.

## Search

`GET /api/v1/mounts/{mountID}/files/search?path=…&query=…` walks the subtree
under `path`. Filters: `type` (`file`/`directory`), `extensions`, `min_size`,
`max_size`, `modified_after`, `modified_before`, `limit`. A query or at least one
filter is required.

Every search is bounded, because an unbounded walk over a large mount would pin
a disk and a worker for minutes on one request:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SEARCH_MAX_RESULTS` | 500 | matches returned |
| `SEARCH_MAX_ENTRIES` | 200 000 | entries inspected |
| `SEARCH_TIMEOUT` | 15s | wall clock per request |

A partial answer sets `truncated` with a `truncated_reason` of `results`,
`entries` or `timeout`, so the UI can say "showing the first N of more" rather
than implying the list is complete. Symlinks are never followed: a link back to
an ancestor would make the walk loop, and a link out of the mount would expose
paths the caller has no authorization for. Size filters exclude directories,
whose reported size is filesystem bookkeeping rather than content.

## Directory pages and operational status

`GET /api/v1/mounts/{mountID}/files` keeps the existing `items` and `path`
fields and adds `has_more` and `next_after`. Pass the opaque `next_after` back
as `after` until `has_more` is false. The default page is 200 entries, maximum
1,000. Directories come first; case-folded names use exact names to break ties.
The explorer, destination folder picker and public folder listing offer more
pages instead of silently truncating the directory. Selection stays intact when
loading another page. The cursor is not a filesystem snapshot: concurrent
insertions before it are visible on refresh.

`GET /api/v1/jobs/summary` returns `{counts, observed_at}` over all durable jobs,
including active jobs older than the recent history page. The control proxy
requires `list` on `nodes/{nodeID}/jobs`, just like the job list and SSE stream.
Job-item pages are selected from the storage index before decoding payloads.
The proxy preserves `Last-Event-ID` during SSE reconnection.

The network view updates every 15 seconds while visible, with at most four
requests in flight. It separates running operations, queued jobs and waiting
states; sections use their existing permissions. Missing information is shown
as unavailable/restricted, with prior observations timestamped. A failed
workspace section leaves the other sections usable and has its own retry.

## Resumable uploads

The Control Tower resolves each upload ID to its persisted mount and destination
before checking permission. Reading, appending, completing and aborting a session
require `create` on that exact destination; creation and chunk writes also require
`create` on the node's jobs resource. Session listings expose only destinations
the caller may write. A `path` query parameter cannot change these checks.

A plain `PUT …/files/content` is still a single stream. For large files over a
flaky link, use the session API:

1. `POST …/files/uploads` with `{path, size, overwrite, checksum?}` → session.
2. `PATCH …/files/uploads/{uploadID}` with
   `Content-Range: bytes <start>-<end>/<total>` per chunk.
3. `POST …/files/uploads/{uploadID}/complete` → verifies and publishes, returning a durable receipt.
4. After reopening the explorer, select the corresponding local file for a
   pending session. `GET …/files/uploads/{uploadID}/verification?after=0`
   returns at most sixteen 8 MiB SHA-256 blocks per page, the durable `offset`,
   and a byte `next_after` (zero when finished). The browser verifies every
   received byte before sending the remainder, without loading the whole file.
   A different prefix or size is refused without sending any new bytes.

Sessions transition from `open` (legacy records without a state are also open)
to `publishing` with a durable verified checksum, then `completed`. A restarted
node reconciles the publication intent against the partial or destination
content before acknowledging completion. `GET` reports the state; repeating
`complete` returns the same receipt, including SHA-256 and `completed_at`, even
if its previous response was lost. Completion retries never republish a later
external replacement. Receipts expire using `upload_session_ttl` after completion,
are excluded from active session lists and reservations, and their cleanup
never removes the published file. Session writes, publication and expiry are
serialized together. The queue stores each original node/mount/path so changing
the current screen cannot retarget a retry or discard.

Properties that make a resumed upload trustworthy:

- The **declared size is the authority**. The node writes at most that many
  bytes and verifies the total before publishing, so a truncated upload can
  never replace a good file.
- Each chunk is **fsynced before the new offset is reported**, so an offset read
  back after a crash refers to bytes that are genuinely durable.
- An append at the wrong offset is refused with `409` and the real offset in
  `X-Jolt-Upload-Offset`, so a client seeks instead of creating a hole.
- Publication is an **atomic rename**, so the destination is never a partial
  file. An optional `checksum` is verified first.
- One destination may hold only **one** open session, and the appends of a
  single session are serialized: two writers at the same offset would otherwise
  both pass the offset check and interleave their bytes into the partial file.
  The loser is told the real offset and resumes from it.
- A zero-byte file sends no chunk, so its partial is materialized at completion
  and published through the same verified path as any other file.
- `overwrite` is not implied. The UI starts an upload without it and surfaces a
  conflict, so replacing an existing file is always an explicit choice.
- Partials are named `.jolt-<id>.partial` and are hidden from listings, search
  and archives, and are not addressable through the API.
- `GET …/files/uploads` lists unfinished sessions so the UI can offer to resume
  after a reload. `DELETE` aborts one and removes its partial.
- Sessions expire after `UPLOAD_SESSION_TTL` (default 24h, extended while bytes
  keep arriving) and are swept together with their partial files.

## Public share links

A share is a read-only link to one file or folder.

Management (authenticated): `GET`/`POST /api/v1/control-tower/shares`,
`POST …/{shareID}/revoke`, `DELETE …/{shareID}`.
Public (no session): `GET /api/v1/public/shares/{token}` plus
`/list`, `/content`, `/archive`, and `POST …/unlock`.
The browser-facing URL is `/s/{token}`.

Options: `password` (minimum 8 characters), `expires_in_seconds` (capped at one
year), `max_downloads`, and `allow_archive` for folders.

Security properties:

- Creating a link requires the `create` capability on `control-tower/shares`
  **and** `read` on the exact path. A link can never widen what its creator
  already reached.
- **Every public request re-evaluates the creator's own access.** Revoking an
  operator's policies, disabling their account, or demoting an administrator
  kills every link they published — a departed operator's shares do not keep
  serving data. The creator's role is read from storage on each request, which
  is what makes a demotion take effect; an administrator is authorized by the
  same built-in override that applies to their interactive requests.
- A folder share is refused while a `deny` rule applies inside its subtree.
- The token is returned **once** and stored only as a digest, so a leaked
  database cannot be turned into working links.
- Public metadata exposes only a display name and whether the link is a file or
  a folder. It never reveals the node, mount or path.
- An unknown token and a revoked token answer identically, so the endpoint
  cannot be used to enumerate which links exist.
- A folder share confines every subpath to its own subtree; a file share accepts
  no subpath at all.
- Password attempts are rate limited through the same lockout table as logins.
  An unlock mints a stateless HMAC ticket scoped to that one share, bound to the
  stored password hash, so changing the password invalidates outstanding
  tickets and a ticket for one link never opens another.
- Every content/archive request consumes the atomic download budget, including
  Range requests and resumed requests. The limit counts attempts, not verified
  complete files. A Range header cannot prove an earlier counted download.
- Responses are `Cache-Control: private, no-store`, because the URL is the
  credential.
- The public surface accepts no writes under any method.

Expired links stop serving immediately; their rows are kept for 30 days so the
audit trail still explains what the link was and who created it.

## Filesystem containment and upload budgets

Mounted file content never follows symlinks, including intermediate path
components and links whose target is inside the mount. This keeps subpath RBAC,
public shares and transfer grants aligned with the actual bytes. Deleting or
moving a symlink operates on the link entry and preserves its target. ZIP/search
continue skipping symlinks. Paths are accessed relative to open directory
descriptors with no-follow checks at each component; swapping a symlink between
validation and use does not redirect a read or write.

Publication with `overwrite=false` uses the kernel's no-replace rename operation
on Linux and macOS. A concurrent destination produces a conflict, without
replacing its bytes. Filesystems that do not support the required operation fail
closed; qualify the intended filesystem before deployment.

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPLOAD_MAX_BYTES` | 100 GiB | Maximum size of a streaming or resumable upload |
| `UPLOAD_MAX_SESSIONS` | 32 | Maximum unfinished, unexpired sessions on the node |
| `UPLOAD_MAX_RESERVED_BYTES` | 400 GiB | Maximum unwritten bytes declared by active sessions |
| `UPLOAD_MIN_FREE_BYTES` | 1 GiB | Safety margin checked at admission and on every upload write |

Session admission is serialized so concurrent declarations cannot overbook the
same budget. Disk admission conservatively includes all other sessions, even
across mounts. Already-written bytes are excluded from the reservation. Streaming
bodies are bounded while reading, including requests without Content-Length.
The client respects the session's chunk-size limit. Size, space and session-limit
failures return 413, 507 and 429 respectively; failed streaming uploads remain
unpublished. Other processes may still consume space, so ENOSPC must be treated
as an upload failure. These budgets apply to uploads, not a general filesystem
quota for transfer jobs or other host processes. Effective limits are available
from the node's metadata and effective-configuration API.

The Compose example forwards these limits, separate node/control metrics tokens,
and a configurable peer endpoint. Copy `.env.example` and fill all required
secrets. `JOLT_OWNED_PATHS` is a recursive ownership operation; an explicitly empty
value disables mount reconciliation when the host ownership is already prepared.

## Metrics endpoints

Both services expose Prometheus text format on `GET /metrics`, served only when
a token is configured and requiring that token:

- node: `METRICS_TOKEN`
- Control Tower: `CONTROL_TOWER_METRICS_TOKEN`

A scraper therefore never needs the operational token or an operator session.
Labels use matched route patterns rather than raw paths, so a mount with
thousands of files cannot explode cardinality, and a share token never becomes a
label.

Selected series — node: `jolt_http_requests_total`,
`jolt_http_request_duration_seconds`, `jolt_uploads_active`,
`jolt_upload_bytes_total`, `jolt_jobs_active`, `jolt_job_bytes_total`.
Control Tower: `jolt_control_http_requests_total`,
`jolt_control_login_failures_total`, `jolt_control_authorization_denied_total`,
`jolt_control_node_proxy_total`, `jolt_control_share_downloads_total`,
`jolt_control_share_unlock_failures_total`. Both expose `go_goroutines` and heap
gauges.

Example scrape config:

```yaml
scrape_configs:
  - job_name: jolt-node
    authorization: { credentials: "<METRICS_TOKEN>" }
    static_configs:
      - targets: ["jolt-node:8080"]
  - job_name: jolt-control
    authorization: { credentials: "<CONTROL_TOWER_METRICS_TOKEN>" }
    static_configs:
      - targets: ["jolt-control:8090"]
```

## Verification commands

Run `make test`, `make vet`, and `make acceptance` for backend and unit coverage.
For browser scenarios, run `npx playwright install chromium` once inside
`control/frontend`, then `npm run test:e2e`. The browser suite starts its own
loopback development server and uses synthetic API fixtures in desktop and
mobile viewports. `scripts/container-smoke.py` exercises the real container APIs,
including upload verification, receipts after restart, summary permissions and
credential cutover. It requires locally built `jolt-node:smoke` and
`jolt-control:smoke` images and removes its disposable containers and volumes.
