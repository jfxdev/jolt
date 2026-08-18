package recovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"golang.org/x/sys/unix"
)

type DiagnosticIssue struct {
	Severity     string `json:"severity"`
	Code         string `json:"code"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	Message      string `json:"message"`
}

type MountDiagnostic struct {
	ID         string `json:"mount_id"`
	Name       string `json:"name"`
	LocalPath  string `json:"local_path"`
	Mode       string `json:"mode"`
	TargetType string `json:"target_type"`
	Enabled    bool   `json:"enabled"`
	State      string `json:"state"`
}

type PartialDiagnostic struct {
	MountID    string `json:"mount_id"`
	Path       string `json:"path"`
	JobID      string `json:"job_id,omitempty"`
	Size       int64  `json:"size"`
	Checkpoint int64  `json:"checkpoint"`
	State      string `json:"state"`
}

type RestoreDiagnosticReport struct {
	Version                 int                 `json:"version"`
	Kind                    string              `json:"kind"`
	CheckedAt               time.Time           `json:"checked_at"`
	Status                  string              `json:"status"`
	DatabaseIntegrity       string              `json:"database_integrity"`
	ForeignKeyViolations    int                 `json:"foreign_key_violations"`
	NodeID                  string              `json:"node_id,omitempty"`
	Fingerprint             string              `json:"fingerprint,omitempty"`
	IdentityEpoch           int                 `json:"identity_epoch,omitempty"`
	Mounts                  []MountDiagnostic   `json:"mounts"`
	PeerCount               int                 `json:"peer_count"`
	GrantCount              int                 `json:"grant_count"`
	JobCount                int                 `json:"job_count"`
	JobsRequiringValidation int                 `json:"jobs_requiring_validation"`
	Partials                []PartialDiagnostic `json:"partials"`
	PartialScanTruncated    bool                `json:"partial_scan_truncated"`
	Issues                  []DiagnosticIssue   `json:"issues"`
}

type diagnosticMount struct {
	ID, Name, LocalPath, TargetType, Mode string
	Enabled                               bool
	State                                 string
}

type diagnosticJob struct {
	ID, Type, State, MountID, PeerNodeID, SourceGrantID, DestinationGrantID, Destination string
	BytesCompleted                                                                       int64
}

type expectedPartial struct {
	MountID, JobID string
	Checkpoint     int64
}

func DiagnoseRestore(ctx context.Context, dataDir, keysDir, expectedNodeID,
	expectedFingerprint string) (RestoreDiagnosticReport, error) {
	report := RestoreDiagnosticReport{
		Version: 1, Kind: "jolt_node_restore", CheckedAt: time.Now().UTC(),
		Status: "ok", Mounts: []MountDiagnostic{}, Partials: []PartialDiagnostic{},
		Issues: []DiagnosticIssue{},
	}
	lock, err := AcquireLock(dataDir)
	if err != nil {
		return report, err
	}
	defer lock.Close()

	identity, identityErr := joltcrypto.LoadExisting(keysDir)
	if identityErr != nil {
		report.add("error", "identity_invalid", "identity", "", identityErr.Error())
	} else {
		report.NodeID, report.Fingerprint, report.IdentityEpoch =
			identity.NodeID, identity.Fingerprint, identity.Epoch
		if expectedNodeID != "" && expectedNodeID != identity.NodeID {
			report.add("error", "node_id_mismatch", "identity", identity.NodeID,
				"restored node_id does not match the expected node_id")
		}
		if expectedFingerprint != "" && expectedFingerprint != identity.Fingerprint {
			report.add("error", "fingerprint_mismatch", "identity", identity.NodeID,
				"restored fingerprint does not match the expected fingerprint")
		}
	}

	database, err := openDiagnosticDatabase(filepath.Join(dataDir, "jolt.db"))
	if err != nil {
		report.add("error", "database_unavailable", "database", "jolt.db", err.Error())
		report.finalize()
		return report, nil
	}
	defer database.Close()
	report.DatabaseIntegrity, err = databaseIntegrity(ctx, database)
	if err != nil {
		report.add("error", "database_integrity_failed", "database", "jolt.db", err.Error())
	}
	report.ForeignKeyViolations, err = foreignKeyViolations(ctx, database)
	if err != nil {
		report.add("error", "foreign_key_check_failed", "database", "jolt.db", err.Error())
	} else if report.ForeignKeyViolations > 0 {
		report.add("error", "foreign_key_violations", "database", "jolt.db",
			fmt.Sprintf("%d foreign key violation(s) found", report.ForeignKeyViolations))
	}

	mounts, err := loadDiagnosticMounts(ctx, database)
	if err != nil {
		report.add("error", "mounts_unreadable", "database", "mounts", err.Error())
		report.finalize()
		return report, nil
	}
	mountByID := make(map[string]diagnosticMount, len(mounts))
	for _, mount := range mounts {
		mount.State = diagnoseMount(mount, &report)
		mountByID[mount.ID] = mount
		report.Mounts = append(report.Mounts, MountDiagnostic{
			ID: mount.ID, Name: mount.Name, LocalPath: mount.LocalPath, Mode: mount.Mode,
			TargetType: mount.TargetType, Enabled: mount.Enabled, State: mount.State,
		})
	}

	peers, err := loadPeerStates(ctx, database)
	if err != nil {
		report.add("error", "peers_unreadable", "database", "peers", err.Error())
	}
	report.PeerCount = len(peers)
	grants, err := loadGrants(ctx, database)
	if err != nil {
		report.add("error", "grants_unreadable", "database", "grants", err.Error())
	}
	report.GrantCount = len(grants)
	grantIDs := map[string]bool{}
	for _, grant := range grants {
		grantIDs[grant.id] = true
		mount, mountExists := mountByID[grant.mountID]
		peerState, peerExists := peers[grant.peerNodeID]
		switch {
		case !mountExists:
			report.add("error", "grant_mount_missing", "grant", grant.id, "referenced mount is missing")
		case !peerExists:
			report.add("error", "grant_peer_missing", "grant", grant.id, "referenced peer is missing")
		case peerState == "revoked" && grant.enabled:
			report.add("error", "enabled_grant_for_revoked_peer", "grant", grant.id,
				"enabled grant references a revoked peer")
		case grant.enabled && mount.State != "available":
			report.add("warning", "grant_mount_unavailable", "grant", grant.id,
				"enabled grant references a mount that is not available")
		}
		if mountExists && grant.enabled {
			checkGrantPath(grant.id, grant.path, mount, &report)
		}
	}

	jobs, err := loadJobs(ctx, database)
	if err != nil {
		report.add("error", "jobs_unreadable", "database", "jobs", err.Error())
	}
	report.JobCount = len(jobs)
	jobIDs := make(map[string]bool, len(jobs))
	expected := map[string]expectedPartial{}
	for _, job := range jobs {
		jobIDs[job.ID] = true
		if jobNeedsValidation(job.State) {
			report.JobsRequiringValidation++
			if job.State != "waiting_validation" && job.State != "waiting_mount" &&
				job.State != "waiting_peer" && job.State != "paused" {
				report.add("warning", "job_requires_safe_recovery", "job", job.ID,
					"persisted non-terminal job must be moved through restore validation before execution")
			}
			if mount, exists := mountByID[job.MountID]; !exists || mount.State != "available" {
				report.add("warning", "job_mount_unavailable", "job", job.ID,
					"job destination mount is missing or unavailable")
			}
			if job.PeerNodeID != "" {
				state, exists := peers[job.PeerNodeID]
				if !exists || state == "revoked" || state == "identity_changed" || state == "untrusted" {
					report.add("warning", "job_peer_unavailable", "job", job.ID,
						"job peer is missing or not currently trusted")
				}
			}
			if job.DestinationGrantID != "" && !grantIDs[job.DestinationGrantID] {
				report.add("error", "job_grant_missing", "job", job.ID,
					"job references a missing local destination grant")
			}
			if job.Type == "transfer_pull" && job.BytesCompleted > 0 && job.Destination != "" {
				if mount, exists := mountByID[job.MountID]; exists {
					if safeRelative(job.Destination) {
						path := expectedPartialPath(mount.LocalPath, job.Destination, job.ID)
						expected[path] = expectedPartial{MountID: job.MountID, JobID: job.ID, Checkpoint: job.BytesCompleted}
					} else {
						report.add("error", "job_destination_invalid", "job", job.ID,
							"job destination is not a safe relative path")
					}
				}
			}
		}
	}
	items, err := loadIncompleteJobItems(ctx, database)
	if err != nil {
		report.add("error", "job_items_unreadable", "database", "job_items", err.Error())
	}
	for _, item := range items {
		if item.checkpoint <= 0 {
			continue
		}
		if mount, exists := mountByID[item.mountID]; exists {
			if !safeRelative(item.destination) {
				report.add("error", "job_item_destination_invalid", "job", item.jobID,
					"job item destination is not a safe relative path")
				continue
			}
			key := item.jobID + "-" + strconv.Itoa(item.ordinal)
			path := expectedPartialPath(mount.LocalPath, item.destination, key)
			expected[path] = expectedPartial{
				MountID: item.mountID, JobID: item.jobID, Checkpoint: item.checkpoint,
			}
		}
	}
	scanPartials(mounts, expected, jobIDs, &report)
	report.finalize()
	return report, nil
}

func openDiagnosticDatabase(path string) (*sql.DB, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("database is not a regular file")
	}
	database, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	if err := database.Ping(); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func databaseIntegrity(ctx context.Context, database *sql.DB) (string, error) {
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return "", err
	}
	if result != "ok" {
		return result, fmt.Errorf("integrity check returned %s", result)
	}
	return result, nil
}

func foreignKeyViolations(ctx context.Context, database *sql.DB) (int, error) {
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

func loadDiagnosticMounts(ctx context.Context, database *sql.DB) ([]diagnosticMount, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id,name,local_path,target_type,mode,enabled FROM mounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mounts []diagnosticMount
	for rows.Next() {
		var mount diagnosticMount
		var enabled int
		if err := rows.Scan(&mount.ID, &mount.Name, &mount.LocalPath, &mount.TargetType,
			&mount.Mode, &enabled); err != nil {
			return nil, err
		}
		mount.Enabled = enabled != 0
		mounts = append(mounts, mount)
	}
	return mounts, rows.Err()
}

func diagnoseMount(mount diagnosticMount, report *RestoreDiagnosticReport) string {
	if !mount.Enabled {
		return "disabled"
	}
	info, err := os.Stat(mount.LocalPath)
	if err != nil {
		report.add("error", "mount_missing", "mount", mount.ID, err.Error())
		return "unavailable"
	}
	if mount.TargetType == "directory" && !info.IsDir() ||
		mount.TargetType == "file" && !info.Mode().IsRegular() {
		report.add("error", "mount_type_changed", "mount", mount.ID,
			"restored mount target type differs from the registered type")
		return "divergent"
	}
	if err := unix.Access(mount.LocalPath, unix.R_OK); err != nil {
		report.add("error", "mount_unreadable", "mount", mount.ID, "mount is not readable")
		return "unavailable"
	}
	if mount.Mode == "read_write" && unix.Access(mount.LocalPath, unix.W_OK) != nil {
		report.add("warning", "mount_read_only", "mount", mount.ID,
			"read-write mount is not writable by the current process")
		return "degraded"
	}
	return "available"
}

type diagnosticGrant struct {
	id, peerNodeID, mountID, path string
	enabled                       bool
}

func loadPeerStates(ctx context.Context, database *sql.DB) (map[string]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT node_id,state FROM peers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	peers := map[string]string{}
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, err
		}
		peers[id] = state
	}
	return peers, rows.Err()
}

func loadGrants(ctx context.Context, database *sql.DB) ([]diagnosticGrant, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id,peer_node_id,mount_id,path,enabled FROM transfer_grants`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []diagnosticGrant
	for rows.Next() {
		var grant diagnosticGrant
		var enabled int
		if err := rows.Scan(&grant.id, &grant.peerNodeID, &grant.mountID, &grant.path, &enabled); err != nil {
			return nil, err
		}
		grant.enabled = enabled != 0
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func checkGrantPath(grantID, relative string, mount diagnosticMount, report *RestoreDiagnosticReport) {
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == ".." || filepath.IsAbs(clean) ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		report.add("error", "grant_path_invalid", "grant", grantID, "grant path is unsafe")
		return
	}
	target := mount.LocalPath
	if clean != "." {
		target = filepath.Join(target, clean)
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(mount.LocalPath)
	resolvedTarget, targetErr := filepath.EvalSymlinks(target)
	if rootErr != nil || targetErr != nil {
		report.add("warning", "grant_path_missing", "grant", grantID,
			"grant path cannot be resolved inside the restored mount")
		return
	}
	relativeToRoot, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || relativeToRoot == ".." ||
		strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
		report.add("error", "grant_path_escape", "grant", grantID,
			"grant path resolves outside its registered mount")
	}
}

func loadJobs(ctx context.Context, database *sql.DB) ([]diagnosticJob, error) {
	rows, err := database.QueryContext(ctx, `SELECT id,type,state,mount_id,
COALESCE(peer_node_id,''),COALESCE(source_grant_id,''),COALESCE(destination_grant_id,''),
destination_path,bytes_completed FROM jobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []diagnosticJob
	for rows.Next() {
		var job diagnosticJob
		if err := rows.Scan(&job.ID, &job.Type, &job.State, &job.MountID, &job.PeerNodeID,
			&job.SourceGrantID, &job.DestinationGrantID, &job.Destination,
			&job.BytesCompleted); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

type incompleteItem struct {
	jobID, mountID, destination string
	ordinal                     int
	checkpoint                  int64
}

func loadIncompleteJobItems(ctx context.Context, database *sql.DB) ([]incompleteItem, error) {
	rows, err := database.QueryContext(ctx, `SELECT i.job_id,j.mount_id,i.ordinal,
i.destination_path,i.bytes_completed FROM job_items i JOIN jobs j ON j.id=i.job_id
WHERE i.type='file' AND i.state NOT IN ('completed','skipped')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []incompleteItem
	for rows.Next() {
		var item incompleteItem
		if err := rows.Scan(&item.jobID, &item.mountID, &item.ordinal,
			&item.destination, &item.checkpoint); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func jobNeedsValidation(state string) bool {
	switch state {
	case "completed", "completed_with_warnings", "failed", "canceled":
		return false
	default:
		return true
	}
}

func expectedPartialPath(root, destination, resumeKey string) string {
	safeKey := strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, resumeKey)
	return filepath.Join(filepath.Dir(filepath.Join(root, filepath.FromSlash(destination))),
		".jolt-"+safeKey+".partial")
}

func safeRelative(value string) bool {
	clean := filepath.Clean(filepath.FromSlash(strings.TrimSpace(value)))
	return clean != "" && clean != ".." && !filepath.IsAbs(clean) &&
		!strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func scanPartials(mounts []diagnosticMount, expected map[string]expectedPartial,
	jobIDs map[string]bool, report *RestoreDiagnosticReport) {
	const maxEntries = 200000
	seenExpected := map[string]bool{}
	seenRoots := map[string]bool{}
	entries := 0
	for _, mount := range mounts {
		if !mount.Enabled || mount.State == "unavailable" || mount.TargetType != "directory" ||
			seenRoots[mount.LocalPath] {
			continue
		}
		seenRoots[mount.LocalPath] = true
		walkErr := filepath.WalkDir(mount.LocalPath, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			entries++
			if entries > maxEntries {
				report.PartialScanTruncated = true
				return fs.SkipAll
			}
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".jolt-") ||
				!strings.HasSuffix(entry.Name(), ".partial") {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			partial := PartialDiagnostic{MountID: mount.ID, Path: path, Size: info.Size(), State: "orphan"}
			if expectedItem, exists := expected[path]; exists {
				seenExpected[path] = true
				partial.JobID, partial.Checkpoint = expectedItem.JobID, expectedItem.Checkpoint
				partial.State = "valid"
				if info.Size() < expectedItem.Checkpoint {
					partial.State = "shorter_than_checkpoint"
					report.add("error", "partial_shorter_than_checkpoint", "job", expectedItem.JobID,
						"partial file is shorter than its durable checkpoint")
				} else if info.Size() > expectedItem.Checkpoint {
					partial.State = "ahead_of_checkpoint"
					report.add("warning", "partial_ahead_of_checkpoint", "job", expectedItem.JobID,
						"partial contains bytes beyond the durable checkpoint and will be truncated on resume")
				}
			} else {
				jobID := partialJobID(entry.Name())
				partial.JobID = jobID
				code := "orphan_partial"
				if jobIDs[jobID] {
					code = "unexpected_job_partial"
				}
				report.add("warning", code, "partial", path,
					"partial file is not associated with a persisted resumable checkpoint")
			}
			report.Partials = append(report.Partials, partial)
			return nil
		})
		if walkErr != nil {
			report.add("warning", "partial_scan_failed", "mount", mount.ID, walkErr.Error())
		}
	}
	for path, expectedItem := range expected {
		if !seenExpected[path] {
			report.add("error", "checkpoint_partial_missing", "job", expectedItem.JobID,
				"durable checkpoint references a missing partial file")
		}
	}
	if report.PartialScanTruncated {
		report.add("warning", "partial_scan_truncated", "filesystem", "",
			fmt.Sprintf("partial scan stopped after %d entries", maxEntries))
	}
}

func partialJobID(name string) string {
	value := strings.TrimSuffix(strings.TrimPrefix(name, ".jolt-"), ".partial")
	if index := strings.LastIndex(value, "-"); index > 0 {
		if _, err := strconv.Atoi(value[index+1:]); err == nil {
			value = value[:index]
		}
	}
	return value
}

func (r *RestoreDiagnosticReport) add(severity, code, resourceType, resourceID, message string) {
	r.Issues = append(r.Issues, DiagnosticIssue{
		Severity: severity, Code: code, ResourceType: resourceType,
		ResourceID: resourceID, Message: message,
	})
}

func (r *RestoreDiagnosticReport) finalize() {
	r.Status = "ok"
	for _, issue := range r.Issues {
		if issue.Severity == "error" {
			r.Status = "error"
			return
		}
		if issue.Severity == "warning" {
			r.Status = "warning"
		}
	}
}
