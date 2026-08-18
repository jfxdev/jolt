//go:build acceptance

package jobs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type acceptanceProfile struct {
	fileBytes          int64
	directoryBytes     int64
	directoryFileCount int
	bandwidthLimit     int64
	timeout            time.Duration
}

func loadAcceptanceProfile(t *testing.T) acceptanceProfile {
	t.Helper()
	profile := acceptanceProfile{
		fileBytes:          64 << 20,
		directoryBytes:     128 << 20,
		directoryFileCount: 1_024,
		bandwidthLimit:     16 << 20,
		timeout:            10 * time.Minute,
	}
	switch os.Getenv("JOLT_ACCEPTANCE_PROFILE") {
	case "quick":
	case "half":
		profile.fileBytes = 5 << 30
		profile.directoryBytes = 50 << 30
		profile.directoryFileCount = 2_500
		profile.bandwidthLimit = 128 << 20
		profile.timeout = 90 * time.Minute
	case "full":
		profile.fileBytes = 10 << 30
		profile.directoryBytes = 100 << 30
		profile.directoryFileCount = 5_000
		profile.bandwidthLimit = 128 << 20
		profile.timeout = 3 * time.Hour
	default:
		t.Skip("set JOLT_ACCEPTANCE_PROFILE=quick, half, or full; or use a make acceptance target")
	}
	profile.fileBytes = acceptanceInt64(t, "JOLT_ACCEPTANCE_FILE_BYTES", profile.fileBytes)
	profile.directoryBytes = acceptanceInt64(t, "JOLT_ACCEPTANCE_DIRECTORY_BYTES", profile.directoryBytes)
	profile.bandwidthLimit = acceptanceInt64(t, "JOLT_ACCEPTANCE_BANDWIDTH_BYTES_PER_SECOND", profile.bandwidthLimit)
	profile.directoryFileCount = int(acceptanceInt64(t, "JOLT_ACCEPTANCE_DIRECTORY_FILES", int64(profile.directoryFileCount)))
	if profile.fileBytes <= 0 || profile.directoryBytes <= 0 || profile.directoryFileCount <= 0 ||
		profile.bandwidthLimit <= 0 {
		t.Fatal("acceptance sizes, file count, and bandwidth must be positive")
	}
	return profile
}

func acceptanceInt64(t *testing.T, name string, fallback int64) int64 {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("%s must be an integer: %v", name, err)
	}
	return parsed
}

func writePatternFile(t *testing.T, name string, size int64, seed byte) {
	t.Helper()
	file, err := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1<<20)
	for index := range buffer {
		buffer[index] = seed + byte(index%251)
	}
	for written := int64(0); written < size; {
		count := int64(len(buffer))
		if remaining := size - written; remaining < count {
			count = remaining
		}
		if _, err := file.Write(buffer[:count]); err != nil {
			file.Close()
			t.Fatal(err)
		}
		written += count
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitAcceptanceJob(t *testing.T, service *Service, id string, timeout time.Duration, states ...string) entitiesJob {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job, err := service.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, state := range states {
			if job.State == state {
				return entitiesJob{state: job.State, bytesCompleted: job.BytesCompleted, filesCompleted: job.FilesCompleted}
			}
		}
		if job.State == "failed" || job.State == "completed_with_warnings" || job.State == "canceled" {
			t.Fatalf("job reached unexpected terminal state: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach %v before %s", id, states, timeout)
	return entitiesJob{}
}

type entitiesJob struct {
	state          string
	bytesCompleted int64
	filesCompleted int
}

func TestAcceptanceLargeFileSurvivesProcessInterruptionAndResumes(t *testing.T) {
	profile := loadAcceptanceProfile(t)
	service, files, mountID := testService(t)
	service.ConfigureChunkSize(1 << 20)
	service.ConfigureParallelism(4, 4)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	writePatternFile(t, filepath.Join(mount.LocalPath, "large-source.bin"), profile.fileBytes, 17)

	firstContext, stopFirst := context.WithCancel(context.Background())
	if _, err := service.Start(firstContext, 1); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "large-source.bin",
		Destination: "large-destination.bin", ConflictPolicy: "fail",
		BandwidthLimit: profile.bandwidthLimit, MaxParallelChunks: 4,
	}, "acceptance-large-file")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(profile.timeout)
	var checkpoint int64
	for time.Now().Before(deadline) {
		items, listErr := service.ListItems(context.Background(), job.ID)
		if listErr == nil && len(items) == 1 && items[0].BytesCompleted >= 4<<20 &&
			items[0].BytesCompleted < profile.fileBytes {
			checkpoint = items[0].BytesCompleted
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if checkpoint == 0 {
		t.Fatal("large copy produced no observable durable checkpoint")
	}
	stopFirst()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	if err := service.Shutdown(shutdownContext); err != nil {
		cancelShutdown()
		t.Fatal(err)
	}
	cancelShutdown()

	interrupted := waitAcceptanceJob(t, service, job.ID, time.Minute, "waiting_validation")
	if interrupted.bytesCompleted < checkpoint {
		t.Fatalf("checkpoint regressed across process interruption: before=%d after=%d", checkpoint, interrupted.bytesCompleted)
	}
	if _, err := os.Stat(filepath.Join(mount.LocalPath, "large-destination.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination was published before resumed validation: %v", err)
	}

	restarted := New(service.store, files)
	restarted.ConfigureChunkSize(1 << 20)
	restarted.ConfigureParallelism(4, 4)
	secondContext, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()
	if recovered, err := restarted.Start(secondContext, 1); err != nil || recovered != 0 {
		t.Fatalf("restart recovery: recovered=%d err=%v", recovered, err)
	}
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = restarted.Shutdown(shutdownContext)
	})
	if _, err := restarted.Resume(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	completed := waitAcceptanceJob(t, restarted, job.ID, profile.timeout, "completed")
	if completed.bytesCompleted != profile.fileBytes {
		t.Fatalf("completed bytes=%d want=%d", completed.bytesCompleted, profile.fileBytes)
	}
	sourceChecksum, err := files.Checksum(context.Background(), mountID, "large-source.bin")
	if err != nil {
		t.Fatal(err)
	}
	destinationChecksum, err := files.Checksum(context.Background(), mountID, "large-destination.bin")
	if err != nil {
		t.Fatal(err)
	}
	if sourceChecksum != destinationChecksum {
		t.Fatal("resumed large-file checksum differs")
	}
}

func TestAcceptanceLargeDirectoryCompletesWithParallelFilesAndChunks(t *testing.T) {
	profile := loadAcceptanceProfile(t)
	service, files, mountID := testService(t)
	service.ConfigureChunkSize(1 << 20)
	service.ConfigureParallelism(8, 2)
	mount, err := files.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := filepath.Join(mount.LocalPath, "library")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	baseSize := profile.directoryBytes / int64(profile.directoryFileCount)
	remainder := profile.directoryBytes % int64(profile.directoryFileCount)
	for index := 0; index < profile.directoryFileCount; index++ {
		size := baseSize
		if int64(index) < remainder {
			size++
		}
		directory := filepath.Join(sourceRoot, fmt.Sprintf("%03d", index%64))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		writePatternFile(t, filepath.Join(directory, fmt.Sprintf("item-%06d.bin", index)), size, byte(index))
	}

	runContext, stop := context.WithCancel(context.Background())
	defer stop()
	if _, err := service.Start(runContext, 2); err != nil {
		t.Fatal(err)
	}
	job, _, err := service.Create(context.Background(), CreateRequest{
		Type: "copy_local", MountID: mountID, SourcePath: "library",
		Destination: "library-copy", ConflictPolicy: "fail",
		MaxParallelFiles: 8, MaxParallelChunks: 2,
	}, "acceptance-large-directory")
	if err != nil {
		t.Fatal(err)
	}
	completed := waitAcceptanceJob(t, service, job.ID, profile.timeout, "completed")
	if completed.bytesCompleted != profile.directoryBytes || completed.filesCompleted != profile.directoryFileCount {
		t.Fatalf("directory progress bytes=%d/%d files=%d/%d", completed.bytesCompleted,
			profile.directoryBytes, completed.filesCompleted, profile.directoryFileCount)
	}
	for _, index := range []int{0, profile.directoryFileCount / 2, profile.directoryFileCount - 1} {
		relative := filepath.ToSlash(filepath.Join(fmt.Sprintf("%03d", index%64), fmt.Sprintf("item-%06d.bin", index)))
		sourceChecksum, err := files.Checksum(context.Background(), mountID, filepath.ToSlash(filepath.Join("library", relative)))
		if err != nil {
			t.Fatal(err)
		}
		destinationChecksum, err := files.Checksum(context.Background(), mountID, filepath.ToSlash(filepath.Join("library-copy", relative)))
		if err != nil {
			t.Fatal(err)
		}
		if sourceChecksum != destinationChecksum {
			t.Fatalf("directory sample checksum differs for %s", relative)
		}
	}
}
