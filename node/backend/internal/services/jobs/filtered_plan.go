package jobs

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

// PlanCopyFiltered plans only visible, readable sources and checks every final
// destination. Omitted roots must be reported by the caller; this internal
// planner does not enable execution of protected jobs.
func (s *Service) PlanCopyFiltered(ctx context.Context, mountID, source, destination, conflictPolicy string, filter *filesystem.AccessFilter, verifyChecksum bool) (entities.CopyPlan, int, error) {
	if filter == nil || source == "" || destination == "" || path.IsAbs(source) || path.IsAbs(destination) || path.Clean(source) != source || path.Clean(destination) != destination || strings.ContainsAny(source+destination, "\\\x00") {
		return entities.CopyPlan{}, 0, ErrInvalid
	}
	policy, err := normalizeConflictPolicy(conflictPolicy, false)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	sourceMetadata, err := s.files.MetadataFiltered(ctx, mountID, source, filter)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	if source == destination || sourceMetadata.Type == "directory" && (source == "." || strings.HasPrefix(destination, strings.TrimSuffix(source, "/")+"/")) {
		return entities.CopyPlan{}, 0, ErrInvalid
	}
	manifest, omitted, err := s.files.ManifestFiltered(ctx, mountID, source, filter)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	entries := manifest
	if sourceMetadata.Type == "directory" {
		entries = append([]entities.FileEntry{{Name: sourceMetadata.Name, Path: ".", Type: "directory", ModifiedAt: sourceMetadata.ModifiedAt}}, manifest...)
	}
	plan := entities.CopyPlan{SourcePath: source, DestinationPath: destination, ConflictPolicy: policy, Items: make([]entities.JobItem, 0, len(entries))}
	now := s.now()
	blockedDirectories := make(map[string]struct{})
	for index, entry := range entries {
		if err := ctx.Err(); err != nil {
			return entities.CopyPlan{}, 0, err
		}
		item := entities.JobItem{Ordinal: index, RelativePath: entry.Path, SourcePath: joinRelative(source, entry.Path), DestinationPath: joinRelative(destination, entry.Path), Type: entry.Type, Size: entry.Size, ModifiedAt: entry.ModifiedAt, State: "pending", UpdatedAt: now}
		if hasBlockedParent(entry.Path, blockedDirectories) {
			item.Action = "conflict"
		} else {
			item.Action, item.DestinationPath, item.Checksum, err = s.planActionFiltered(ctx, mountID, item, policy, filter)
			if err != nil {
				return entities.CopyPlan{}, 0, err
			}
		}
		if item.Type == "file" && (verifyChecksum || policy == "checksum") && item.Checksum == "" {
			item.Checksum, err = s.files.ChecksumFiltered(ctx, mountID, item.SourcePath, filter)
			if err != nil {
				return entities.CopyPlan{}, 0, err
			}
		}
		if item.Type == "directory" && item.Action == "conflict" {
			blockedDirectories[entry.Path] = struct{}{}
		}
		if item.Type == "file" {
			plan.FilesTotal++
			switch item.Action {
			case "copy", "overwrite":
				plan.CopyCount++
				plan.BytesTotal += item.Size
			case "rename":
				plan.RenameCount++
				plan.BytesTotal += item.Size
			case "skip":
				plan.SkipCount++
			case "conflict":
				plan.ConflictCount++
			}
		}
		plan.Items = append(plan.Items, item)
	}
	if err := ctx.Err(); err != nil {
		return entities.CopyPlan{}, 0, err
	}
	return plan, omitted, nil
}

func (s *Service) planActionFiltered(ctx context.Context, mountID string, item entities.JobItem, policy string, filter *filesystem.AccessFilter) (string, string, string, error) {
	existing, exists, err := s.files.InspectCopyDestinationFiltered(ctx, mountID, item.DestinationPath, item.Type, filter)
	if err != nil {
		return "", item.DestinationPath, "", err
	}
	if !exists {
		if item.Type == "directory" {
			return "create", item.DestinationPath, "", nil
		}
		return "copy", item.DestinationPath, item.Checksum, nil
	}
	if item.Type == "directory" {
		if existing.Type != "directory" {
			return "conflict", item.DestinationPath, "", nil
		}
		return "merge", item.DestinationPath, "", nil
	}
	if existing.Type != "file" {
		return "conflict", item.DestinationPath, item.Checksum, nil
	}
	switch policy {
	case "skip":
		return "skip", item.DestinationPath, item.Checksum, nil
	case "overwrite":
		return "overwrite", item.DestinationPath, item.Checksum, nil
	case "rename":
		extension := path.Ext(item.DestinationPath)
		base := strings.TrimSuffix(item.DestinationPath, extension)
		for index := 1; index <= 10_000; index++ {
			candidate := fmt.Sprintf("%s (%d)%s", base, index, extension)
			_, exists, err := s.files.InspectCopyDestinationFiltered(ctx, mountID, candidate, "file", filter)
			if err != nil {
				return "", item.DestinationPath, "", err
			}
			if !exists {
				return "rename", candidate, item.Checksum, nil
			}
		}
		return "", item.DestinationPath, "", fmt.Errorf("%w: could not find an available conflict name", ErrInvalid)
	case "checksum":
		sourceChecksum, err := s.files.ChecksumFiltered(ctx, mountID, item.SourcePath, filter)
		if err != nil {
			return "", item.DestinationPath, "", err
		}
		destinationChecksum, err := s.files.ChecksumFiltered(ctx, mountID, item.DestinationPath, filter)
		if err != nil {
			return "", item.DestinationPath, "", err
		}
		if sourceChecksum == destinationChecksum {
			return "skip", item.DestinationPath, sourceChecksum, nil
		}
		return "overwrite", item.DestinationPath, sourceChecksum, nil
	default:
		return "conflict", item.DestinationPath, item.Checksum, nil
	}
}
