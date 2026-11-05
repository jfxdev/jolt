package filesystem

import (
	"io/fs"
	"time"
)

// entryInfo lets the access filter judge an entry known only by its path and
// type, such as one listed in a peer's manifest.
type entryInfo struct{ dir bool }

func (entryInfo) Name() string       { return "" }
func (entryInfo) Size() int64        { return 0 }
func (entryInfo) ModTime() time.Time { return time.Time{} }
func (entryInfo) Sys() any           { return nil }
func (e entryInfo) IsDir() bool      { return e.dir }
func (e entryInfo) Mode() fs.FileMode {
	if e.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}

// AllowsListedEntry reports whether a file would be listed and readable, or a
// directory listed and traversable, for an entry given by its mount-relative
// path. kind is "file" or "directory"; anything else is refused.
func (f *AccessFilter) AllowsListedEntry(relative, kind string) bool {
	if f == nil || (kind != "file" && kind != "directory") {
		return false
	}
	decision := f.decide(relative, entryInfo{dir: kind == "directory"})
	if kind == "directory" {
		return decision.visible && decision.traversable
	}
	return decision.visible && decision.readable
}
