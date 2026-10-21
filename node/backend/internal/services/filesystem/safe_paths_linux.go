package filesystem

import (
	"golang.org/x/sys/unix"
	"time"
)

func statTime(st unix.Stat_t) time.Time { return time.Unix(st.Mtim.Sec, st.Mtim.Nsec) }
func renameNoReplace(from int, source string, to int, destination string) error {
	return unix.Renameat2(from, source, to, destination, unix.RENAME_NOREPLACE)
}

const directorySearchFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
