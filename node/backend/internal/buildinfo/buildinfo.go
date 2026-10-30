package buildinfo

var (
	Version = "development"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"build_date"`
}

func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}
