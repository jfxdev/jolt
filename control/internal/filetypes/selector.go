// Package filetypes defines the shared, filename-only selector semantics.
// It is not an authorization boundary until nodes apply the full policy context.
package filetypes

import (
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Selector struct {
	Classes    []string `json:"classes,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
	Names      []string `json:"names,omitempty"`
}

// Matcher is compiled once per policy context and can be reused for entries.
type Matcher struct {
	extensions map[string]bool
	names      map[string]bool
}

type class struct{ extensions, names map[string]bool }

func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

// Fixed tables deliberately do not infer content from extensions.
var classes = map[string]class{
	"video":      {extensions: set("mp4", "mkv", "avi", "mov", "webm", "m4v", "mpeg", "mpg", "ts")},
	"audio":      {extensions: set("mp3", "flac", "wav", "ogg", "m4a", "aac", "opus")},
	"image":      {extensions: set("jpg", "jpeg", "png", "gif", "webp", "svg", "avif", "bmp", "tif", "tiff")},
	"document":   {extensions: set("txt", "md", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "csv", "json", "xml", "yaml", "yml")},
	"archive":    {extensions: set("zip", "gz", "tar", "tgz", "7z", "rar", "bz2", "xz", "zst")},
	"executable": {extensions: set("exe", "dll", "msi", "com", "bat", "cmd", "ps1", "sh", "bash", "zsh", "elf", "bin", "so", "dylib", "appimage", "wasm")},
	"secret":     {extensions: set("env", "pem", "key", "p12", "pfx", "p8", "jks", "kdbx"), names: set(".env", "acme.json", "id_rsa", "id_ed25519")},
}

// Validate rejects invalid and excessive selectors instead of dropping them.
func (s Selector) Validate() error {
	count := len(s.Classes) + len(s.Extensions) + len(s.Names)
	if count == 0 || count > 64 {
		return errors.New("file types require 1 to 64 selectors")
	}
	seen := make(map[string]bool, count)
	for _, value := range s.Classes {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := classes[value]; !ok || seen["c:"+value] {
			return errors.New("invalid or duplicate class")
		}
		seen["c:"+value] = true
	}
	for _, value := range s.Extensions {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || utf8.RuneCountInString(value) > 128 || seen["e:"+value] {
			return errors.New("invalid or duplicate extension")
		}
		for _, r := range value {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '+' {
				return errors.New("invalid extension")
			}
		}
		seen["e:"+value] = true
	}
	for _, value := range s.Names {
		value = strings.ToLower(value)
		if value == "" || value == "." || value == ".." || !utf8.ValidString(value) || strings.ContainsAny(value, "/\\\x00") || utf8.RuneCountInString(value) > 255 || seen["n:"+value] {
			return errors.New("invalid or duplicate name")
		}
		seen["n:"+value] = true
	}
	return nil
}

// Matches uses a union of classes, extensions and exact names, and only
// matches regular file entries. Directories remain governed by path rules.
func (s Selector) Compile() (*Matcher, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	matcher := &Matcher{extensions: map[string]bool{}, names: map[string]bool{}}
	for _, name := range s.Names {
		matcher.names[strings.ToLower(name)] = true
	}
	for _, extension := range s.Extensions {
		matcher.extensions[strings.ToLower(strings.TrimSpace(extension))] = true
	}
	for _, value := range s.Classes {
		entry := classes[strings.ToLower(strings.TrimSpace(value))]
		for extension := range entry.extensions {
			matcher.extensions[extension] = true
		}
		for name := range entry.names {
			matcher.names[name] = true
		}
	}
	return matcher, nil
}

func (m *Matcher) Matches(name string, isFile bool) bool {
	if m == nil || !isFile || name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	name = strings.ToLower(name)
	return m.names[name] || m.extensions[strings.TrimPrefix(path.Ext(name), ".")]
}

func (s Selector) Matches(name string, isFile bool) bool {
	matcher, err := s.Compile()
	return err == nil && matcher.Matches(name, isFile)
}
