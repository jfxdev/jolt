package filesystem

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
)

var ErrUploadContentRejected = errors.New("upload content rejected")

type UploadInspection struct {
	Enabled           bool
	BlockExecutables  bool
	AllowedMediaTypes []string
}

// ConfigureUploadInspection is called before serving requests, after reading
// node.yaml. Configuration changes require a restart.
func (s *Service) ConfigureUploadInspection(policy UploadInspection) {
	policy.AllowedMediaTypes = append([]string(nil), policy.AllowedMediaTypes...)
	s.uploadInspection = policy
}

func (s *Service) inspectUpload(file *os.File) error {
	policy := s.uploadInspection
	if !policy.Enabled {
		return nil
	}
	var buffer [512]byte
	n, err := file.ReadAt(buffer[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	prefix := buffer[:n]
	if policy.BlockExecutables && executableSignature(prefix) {
		return ErrUploadContentRejected
	}
	if len(policy.AllowedMediaTypes) > 0 {
		detected, _, err := mime.ParseMediaType(http.DetectContentType(prefix))
		if err != nil {
			return ErrUploadContentRejected
		}
		for _, allowed := range policy.AllowedMediaTypes {
			if detected == allowed {
				return nil
			}
		}
		return ErrUploadContentRejected
	}
	return nil
}

func executableSignature(prefix []byte) bool {
	for _, signature := range [][]byte{
		[]byte("\x7fELF"), []byte("MZ"), []byte("#!"), []byte("\x00asm"),
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
		{0xca, 0xfe, 0xba, 0xbf}, {0xbf, 0xba, 0xfe, 0xca},
	} {
		if bytes.HasPrefix(prefix, signature) {
			return true
		}
	}
	return false
}
