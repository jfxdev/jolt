package contracts

import "errors"

var (
	ErrNotFound             = errors.New("not found")
	ErrInUse                = errors.New("resource is in use")
	ErrIdempotencyConflict  = errors.New("idempotency key was reused with a different request")
	ErrUploadSessionExists  = errors.New("an upload session already targets this destination")
	ErrManagedConfiguration = errors.New("configuration is managed by file")
	ErrStateUnavailable     = errors.New("persistent state unavailable; restart required")
)
