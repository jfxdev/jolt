package contracts

import "errors"

var (
	ErrNotFound             = errors.New("not found")
	ErrInUse                = errors.New("resource is in use")
	ErrIdempotencyConflict  = errors.New("idempotency key was reused with a different request")
	ErrUploadSessionExists  = errors.New("an upload session already targets this destination")
	ErrManagedConfiguration = errors.New("configuration is managed by file")
	ErrStateUnavailable     = errors.New("persistent state unavailable; restart required")

	// Cancellation causes for jobs whose signed authorization lapsed or whose
	// policy context changed while they were running.
	ErrJobAuthorizationUnavailable = errors.New("job authorization is unavailable or expired")
	ErrJobAuthorizationChanged     = errors.New("job authorization context changed")
)
