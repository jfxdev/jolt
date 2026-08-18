package contracts

import (
	"context"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

type Store interface {
	Close() error
	ListMounts(context.Context) ([]entities.Mount, error)
	GetMount(context.Context, string) (entities.Mount, error)
	UpsertMount(context.Context, entities.Mount) error
	DeleteMount(context.Context, string) error
	GetOperationalTokenState(context.Context) (entities.OperationalTokenState, error)
	StageOperationalToken(context.Context, string, string, time.Time) error
	CommitOperationalToken(context.Context, string, string, time.Time) error
	CreateJob(context.Context, entities.Job, string) (entities.Job, bool, error)
	CreateJobWithItems(context.Context, entities.Job, []entities.JobItem, string) (entities.Job, bool, error)
	UpdateJob(context.Context, entities.Job) error
	ListJobs(context.Context, int) ([]entities.Job, error)
	ListJobsByPeer(context.Context, string) ([]entities.Job, error)
	GetJob(context.Context, string) (entities.Job, error)
	ClaimNextJob(context.Context, time.Time) (entities.Job, error)
	RecoverRunningJobs(context.Context, time.Time) ([]entities.Job, error)
	WakeWaitingPeerJobs(context.Context, string, time.Time) ([]entities.Job, error)
	WakeWaitingMountJobs(context.Context, string, time.Time) ([]entities.Job, error)
	RecordJobEvent(context.Context, entities.JobEvent) (entities.JobEvent, error)
	ListJobEvents(context.Context, int64, string, int) ([]entities.JobEvent, error)
	ReplaceJobItems(context.Context, string, []entities.JobItem) error
	ListJobItems(context.Context, string) ([]entities.JobItem, error)
	UpdateJobItem(context.Context, entities.JobItem) error
	CreatePairingInvite(context.Context, entities.PairingInvite, string) error
	ListPairingInvites(context.Context) ([]entities.PairingInvite, error)
	GetPairingInvite(context.Context, string) (entities.PairingInvite, error)
	RevokePairingInvite(context.Context, string, time.Time) error
	CreatePairingRequest(context.Context, entities.PairingRequest, string) error
	ListPairingRequests(context.Context) ([]entities.PairingRequest, error)
	GetPairingRequest(context.Context, string) (entities.PairingRequest, error)
	ApprovePairingInvite(context.Context, string, string, entities.Peer, time.Time) error
	ResolvePairingRequest(context.Context, string, string, *entities.Peer, time.Time) error
	ListPeers(context.Context) ([]entities.Peer, error)
	GetPeer(context.Context, string) (entities.Peer, error)
	UpdatePeerHealth(context.Context, string, string, *time.Time, int) error
	UpdatePeerEndpoints(context.Context, string, string, string, string) error
	RecoverPeerIdentity(context.Context, string, string, string) error
	ApplyPeerIdentityHandover(context.Context, string, int, string, int, string, string) error
	ConfirmPeerIdentityHandover(context.Context, string, int, string) error
	RevokePeer(context.Context, string, string, time.Time) error
	CreateTransferGrant(context.Context, entities.TransferPathGrant) error
	UpdateTransferGrant(context.Context, entities.TransferPathGrant) error
	ListTransferGrants(context.Context) ([]entities.TransferPathGrant, error)
	GetTransferGrant(context.Context, string) (entities.TransferPathGrant, error)
	DeleteTransferGrant(context.Context, string, string, time.Time) error
}
