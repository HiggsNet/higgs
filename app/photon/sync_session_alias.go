package main

import "github.com/HiggsNet/photon/pkg/core/gossip"

// These aliases keep the Linux daemon surface stable while the portable
// state machine lives in a package that Photon Windows can import directly.
type SyncSessionState = gossip.SyncSessionState

const (
	SyncSessionIdle           = gossip.SyncSessionIdle
	SyncSessionPingSent       = gossip.SyncSessionPingSent
	SyncSessionSummarySent    = gossip.SyncSessionSummarySent
	SyncSessionCatalogDiffing = gossip.SyncSessionCatalogDiffing
	SyncSessionObjectPulling  = gossip.SyncSessionObjectPulling
	SyncSessionChunkFallback  = gossip.SyncSessionChunkFallback
	SyncSessionCompleted      = gossip.SyncSessionCompleted
	SyncSessionFailed         = gossip.SyncSessionFailed

	MinCatalogPageTimeout = gossip.MinCatalogPageTimeout
	MinRoundTimeout       = gossip.MinRoundTimeout
	ObjectPullBudget      = gossip.ObjectPullBudget
	InitialRTT            = gossip.InitialRTT
)

type SyncEvent = gossip.SyncEvent
type SyncTimerEvent = gossip.SyncTimerEvent
type PongReceivedEvent = gossip.PongReceivedEvent
type CatalogSummaryReceivedEvent = gossip.CatalogSummaryReceivedEvent
type CatalogPageReceivedEvent = gossip.CatalogPageReceivedEvent
type CatalogPageTimeoutEvent = gossip.CatalogPageTimeoutEvent
type RoundTimeoutEvent = gossip.RoundTimeoutEvent
type ObjectPullResultEvent = gossip.ObjectPullResultEvent
type ObjectChunkEvent = gossip.ObjectChunkEvent

type SyncAction = gossip.SyncAction
type SendPingAction = gossip.SendPingAction
type SendFetchZoneAction = gossip.SendFetchZoneAction
type SendFetchCatalogPageAction = gossip.SendFetchCatalogPageAction
type SendCatalogPageAction = gossip.SendCatalogPageAction
type StartObjectPullAction = gossip.StartObjectPullAction
type ApplySnapshotAction = gossip.ApplySnapshotAction
type SyncPersistenceScope = gossip.SyncPersistenceScope

const (
	SyncPersistenceUnspecified = gossip.SyncPersistenceUnspecified
	SyncPersistenceMeta        = gossip.SyncPersistenceMeta
	SyncPersistenceNetwork     = gossip.SyncPersistenceNetwork
)

type SaveStateAction = gossip.SaveStateAction
type RecordBackoffAction = gossip.RecordBackoffAction
type StartTimerAction = gossip.StartTimerAction
type CancelTimerAction = gossip.CancelTimerAction
type SyncSession = gossip.SyncSession

func NewSyncSession(peerID string) *SyncSession {
	return gossip.NewSyncSession(peerID)
}
