package main

import (
	"maps"
	"time"
)

const (
	defaultMetadataCheckpointMaxDelay = time.Minute
	defaultMetadataCheckpointRetry    = time.Second
	defaultMetadataCheckpointRetryMax = time.Minute
)

type metadataCheckpointState struct {
	dirty         bool
	dirtyRevision uint64
	due           time.Time
	retry         time.Duration
}

func (d *DaemonService) markMetadataCheckpointDirty() {
	if d == nil || d.StateStore == nil {
		return
	}
	now := d.metadataCheckpointNow()
	revision := d.StateStore.Meta().Revision
	maxDelay := d.Interval
	if maxDelay <= 0 || maxDelay > defaultMetadataCheckpointMaxDelay {
		maxDelay = defaultMetadataCheckpointMaxDelay
	}

	d.metadataCheckpointMu.Lock()
	defer d.metadataCheckpointMu.Unlock()
	checkpoint := &d.metadataCheckpoint
	if !checkpoint.dirty {
		checkpoint.dirty = true
		// Schedule from the first dirty update, rather than sliding the due
		// time on every peer response. This gives the in-memory batch a strict
		// upper bound even while sync traffic remains continuous.
		checkpoint.due = now.Add(maxDelay)
	}
	if revision > checkpoint.dirtyRevision {
		checkpoint.dirtyRevision = revision
	}
}

func (d *DaemonService) metadataCheckpointDue() time.Time {
	if d == nil {
		return time.Time{}
	}
	d.metadataCheckpointMu.Lock()
	defer d.metadataCheckpointMu.Unlock()
	if !d.metadataCheckpoint.dirty {
		return time.Time{}
	}
	return d.metadataCheckpoint.due
}

func (d *DaemonService) flushMetadataCheckpoint(force bool) error {
	if d == nil || d.StateStore == nil {
		return nil
	}
	now := d.metadataCheckpointNow()
	d.metadataCheckpointMu.Lock()
	checkpoint := d.metadataCheckpoint
	if !checkpoint.dirty || (!force && checkpoint.due.After(now)) {
		d.metadataCheckpointMu.Unlock()
		return nil
	}
	d.metadataCheckpointMu.Unlock()

	var err error
	if d.metadataCheckpointSave != nil {
		saveRevision := d.StateStore.Meta().Revision
		err = d.metadataCheckpointSave()
		if err == nil {
			d.noteMetadataPersisted(saveRevision)
		}
	} else {
		err = d.saveCommittedMeta()
	}
	if err == nil {
		return nil
	}

	d.metadataCheckpointMu.Lock()
	defer d.metadataCheckpointMu.Unlock()
	if d.metadataCheckpoint.dirty {
		retry := d.metadataCheckpoint.retry
		if retry <= 0 {
			retry = defaultMetadataCheckpointRetry
		} else if retry < defaultMetadataCheckpointRetryMax {
			retry *= 2
			if retry > defaultMetadataCheckpointRetryMax {
				retry = defaultMetadataCheckpointRetryMax
			}
		}
		d.metadataCheckpoint.retry = retry
		d.metadataCheckpoint.due = now.Add(retry)
	}
	return err
}

func (d *DaemonService) metadataCheckpointNow() time.Time {
	if d != nil && d.Sync != nil {
		return d.Sync.now()
	}
	return time.Now()
}

func (d *DaemonService) noteMetadataPersisted(revision uint64) {
	if d == nil {
		return
	}
	d.metadataCheckpointMu.Lock()
	defer d.metadataCheckpointMu.Unlock()
	if !d.metadataCheckpoint.dirty || revision < d.metadataCheckpoint.dirtyRevision {
		return
	}
	d.metadataCheckpoint = metadataCheckpointState{}
}

func (d *DaemonService) rebasePendingPeerMetadata(latest *stateFile) bool {
	if d == nil || latest == nil || d.StateStore == nil {
		return false
	}
	d.metadataCheckpointMu.Lock()
	dirty := d.metadataCheckpoint.dirty
	d.metadataCheckpointMu.Unlock()
	if !dirty {
		return false
	}
	current, _ := d.StateStore.Snapshot()
	if current == nil {
		return false
	}
	latest.SyncPeers = cloneSyncPeers(current.SyncPeers)
	latest.PeerCleanups = maps.Clone(current.PeerCleanups)
	return true
}

func (d *DaemonService) advanceMetadataCheckpointRevision(revision uint64) {
	if d == nil {
		return
	}
	d.metadataCheckpointMu.Lock()
	defer d.metadataCheckpointMu.Unlock()
	if d.metadataCheckpoint.dirty && revision > d.metadataCheckpoint.dirtyRevision {
		d.metadataCheckpoint.dirtyRevision = revision
	}
}

func (d *DaemonService) flushMetadataCheckpointOnShutdown() {
	if err := d.flushMetadataCheckpoint(true); err != nil {
		d.logWarn("state", "metadata_checkpoint_shutdown_failed", map[string]any{"error": err})
	}
}
