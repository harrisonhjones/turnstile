// Package audit persists the audit entries Turnstile records itself — one per
// Check decision, and one per management mutation or denied attempt (there is no
// host-reported intake). The Writer drains them from a single background consumer
// so writes are serialized (matching SQLite's single-writer model) and their id
// order tracks arrival, and it drains in-flight entries at shutdown so the last
// ones aren't lost to a closing DB. Retention prunes old entries on a periodic
// loop.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"harrisonhjones.com/turnstile/internal/metrics"
	"harrisonhjones.com/turnstile/internal/store"
)

// queueSize bounds the in-memory backlog of pending audit writes. Once full,
// Write drops the entry rather than blocking — Check records audit on the hot
// path, so a full queue must never stall a request. Dropped entries are counted
// and logged; audit completeness yields to hot-path latency under overload.
const queueSize = 1024

// Writer persists audit entries from a single background goroutine.
type Writer struct {
	store    *store.Store
	ch       chan *store.AuditEntry
	stopping chan struct{} // closed by Wait to signal shutdown
	done     chan struct{} // closed by the consumer when it has drained and exited
	stopOnce sync.Once
	dropped  atomic.Int64 // entries dropped because the queue was full
}

// NewWriter creates a Writer and starts its background consumer.
func NewWriter(s *store.Store) *Writer {
	w := &Writer{
		store:    s,
		ch:       make(chan *store.AuditEntry, queueSize),
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.run()
	return w
}

// Write enqueues an entry for the background consumer and reports whether it was
// accepted. It NEVER blocks: if the queue is full it drops the entry and returns
// false (audit completeness yields to hot-path latency, since Check records audit
// inline). It also drops once shutdown has begun — after Wait signals stopping,
// enqueuing into a channel whose consumer is draining/exited would be unsafe.
//
// The stopping check is prioritized (a non-blocking pre-check) so that once
// shutdown has begun, Write deterministically drops rather than racing the
// consumer's drain.
func (w *Writer) Write(e *store.AuditEntry) bool {
	select {
	case <-w.stopping:
		slog.Warn("audit writer stopping; dropping entry", "api_key_id", e.APIKeyID)
		return false
	default:
	}
	select {
	case w.ch <- e:
		return true
	case <-w.stopping:
		slog.Warn("audit writer stopping; dropping entry", "api_key_id", e.APIKeyID)
		return false
	default:
		// Queue full — drop rather than block the caller (e.g. the Check hot path).
		metrics.RecordAuditDrop()
		n := w.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			slog.Warn("audit queue full; dropping entries", "dropped_total", n)
		}
		return false
	}
}

// run is the single consumer: it serializes inserts, and on stopping drains
// whatever is already queued before exiting.
func (w *Writer) run() {
	defer close(w.done)
	for {
		select {
		case e := <-w.ch:
			w.insert(e)
		case <-w.stopping:
			// Drain the remaining buffered entries without blocking, then exit.
			for {
				select {
				case e := <-w.ch:
					w.insert(e)
				default:
					return
				}
			}
		}
	}
}

// insert persists one entry with a bounded timeout. Failures are logged, not
// surfaced to the caller (audit is best-effort).
func (w *Writer) insert(e *store.AuditEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.store.InsertAuditEntry(ctx, e); err != nil {
		slog.Error("failed to write audit entry", "error", err, "api_key_id", e.APIKeyID)
	}
}

// Wait signals the consumer to drain its queue and stop, then blocks until it
// has finished. Call it during graceful shutdown, before closing the store, so
// queued entries aren't dropped by a race against a closing DB. It is safe to
// call more than once.
func (w *Writer) Wait() {
	w.stopOnce.Do(func() { close(w.stopping) })
	<-w.done
}
