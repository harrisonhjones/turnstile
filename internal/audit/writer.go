// Package audit records one entry per authenticated request. Hosts report
// entries after a request completes (status and latency aren't known until
// then) via the ReportAudit RPC (a unary batch call). The Writer persists them from a
// single background consumer so writes are serialized (matching SQLite's
// single-writer model) and their id order tracks arrival, and it drains
// in-flight entries at shutdown so the last ones aren't lost to a closing DB.
// Retention prunes old entries on a periodic loop.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/harrisonhjones/turnstile/internal/store"
)

// queueSize bounds the in-memory backlog of pending audit writes. Once full,
// Write blocks (backpressure to the ReportAudit caller) rather than spawning
// unbounded goroutines or growing memory without limit.
const queueSize = 1024

// Writer persists audit entries from a single background goroutine.
type Writer struct {
	store    *store.Store
	ch       chan *store.AuditEntry
	stopping chan struct{} // closed by Wait to signal shutdown
	done     chan struct{} // closed by the consumer when it has drained and exited
	stopOnce sync.Once
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
// accepted. It applies backpressure when the queue is full (blocking the
// caller), but never blocks past shutdown: once Wait has signaled stopping, the
// entry is dropped (with a log line) and Write returns false rather than
// deadlocking or enqueuing into a channel whose consumer has exited.
//
// The stopping check is prioritized (a non-blocking pre-check) so that once
// shutdown has begun, Write deterministically drops rather than racing the
// consumer's drain. In the server, the ShutdownGate quiesces all handlers before
// Wait is called, so no Write races shutdown in practice; this just makes the
// primitive safe on its own.
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
