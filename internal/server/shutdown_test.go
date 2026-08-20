package server

import (
	"context"
	"testing"
	"time"
)

// TestShutdownGateDrains verifies Quiesce waits for an in-flight request, then
// rejects new ones and returns drained once the in-flight one leaves.
func TestShutdownGateDrains(t *testing.T) {
	g := NewShutdownGate()

	if !g.enter() {
		t.Fatal("gate should accept before shutdown")
	}

	done := make(chan bool, 1)
	go func() { done <- g.Quiesce(2 * time.Second) }()

	// With one request in flight, Quiesce must not return yet.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Quiesce returned while a request was still in flight")
	default:
	}

	// New requests are rejected during shutdown.
	if g.enter() {
		t.Fatal("gate should reject new requests during shutdown")
	}

	// Once the in-flight request leaves, Quiesce reports a clean drain.
	g.leave()
	select {
	case drained := <-done:
		if !drained {
			t.Error("Quiesce should report drained after the in-flight request left")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Quiesce did not return after the in-flight request left")
	}
}

// TestShutdownGateBoundedWait verifies a stuck request cannot make Quiesce hang:
// it returns false at the deadline instead of blocking forever.
func TestShutdownGateBoundedWait(t *testing.T) {
	g := NewShutdownGate()
	g.enter() // never leaves — simulates a client holding a stream open

	start := time.Now()
	if g.Quiesce(150 * time.Millisecond) {
		t.Error("Quiesce should report NOT drained with a stuck request")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("Quiesce returned too early (%v); should wait ~the timeout", elapsed)
	}
	g.leave() // cleanup
}

// TestShutdownGateCancelsContexts verifies Quiesce cancels the contexts linked
// to in-flight handlers, so a handler blocked on ctx unwinds promptly.
func TestShutdownGateCancelsContexts(t *testing.T) {
	g := NewShutdownGate()
	ctx, cancel := g.link(context.Background())
	defer cancel()

	go g.Quiesce(time.Second)

	select {
	case <-ctx.Done():
		// good — the linked handler context was cancelled by shutdown.
	case <-time.After(time.Second):
		t.Error("linked handler context should be cancelled by Quiesce")
	}
}
