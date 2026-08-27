package server

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
)

// ShutdownGate makes graceful shutdown correct even on the plaintext h2c path,
// where the HTTP/2 session runs on a hijacked connection that
// http.Server.Shutdown neither tracks nor drains. It is a Connect interceptor
// that, per RPC, (a) rejects new calls once shutdown has begun and (b) tracks
// in-flight calls and links their context to a root context we can cancel.
//
// On shutdown, Quiesce stops accepting, cancels the root context (so a handler
// blocked on slow work unwinds promptly instead of waiting on the client), and
// then waits — bounded by a deadline — for in-flight calls to finish before the
// caller drains the audit writer and closes the DB.
//
// The wait is always bounded: a slow or hostile client can never make shutdown
// hang. This matters even though every RPC is now unary — on the plaintext h2c
// path the HTTP/2 session runs on a hijacked connection that
// http.Server.Shutdown neither tracks nor drains, so the gate's cancel + bounded
// wait is the backstop for in-flight calls there.
type ShutdownGate struct {
	accepting atomic.Bool
	inflight  atomic.Int64
	rootCtx   context.Context
	cancel    context.CancelFunc
}

var errShuttingDown = errors.New("server is shutting down")

// NewShutdownGate returns a gate that is accepting requests.
func NewShutdownGate() *ShutdownGate {
	ctx, cancel := context.WithCancel(context.Background())
	g := &ShutdownGate{rootCtx: ctx, cancel: cancel}
	g.accepting.Store(true)
	return g
}

// enter admits a request if the gate is still accepting, counting it as
// in-flight. The increment happens before the accepting check, and Quiesce
// stores accepting=false before reading the in-flight count, so (under Go's
// sequentially consistent atomics) an admitted request is always observed by
// Quiesce's drain — closing the check-then-act window against DB close.
func (g *ShutdownGate) enter() bool {
	g.inflight.Add(1)
	if !g.accepting.Load() {
		g.inflight.Add(-1)
		return false
	}
	return true
}

func (g *ShutdownGate) leave() { g.inflight.Add(-1) }

// WrapUnary implements connect.Interceptor.
func (g *ShutdownGate) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !g.enter() {
			return nil, connect.NewError(connect.CodeUnavailable, errShuttingDown)
		}
		defer g.leave()
		ctx, cancel := g.link(ctx)
		defer cancel()
		return next(ctx, req)
	}
}

// WrapStreamingHandler implements connect.Interceptor (server side).
func (g *ShutdownGate) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if !g.enter() {
			return connect.NewError(connect.CodeUnavailable, errShuttingDown)
		}
		defer g.leave()
		ctx, cancel := g.link(ctx)
		defer cancel()
		return next(ctx, conn)
	}
}

// WrapStreamingClient implements connect.Interceptor; client-side calls are not
// gated, so it passes through.
func (g *ShutdownGate) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// link derives a cancellable child of ctx that is also cancelled when the gate's
// root context is cancelled (via Quiesce), without leaking a goroutine per
// request. The returned cancel must be called when the handler returns.
func (g *ShutdownGate) link(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.rootCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Quiesce stops accepting new requests, cancels in-flight handler contexts, and
// waits up to timeout for in-flight requests to drain. It returns true if they
// drained, false if the timeout elapsed first (in which case the caller should
// proceed anyway — at worst a few best-effort audit writes are lost, which is
// strictly better than hanging on a stuck or hostile client).
func (g *ShutdownGate) Quiesce(timeout time.Duration) (drained bool) {
	g.accepting.Store(false)
	g.cancel()

	if g.inflight.Load() == 0 {
		return true
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-deadline.C:
			return g.inflight.Load() == 0
		case <-poll.C:
			if g.inflight.Load() == 0 {
				return true
			}
		}
	}
}
