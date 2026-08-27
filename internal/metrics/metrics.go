// Package metrics provides optional Prometheus instrumentation for Turnstile: a
// /metrics endpoint, request counters/histograms for the Connect API, and a
// domain counter for Check decisions.
//
// It is created only when metrics are enabled (see config METRICS_ENABLED);
// when disabled the process-wide global stays nil and the record helpers
// (RecordCheck) are no-ops, so callers need no branch of their own.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus collectors for the server.
type Metrics struct {
	registry *prometheus.Registry
	httpReqs *prometheus.CounterVec   // labels: code
	httpDur  *prometheus.HistogramVec // labels: code
	checks   *prometheus.CounterVec   // labels: decision
}

// global is the process-wide instance, set by Enable. nil means metrics are
// disabled, which makes the package-level record helpers no-ops.
var global *Metrics

// Enable builds and registers the collectors (the standard Go runtime and
// process collectors plus Turnstile's own) and stores the instance as the
// process-wide global. Call it once at startup: each call uses a fresh registry,
// so a second call silently replaces the global rather than panicking.
func Enable() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := &Metrics{
		registry: reg,
		httpReqs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "turnstile", Subsystem: "http", Name: "requests_total",
			Help: "Connect API requests by response code.",
		}, []string{"code"}),
		httpDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "turnstile", Subsystem: "http", Name: "request_duration_seconds",
			Help: "Connect API request duration by response code.", Buckets: prometheus.DefBuckets,
		}, []string{"code"}),
		checks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "turnstile", Subsystem: "check", Name: "decisions_total",
			Help: "Check decisions by outcome (allowed, policy_denied, rate_limited, unauthenticated).",
		}, []string{"decision"}),
	}
	reg.MustRegister(m.httpReqs, m.httpDur, m.checks)
	global = m
	return m
}

// Handler serves the metrics in the Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Instrument wraps an HTTP handler with request-count and duration metrics. The
// promhttp delegators preserve http.Flusher and friends, so flushing/streaming
// responses (e.g. gRPC over HTTP/2) are unaffected.
func (m *Metrics) Instrument(next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerCounter(m.httpReqs,
		promhttp.InstrumentHandlerDuration(m.httpDur, next))
}

// RecordCheck counts a Check decision by outcome. decision should be the
// lowercased outcome, e.g. "allowed" or "rate_limited". It is a no-op when
// metrics are disabled.
func RecordCheck(decision string) {
	if global == nil {
		return
	}
	global.checks.WithLabelValues(decision).Inc()
}
