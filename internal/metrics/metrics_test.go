package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecordCheckNoopWhenDisabled(t *testing.T) {
	// Before Enable, the process-wide global is nil and RecordCheck must be a
	// safe no-op rather than panicking.
	global = nil
	RecordCheck("allowed") // must not panic
}

func TestMetricsEndpointAndCounters(t *testing.T) {
	m := Enable()

	// Domain counter: two allowed decisions, one denied.
	RecordCheck("allowed")
	RecordCheck("allowed")
	RecordCheck("policy_denied")

	// HTTP instrumentation: one request through the wrapped handler.
	wrapped := m.Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/turnstile.v1.Turnstile/Check", nil))

	// Scrape /metrics and assert the expected series are present.
	scrape := httptest.NewRecorder()
	m.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if scrape.Code != http.StatusOK {
		t.Fatalf("metrics endpoint status = %d, want 200", scrape.Code)
	}
	body, _ := io.ReadAll(scrape.Body)
	out := string(body)

	for _, want := range []string{
		`turnstile_check_decisions_total{decision="allowed"} 2`,
		`turnstile_check_decisions_total{decision="policy_denied"} 1`,
		`turnstile_http_requests_total{code="200"} 1`,
		"go_goroutines", // standard Go collector is registered
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}
