package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newClockManager builds a Manager whose clock is driven by the returned
// pointer, so tests advance time deterministically.
func newClockManager(g Global) (*Manager, *time.Time) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	m := New(g)
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestAllow_PerKeyBurstThenBlock(t *testing.T) {
	g := Global{PerKey: Config{Default: &Limit{PerMinute: 60, Burst: 1}}}
	m, _ := newClockManager(g)

	if ok, _ := m.Allow("k1", nil, "svc:read"); !ok {
		t.Fatal("first call should be allowed (burst 1)")
	}
	ok, retry := m.Allow("k1", nil, "svc:read")
	if ok {
		t.Fatal("second immediate call should be blocked")
	}
	if retry <= 0 {
		t.Errorf("blocked call should report a positive retryAfter, got %v", retry)
	}
}

func TestAllow_Unlimited(t *testing.T) {
	m, _ := newClockManager(Global{}) // no limits configured anywhere
	for i := 0; i < 100; i++ {
		if ok, _ := m.Allow("k1", nil, "svc:read"); !ok {
			t.Fatalf("call %d should be allowed when unlimited", i)
		}
	}
}

func TestAllow_KeyOverrideBeatsGlobalDefault(t *testing.T) {
	// Global default is generous; the key's per-action override is stricter and
	// wins for that action.
	g := Global{PerKey: Config{Default: &Limit{PerMinute: 6000, Burst: 100}}}
	m, _ := newClockManager(g)
	keyLimits := PerActionLimits{"svc:read": {PerMinute: 60, Burst: 1}}

	if ok, _ := m.Allow("k1", keyLimits, "svc:read"); !ok {
		t.Fatal("first call should be allowed")
	}
	if ok, _ := m.Allow("k1", keyLimits, "svc:read"); ok {
		t.Fatal("second call should be blocked by the key's stricter override")
	}
}

// TestAllow_RefundsOnBlock verifies the reserve-then-confirm behavior: when the
// per-key limiter blocks, the service-wide reservation is refunded so a block on
// one limiter never burns a token on the other.
func TestAllow_RefundsOnBlock(t *testing.T) {
	g := Global{
		PerKey:      Config{Default: &Limit{PerMinute: 600, Burst: 1}}, // recovers ~10/s
		ServiceWide: Config{Default: &Limit{PerMinute: 6, Burst: 2}},   // recovers ~0.1/s
	}
	m, clock := newClockManager(g)

	// call1: both limiters allow. service-wide now has ~1 token left.
	if ok, _ := m.Allow("k1", nil, "svc:read"); !ok {
		t.Fatal("call1 should be allowed")
	}
	// call2 (same instant): per-key blocks. If the service-wide reservation is
	// correctly refunded, service-wide still has ~1 token.
	if ok, _ := m.Allow("k1", nil, "svc:read"); ok {
		t.Fatal("call2 should be blocked by the per-key limiter")
	}
	// Advance just enough for the per-key bucket to refill (service-wide barely
	// moves at 0.1/s).
	*clock = clock.Add(200 * time.Millisecond)
	// call3: per-key recovered; service-wide must still have its refunded token.
	if ok, _ := m.Allow("k1", nil, "svc:read"); !ok {
		t.Fatal("call3 should be allowed — service-wide token must not have been burned on the blocked call2")
	}
	// call4: service-wide is now exhausted, so this blocks regardless of per-key.
	*clock = clock.Add(200 * time.Millisecond)
	if ok, _ := m.Allow("k1", nil, "svc:read"); ok {
		t.Fatal("call4 should be blocked by the exhausted service-wide limiter")
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{Default: &Limit{PerMinute: -1}},
		{Default: &Limit{Burst: -5}},
		{PerAction: map[string]Limit{"a": {PerMinute: maxPerMinute + 1}}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	good := Config{Default: &Limit{PerMinute: 100, Burst: 10}, PerAction: map[string]Limit{"a": {PerMinute: 5}}}
	if err := good.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestEvictIdle(t *testing.T) {
	g := Global{
		PerKey:      Config{Default: &Limit{PerMinute: 600, Burst: 1}},
		ServiceWide: Config{Default: &Limit{PerMinute: 600, Burst: 1}},
	}
	m, clock := newClockManager(g)

	// A request creates per-key and service-wide limiters and consumes their
	// single token, so they are not yet idle.
	if ok, _ := m.Allow("k1", nil, "svc:read"); !ok {
		t.Fatal("first call should be allowed")
	}
	m.EvictIdle()
	if len(m.keyLim) == 0 || len(m.svcLim) == 0 {
		t.Fatal("in-use limiters must not be evicted")
	}

	// After enough time to refill to full capacity, they are idle and evicted.
	*clock = clock.Add(time.Minute)
	m.EvictIdle()
	if len(m.keyLim) != 0 {
		t.Errorf("idle per-key limiters should be evicted, have %d keys", len(m.keyLim))
	}
	if len(m.svcLim) != 0 {
		t.Errorf("idle service-wide limiters should be evicted, have %d", len(m.svcLim))
	}
}

// TestManagerConcurrent exercises the shared Manager under concurrent Allow,
// SetGlobal, and ForgetKey — meant to be run under `go test -race`.
func TestManagerConcurrent(t *testing.T) {
	m := New(Global{
		PerKey:      Config{Default: &Limit{PerMinute: 6000, Burst: 100}},
		ServiceWide: Config{Default: &Limit{PerMinute: 60000, Burst: 1000}},
	})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i%5)
			for j := 0; j < 50; j++ {
				m.Allow(key, PerActionLimits{"svc:read": {PerMinute: 1200}}, "svc:read")
			}
		}(i)
	}
	// Concurrently mutate global config and evict keys while Allow runs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			m.SetGlobal(Global{ServiceWide: Config{Default: &Limit{PerMinute: 60000, Burst: 1000}}})
			m.ForgetKey(fmt.Sprintf("k%d", j%5))
		}
	}()
	wg.Wait()
}
