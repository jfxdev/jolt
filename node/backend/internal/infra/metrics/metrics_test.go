package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func render(t *testing.T, registry *Registry) string {
	t.Helper()
	var builder strings.Builder
	if err := registry.Write(&builder); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return builder.String()
}

func requireLine(t *testing.T, output, line string) {
	t.Helper()
	for _, candidate := range strings.Split(output, "\n") {
		if candidate == line {
			return
		}
	}
	t.Fatalf("missing line %q in:\n%s", line, output)
}

func TestCounterRendersLabelsInPrometheusFormat(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("jolt_http_requests_total", "Requests.", "method", "route", "status")
	registry.Inc("jolt_http_requests_total", "GET", "/api/v1/mounts", "200")
	registry.Inc("jolt_http_requests_total", "GET", "/api/v1/mounts", "200")
	registry.Inc("jolt_http_requests_total", "PUT", "/api/v1/mounts", "500")

	output := render(t, registry)
	requireLine(t, output, "# TYPE jolt_http_requests_total counter")
	requireLine(t, output, `jolt_http_requests_total{method="GET",route="/api/v1/mounts",status="200"} 2`)
	requireLine(t, output, `jolt_http_requests_total{method="PUT",route="/api/v1/mounts",status="500"} 1`)
}

func TestCounterWithoutLabelsAndUnknownNameIsSafe(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("jolt_events_total", "Events.")
	registry.Inc("jolt_events_total")
	// An unregistered metric and a label-count mismatch must both be no-ops
	// rather than panics: metrics must never break a request path.
	registry.Inc("jolt_missing_total", "a")
	registry.Inc("jolt_events_total", "unexpected")

	output := render(t, registry)
	requireLine(t, output, "jolt_events_total 1")
	if strings.Contains(output, "jolt_missing_total") {
		t.Fatal("unregistered metric was rendered")
	}
}

func TestGaugeSetAddAndFunc(t *testing.T) {
	registry := NewRegistry()
	registry.Gauge("jolt_jobs_active", "Active jobs.", "type")
	registry.SetGauge("jolt_jobs_active", 3, "upload")
	registry.AddGauge("jolt_jobs_active", -1, "upload")
	registry.GaugeFunc("jolt_sampled", "Sampled.", func() float64 { return 1.5 })

	output := render(t, registry)
	requireLine(t, output, `jolt_jobs_active{type="upload"} 2`)
	requireLine(t, output, "jolt_sampled 1.5")
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	registry := NewRegistry()
	registry.Histogram("jolt_request_seconds", "Latency.", []float64{0.1, 1}, "route")
	registry.Observe("jolt_request_seconds", 0.05, "/health")
	registry.Observe("jolt_request_seconds", 0.5, "/health")
	registry.Observe("jolt_request_seconds", 5, "/health")

	output := render(t, registry)
	requireLine(t, output, "# TYPE jolt_request_seconds histogram")
	requireLine(t, output, `jolt_request_seconds_bucket{route="/health",le="0.1"} 1`)
	requireLine(t, output, `jolt_request_seconds_bucket{route="/health",le="1"} 2`)
	requireLine(t, output, `jolt_request_seconds_bucket{route="/health",le="+Inf"} 3`)
	requireLine(t, output, `jolt_request_seconds_count{route="/health"} 3`)
	requireLine(t, output, `jolt_request_seconds_sum{route="/health"} 5.55`)
}

func TestObserveDurationRecordsASample(t *testing.T) {
	registry := NewRegistry()
	registry.Histogram("jolt_op_seconds", "Op.", nil)
	registry.ObserveDuration("jolt_op_seconds", time.Now())
	requireLine(t, render(t, registry), "jolt_op_seconds_count 1")
}

func TestLabelValuesAreEscaped(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("jolt_paths_total", "Paths.", "path")
	registry.Inc("jolt_paths_total", `with "quote" and \slash`)
	requireLine(t, render(t, registry), `jolt_paths_total{path="with \"quote\" and \\slash"} 1`)
}

func TestConcurrentUpdatesAreRaceFree(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("jolt_concurrent_total", "Concurrent.", "worker")
	registry.Histogram("jolt_concurrent_seconds", "Concurrent.", nil, "worker")
	registry.Gauge("jolt_concurrent_active", "Concurrent.", "worker")

	var waitGroup sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < 200; iteration++ {
				registry.Inc("jolt_concurrent_total", "shared")
				registry.Observe("jolt_concurrent_seconds", 0.01, "shared")
				registry.AddGauge("jolt_concurrent_active", 1, "shared")
			}
		}()
	}
	// Scraping concurrently with writers is the normal production pattern.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for iteration := 0; iteration < 50; iteration++ {
			_ = render(t, registry)
		}
	}()
	waitGroup.Wait()

	output := render(t, registry)
	requireLine(t, output, `jolt_concurrent_total{worker="shared"} 1600`)
	requireLine(t, output, `jolt_concurrent_seconds_count{worker="shared"} 1600`)
	requireLine(t, output, `jolt_concurrent_active{worker="shared"} 1600`)
}

func TestReregisteringKeepsExistingMetric(t *testing.T) {
	registry := NewRegistry()
	registry.Counter("jolt_once_total", "First.")
	registry.Inc("jolt_once_total")
	registry.Counter("jolt_once_total", "Second.")
	output := render(t, registry)
	requireLine(t, output, "jolt_once_total 1")
	if strings.Count(output, "# TYPE jolt_once_total") != 1 {
		t.Fatalf("metric registered twice:\n%s", output)
	}
}

func TestRegisterRuntimeExposesGoroutines(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterRuntime()
	output := render(t, registry)
	if !strings.Contains(output, "go_goroutines ") {
		t.Fatalf("runtime metrics missing:\n%s", output)
	}
}
