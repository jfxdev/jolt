// Package metrics exposes Prometheus text-format metrics without pulling in a
// client library. The surface is deliberately small — counters, gauges and
// fixed-bucket histograms — because that is all the node and the Control Tower
// need, and a self-hosted deployment should not inherit a dependency tree for
// it.
package metrics

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBuckets covers sub-millisecond API calls through the multi-second
// range where a slow mount or a large listing shows up.
var DefaultBuckets = []float64{0.005, 0.025, 0.1, 0.25, 1, 2.5, 10, 30}

type labelKey string

func makeLabelKey(names, values []string) labelKey {
	if len(names) == 0 {
		return ""
	}
	var builder strings.Builder
	for index, name := range names {
		if index > 0 {
			builder.WriteByte(keySeparator)
		}
		builder.WriteString(name)
		builder.WriteByte(keyAssign)
		builder.WriteString(escapeLabelValue(values[index]))
	}
	return labelKey(builder.String())
}

// The key packs "name=value" pairs into one comparable string. The separators
// are control characters that cannot occur in a label value, so a value
// containing "," or "=" cannot forge an extra pair when the key is rendered
// back into Prometheus syntax.
const (
	keySeparator = '\x1f'
	keyAssign    = '\x1e'
)

// escapeLabelValue applies the escaping the exposition format requires. Control
// characters are dropped rather than escaped: they are never meaningful in a
// label and two of them are reserved as key separators.
func escapeLabelValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return replacer.Replace(value)
}

// Registry holds every metric for one process.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*counterVec
	gauges     map[string]*gaugeVec
	histograms map[string]*histogramVec
	order      []string
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   map[string]*counterVec{},
		gauges:     map[string]*gaugeVec{},
		histograms: map[string]*histogramVec{},
	}
}

type counterVec struct {
	help   string
	labels []string
	mu     sync.RWMutex
	values map[labelKey]*atomic.Int64
}

type gaugeVec struct {
	help   string
	labels []string
	mu     sync.RWMutex
	values map[labelKey]*atomic.Int64
	// fn lets a gauge be sampled at scrape time instead of being written to,
	// which suits values the process already tracks elsewhere.
	fn func() float64
}

type histogramVec struct {
	help    string
	labels  []string
	buckets []float64
	mu      sync.RWMutex
	values  map[labelKey]*histogram
}

type histogram struct {
	counts []atomic.Int64
	total  atomic.Int64
	sum    atomic.Uint64 // float64 bits
}

// Counter registers a monotonic counter. Re-registering the same name returns
// the existing metric so wiring order does not matter.
func (r *Registry) Counter(name, help string, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.counters[name]; exists {
		return
	}
	r.counters[name] = &counterVec{help: help, labels: labels, values: map[labelKey]*atomic.Int64{}}
	r.order = append(r.order, name)
}

func (r *Registry) Gauge(name, help string, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.gauges[name]; exists {
		return
	}
	r.gauges[name] = &gaugeVec{help: help, labels: labels, values: map[labelKey]*atomic.Int64{}}
	r.order = append(r.order, name)
}

// GaugeFunc registers a gauge sampled when the registry is written.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.gauges[name]; exists {
		return
	}
	r.gauges[name] = &gaugeVec{help: help, fn: fn}
	r.order = append(r.order, name)
}

func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.histograms[name]; exists {
		return
	}
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	sorted := append([]float64(nil), buckets...)
	sort.Float64s(sorted)
	r.histograms[name] = &histogramVec{help: help, labels: labels, buckets: sorted,
		values: map[labelKey]*histogram{}}
	r.order = append(r.order, name)
}

// Add increments a counter. An unregistered name is ignored rather than
// panicking: a missing metric must never take down a request path.
func (r *Registry) Add(name string, delta int64, labelValues ...string) {
	r.mu.RLock()
	vec := r.counters[name]
	r.mu.RUnlock()
	if vec == nil || len(labelValues) != len(vec.labels) {
		return
	}
	key := makeLabelKey(vec.labels, labelValues)
	vec.mu.RLock()
	value := vec.values[key]
	vec.mu.RUnlock()
	if value == nil {
		vec.mu.Lock()
		if value = vec.values[key]; value == nil {
			value = &atomic.Int64{}
			vec.values[key] = value
		}
		vec.mu.Unlock()
	}
	value.Add(delta)
}

func (r *Registry) Inc(name string, labelValues ...string) {
	r.Add(name, 1, labelValues...)
}

// SetGauge replaces a gauge's value. Values are stored as integers because
// every gauge in this codebase counts things.
func (r *Registry) SetGauge(name string, value int64, labelValues ...string) {
	r.mu.RLock()
	vec := r.gauges[name]
	r.mu.RUnlock()
	if vec == nil || vec.fn != nil || len(labelValues) != len(vec.labels) {
		return
	}
	key := makeLabelKey(vec.labels, labelValues)
	vec.mu.Lock()
	stored := vec.values[key]
	if stored == nil {
		stored = &atomic.Int64{}
		vec.values[key] = stored
	}
	vec.mu.Unlock()
	stored.Store(value)
}

func (r *Registry) AddGauge(name string, delta int64, labelValues ...string) {
	r.mu.RLock()
	vec := r.gauges[name]
	r.mu.RUnlock()
	if vec == nil || vec.fn != nil || len(labelValues) != len(vec.labels) {
		return
	}
	key := makeLabelKey(vec.labels, labelValues)
	vec.mu.Lock()
	stored := vec.values[key]
	if stored == nil {
		stored = &atomic.Int64{}
		vec.values[key] = stored
	}
	vec.mu.Unlock()
	stored.Add(delta)
}

// Observe records one histogram sample in seconds.
func (r *Registry) Observe(name string, seconds float64, labelValues ...string) {
	r.mu.RLock()
	vec := r.histograms[name]
	r.mu.RUnlock()
	if vec == nil || len(labelValues) != len(vec.labels) {
		return
	}
	key := makeLabelKey(vec.labels, labelValues)
	vec.mu.RLock()
	stored := vec.values[key]
	vec.mu.RUnlock()
	if stored == nil {
		vec.mu.Lock()
		if stored = vec.values[key]; stored == nil {
			stored = &histogram{counts: make([]atomic.Int64, len(vec.buckets))}
			vec.values[key] = stored
		}
		vec.mu.Unlock()
	}
	for index, bound := range vec.buckets {
		if seconds <= bound {
			stored.counts[index].Add(1)
		}
	}
	stored.total.Add(1)
	// Compare-and-swap on the bit pattern keeps the sum lock-free.
	for {
		current := stored.sum.Load()
		updated := float64FromBits(current) + seconds
		if stored.sum.CompareAndSwap(current, float64Bits(updated)) {
			return
		}
	}
}

// ObserveDuration is the common case: time a handler and record it.
func (r *Registry) ObserveDuration(name string, start time.Time, labelValues ...string) {
	r.Observe(name, time.Since(start).Seconds(), labelValues...)
}

// Write renders the registry in Prometheus text exposition format. It is
// deliberately not named WriteTo: that name belongs to io.WriterTo, whose
// contract returns a byte count this type has no use for.
func (r *Registry) Write(writer io.Writer) error {
	r.mu.RLock()
	order := append([]string(nil), r.order...)
	counters := make(map[string]*counterVec, len(r.counters))
	for name, vec := range r.counters {
		counters[name] = vec
	}
	gauges := make(map[string]*gaugeVec, len(r.gauges))
	for name, vec := range r.gauges {
		gauges[name] = vec
	}
	histograms := make(map[string]*histogramVec, len(r.histograms))
	for name, vec := range r.histograms {
		histograms[name] = vec
	}
	r.mu.RUnlock()

	var builder strings.Builder
	for _, name := range order {
		switch {
		case counters[name] != nil:
			writeCounter(&builder, name, counters[name])
		case gauges[name] != nil:
			writeGauge(&builder, name, gauges[name])
		case histograms[name] != nil:
			writeHistogram(&builder, name, histograms[name])
		}
	}
	_, err := io.WriteString(writer, builder.String())
	return err
}

func writeCounter(builder *strings.Builder, name string, vec *counterVec) {
	fmt.Fprintf(builder, "# HELP %s %s\n# TYPE %s counter\n", name, vec.help, name)
	vec.mu.RLock()
	keys := sortedKeys(vec.values)
	for _, key := range keys {
		fmt.Fprintf(builder, "%s%s %d\n", name, renderLabels(key), vec.values[key].Load())
	}
	vec.mu.RUnlock()
}

func writeGauge(builder *strings.Builder, name string, vec *gaugeVec) {
	fmt.Fprintf(builder, "# HELP %s %s\n# TYPE %s gauge\n", name, vec.help, name)
	if vec.fn != nil {
		fmt.Fprintf(builder, "%s %s\n", name, formatFloat(vec.fn()))
		return
	}
	vec.mu.RLock()
	for _, key := range sortedKeys(vec.values) {
		fmt.Fprintf(builder, "%s%s %d\n", name, renderLabels(key), vec.values[key].Load())
	}
	vec.mu.RUnlock()
}

func writeHistogram(builder *strings.Builder, name string, vec *histogramVec) {
	fmt.Fprintf(builder, "# HELP %s %s\n# TYPE %s histogram\n", name, vec.help, name)
	vec.mu.RLock()
	defer vec.mu.RUnlock()
	keys := make([]labelKey, 0, len(vec.values))
	for key := range vec.values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	for _, key := range keys {
		stored := vec.values[key]
		for index, bound := range vec.buckets {
			fmt.Fprintf(builder, "%s_bucket%s %d\n", name,
				renderLabelsWith(key, "le", formatFloat(bound)), stored.counts[index].Load())
		}
		fmt.Fprintf(builder, "%s_bucket%s %d\n", name,
			renderLabelsWith(key, "le", "+Inf"), stored.total.Load())
		fmt.Fprintf(builder, "%s_sum%s %s\n", name, renderLabels(key),
			formatFloat(float64FromBits(stored.sum.Load())))
		fmt.Fprintf(builder, "%s_count%s %d\n", name, renderLabels(key), stored.total.Load())
	}
}

func sortedKeys[T any](values map[labelKey]T) []labelKey {
	keys := make([]labelKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	return keys
}

// renderLabels turns the internal "a=x,b=y" key back into Prometheus syntax.
func renderLabels(key labelKey) string {
	if key == "" {
		return ""
	}
	return "{" + quoteLabelPairs(string(key)) + "}"
}

func renderLabelsWith(key labelKey, name, value string) string {
	extra := name + `="` + value + `"`
	if key == "" {
		return "{" + extra + "}"
	}
	return "{" + quoteLabelPairs(string(key)) + "," + extra + "}"
}

func quoteLabelPairs(key string) string {
	pairs := strings.Split(key, string(keySeparator))
	for index, pair := range pairs {
		name, value, found := strings.Cut(pair, string(keyAssign))
		if !found {
			continue
		}
		pairs[index] = name + `="` + value + `"`
	}
	return strings.Join(pairs, ",")
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

// RegisterRuntime adds the Go runtime metrics worth alerting on in a homelab:
// goroutine leaks and heap growth.
func (r *Registry) RegisterRuntime() {
	r.GaugeFunc("go_goroutines", "Number of goroutines that currently exist.", func() float64 {
		return float64(runtime.NumGoroutine())
	})
	r.GaugeFunc("go_memstats_heap_alloc_bytes", "Heap bytes allocated and still in use.", func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.HeapAlloc)
	})
	r.GaugeFunc("go_memstats_sys_bytes", "Bytes obtained from the OS.", func() float64 {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return float64(stats.Sys)
	})
	r.GaugeFunc("process_open_fds_unsupported", "Always 0; kept so dashboards do not break.", func() float64 {
		return 0
	})
}

func float64Bits(value float64) uint64    { return math.Float64bits(value) }
func float64FromBits(bits uint64) float64 { return math.Float64frombits(bits) }
