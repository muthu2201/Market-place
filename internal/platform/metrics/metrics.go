// Package metrics is a dependency-free Prometheus exposition implementation.
//
// Pulling in the official client library would add ~40 transitive modules to a
// system whose security posture depends on a small, auditable dependency tree.
// The exposition format is a stable, simple text contract, so we implement the
// four metric types we actually use and nothing else.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds every metric in the process.
type Registry struct {
	mu     sync.RWMutex
	series map[string]collector
	order  []string
}

type collector interface {
	write(w io.Writer, name string)
	help() (string, string) // help text, type
}

func NewRegistry() *Registry {
	return &Registry{series: make(map[string]collector)}
}

// Default is the process-wide registry.
var Default = NewRegistry()

func (r *Registry) register(name string, c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.series[name]; dup {
		panic("metrics: duplicate registration of " + name)
	}
	r.series[name] = c
	r.order = append(r.order, name)
	sort.Strings(r.order)
}

// WriteTo renders the whole registry in Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	names := make([]string, len(r.order))
	copy(names, r.order)
	cols := make([]collector, len(names))
	for i, n := range names {
		cols[i] = r.series[n]
	}
	r.mu.RUnlock()

	var buf strings.Builder
	for i, n := range names {
		h, t := cols[i].help()
		fmt.Fprintf(&buf, "# HELP %s %s\n# TYPE %s %s\n", n, h, n, t)
		cols[i].write(&buf, n)
	}
	nw, err := io.WriteString(w, buf.String())
	return int64(nw), err
}

// ---- labels ----------------------------------------------------------------

func labelKey(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	return strings.Join(labels, "\x00")
}

func renderLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(values[i]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	if !strings.ContainsAny(s, `\"`+"\n") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// ---- counter ----------------------------------------------------------------

type CounterVec struct {
	helpText   string
	labelNames []string
	mu         sync.RWMutex
	vals       map[string]*counterChild
}

type counterChild struct {
	labels []string
	v      atomic.Uint64
}

// NewCounter registers a monotonically increasing counter.
func NewCounter(r *Registry, name, help string, labelNames ...string) *CounterVec {
	c := &CounterVec{helpText: help, labelNames: labelNames, vals: map[string]*counterChild{}}
	r.register(name, c)
	return c
}

func (c *CounterVec) Inc(labels ...string)               { c.Add(1, labels...) }
func (c *CounterVec) Add(delta uint64, labels ...string) { c.child(labels).v.Add(delta) }

func (c *CounterVec) child(labels []string) *counterChild {
	if len(labels) != len(c.labelNames) {
		panic("metrics: label cardinality mismatch")
	}
	k := labelKey(labels)
	c.mu.RLock()
	ch, ok := c.vals[k]
	c.mu.RUnlock()
	if ok {
		return ch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok = c.vals[k]; ok {
		return ch
	}
	ch = &counterChild{labels: append([]string(nil), labels...)}
	c.vals[k] = ch
	return ch
}

func (c *CounterVec) help() (string, string) { return c.helpText, "counter" }

func (c *CounterVec) write(w io.Writer, name string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ch := c.vals[k]
		fmt.Fprintf(w, "%s%s %d\n", name, renderLabels(c.labelNames, ch.labels), ch.v.Load())
	}
}

// ---- gauge ------------------------------------------------------------------

type GaugeVec struct {
	helpText   string
	labelNames []string
	mu         sync.RWMutex
	vals       map[string]*gaugeChild
}

type gaugeChild struct {
	labels []string
	bits   atomic.Uint64 // float64 bits
}

func NewGauge(r *Registry, name, help string, labelNames ...string) *GaugeVec {
	g := &GaugeVec{helpText: help, labelNames: labelNames, vals: map[string]*gaugeChild{}}
	r.register(name, g)
	return g
}

func (g *GaugeVec) Set(v float64, labels ...string) {
	g.child(labels).bits.Store(math.Float64bits(v))
}

func (g *GaugeVec) child(labels []string) *gaugeChild {
	if len(labels) != len(g.labelNames) {
		panic("metrics: label cardinality mismatch")
	}
	k := labelKey(labels)
	g.mu.RLock()
	ch, ok := g.vals[k]
	g.mu.RUnlock()
	if ok {
		return ch
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ch, ok = g.vals[k]; ok {
		return ch
	}
	ch = &gaugeChild{labels: append([]string(nil), labels...)}
	g.vals[k] = ch
	return ch
}

func (g *GaugeVec) help() (string, string) { return g.helpText, "gauge" }

func (g *GaugeVec) write(w io.Writer, name string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	keys := make([]string, 0, len(g.vals))
	for k := range g.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ch := g.vals[k]
		v := math.Float64frombits(ch.bits.Load())
		fmt.Fprintf(w, "%s%s %s\n", name, renderLabels(g.labelNames, ch.labels), strconv.FormatFloat(v, 'g', -1, 64))
	}
}

// ---- histogram --------------------------------------------------------------

// DefaultBuckets are latency buckets in seconds spanning 1ms to 30s, which is
// the range that actually matters for an HTTP marketplace.
var DefaultBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

type HistogramVec struct {
	helpText   string
	labelNames []string
	buckets    []float64
	mu         sync.RWMutex
	vals       map[string]*histChild
}

type histChild struct {
	labels  []string
	counts  []atomic.Uint64
	sumBits atomic.Uint64
	total   atomic.Uint64
}

func NewHistogram(r *Registry, name, help string, buckets []float64, labelNames ...string) *HistogramVec {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	h := &HistogramVec{helpText: help, labelNames: labelNames, buckets: b, vals: map[string]*histChild{}}
	r.register(name, h)
	return h
}

func (h *HistogramVec) Observe(v float64, labels ...string) {
	ch := h.child(labels)
	for i, b := range h.buckets {
		if v <= b {
			ch.counts[i].Add(1)
		}
	}
	ch.total.Add(1)
	for {
		old := ch.sumBits.Load()
		nw := math.Float64bits(math.Float64frombits(old) + v)
		if ch.sumBits.CompareAndSwap(old, nw) {
			return
		}
	}
}

func (h *HistogramVec) child(labels []string) *histChild {
	if len(labels) != len(h.labelNames) {
		panic("metrics: label cardinality mismatch")
	}
	k := labelKey(labels)
	h.mu.RLock()
	ch, ok := h.vals[k]
	h.mu.RUnlock()
	if ok {
		return ch
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok = h.vals[k]; ok {
		return ch
	}
	ch = &histChild{labels: append([]string(nil), labels...), counts: make([]atomic.Uint64, len(h.buckets))}
	h.vals[k] = ch
	return ch
}

func (h *HistogramVec) help() (string, string) { return h.helpText, "histogram" }

func (h *HistogramVec) write(w io.Writer, name string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, len(h.vals))
	for k := range h.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ch := h.vals[k]
		names := append(append([]string(nil), h.labelNames...), "le")
		for i, b := range h.buckets {
			vals := append(append([]string(nil), ch.labels...), strconv.FormatFloat(b, 'g', -1, 64))
			fmt.Fprintf(w, "%s_bucket%s %d\n", name, renderLabels(names, vals), ch.counts[i].Load())
		}
		infVals := append(append([]string(nil), ch.labels...), "+Inf")
		total := ch.total.Load()
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, renderLabels(names, infVals), total)
		base := renderLabels(h.labelNames, ch.labels)
		sum := math.Float64frombits(ch.sumBits.Load())
		fmt.Fprintf(w, "%s_sum%s %s\n", name, base, strconv.FormatFloat(sum, 'g', -1, 64))
		fmt.Fprintf(w, "%s_count%s %d\n", name, base, total)
	}
}
