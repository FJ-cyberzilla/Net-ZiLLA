// internal/monitoring/metrics.go
package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	requestsTotal          prometheus.Counter
	requestsDuration       prometheus.Histogram
	analysisTotal          prometheus.Counter
	analysisDuration       prometheus.Histogram
	threatLevelGauge       prometheus.GaugeVec
	errorTotal             prometheus.CounterVec
	cacheHits              prometheus.Counter
	cacheMisses            prometheus.Counter
}

func NewMetrics() *Metrics {
	return &Metrics{
		requestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "netzilla_requests_total",
			Help: "Total number of HTTP requests",
		}),
		
		requestsDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "netzilla_request_duration_seconds",
			Help:    "Duration of HTTP requests",
			Buckets: prometheus.DefBuckets,
		}),
		
		analysisTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "netzilla_analysis_total",
			Help: "Total number of analyses performed",
		}),
		
		analysisDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "netzilla_analysis_duration_seconds",
			Help:    "Duration of security analyses",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
		}),
		
		threatLevelGauge: *promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netzilla_threat_level",
			Help: "Current threat level distribution",
		}, []string{"level"}),
		
		errorTotal: *promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "netzilla_errors_total",
			Help: "Total number of errors by type",
		}, []string{"type"}),
		
		cacheHits: promauto.NewCounter(prometheus.CounterOpts{
			Name: "netzilla_cache_hits_total",
			Help: "Total number of cache hits",
		}),
		
		cacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "netzilla_cache_misses_total",
			Help: "Total number of cache misses",
		}),
	}
}

func (m *Metrics) RecordRequest(method, path string, status int, duration time.Duration) {
	m.requestsTotal.Inc()
	m.requestsDuration.Observe(duration.Seconds())
}

func (m *Metrics) RecordAnalysis(analysisType string, duration time.Duration, threatLevel string) {
	m.analysisTotal.Inc()
	m.analysisDuration.Observe(duration.Seconds())
	m.threatLevelGauge.WithLabelValues(threatLevel).Inc()
}

func (m *Metrics) RecordError(errorType string) {
	m.errorTotal.WithLabelValues(errorType).Inc()
}

func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Inc()
}

func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Inc()
}
