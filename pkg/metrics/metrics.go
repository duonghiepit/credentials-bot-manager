package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// SyncRequestsTotal tracks the total number of secret sync invocations.
	SyncRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "platform_controller",
			Subsystem: "secret",
			Name:      "sync_requests_total",
			Help:      "Total count of secret synchronization requests.",
		},
		[]string{"cluster", "namespace", "status"},
	)

	// SyncDurationSeconds observes the duration of secret synchronization cycles.
	SyncDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "platform_controller",
			Subsystem: "secret",
			Name:      "sync_duration_seconds",
			Help:      "Duration in seconds for secret synchronization execution.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"cluster"},
	)

	// SyncedObjectsGauge tracks the total number of managed objects in the cluster.
	SyncedObjectsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "platform_controller",
			Subsystem: "secret",
			Name:      "synced_objects_total",
			Help:      "Current count of managed Kubernetes secret synchronization objects.",
		},
		[]string{"cluster", "type"},
	)

	// AuthFailuresTotal tracks failed API key authentications.
	AuthFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "platform_controller",
			Subsystem: "auth",
			Name:      "failures_total",
			Help:      "Total number of failed API authentication attempts.",
		},
		[]string{"remote_ip"},
	)
)
