// Package metrics defines Prometheus collectors for the SOCKS5 proxy.
//
// Pass a *Metrics into the proxy server via dependency injection. Tests can
// supply a fresh prometheus.Registry to avoid polluting the global one.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics bundles all Prometheus collectors used by the proxy.
type Metrics struct {
	ActiveConnections prometheus.Gauge
	TotalConnections  prometheus.Counter
	AuthFailures      prometheus.Counter
	DialErrors        prometheus.Counter
	HandshakeErrors   prometheus.Counter
	BytesProxied      *prometheus.CounterVec
	BuildInfo         *prometheus.GaugeVec
}

// New constructs collectors and registers them with reg. If reg is nil the
// collectors are not registered and may be registered manually.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "socks5_active_connections",
			Help: "Number of currently active proxy connections.",
		}),
		TotalConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "socks5_connections_total",
			Help: "Total number of proxy connections accepted.",
		}),
		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "socks5_auth_failures_total",
			Help: "Total number of authentication failures.",
		}),
		DialErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "socks5_dial_errors_total",
			Help: "Total number of upstream dial failures.",
		}),
		HandshakeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "socks5_handshake_errors_total",
			Help: "Total number of handshake/protocol failures.",
		}),
		BytesProxied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "socks5_bytes_proxied_total",
			Help: "Total bytes proxied, labeled by direction.",
		}, []string{"direction"}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "socks5_build_info",
			Help: "Build metadata; constant 1, labels carry the values.",
		}, []string{"version", "goversion", "os", "arch"}),
	}
	if reg != nil {
		reg.MustRegister(
			m.ActiveConnections,
			m.TotalConnections,
			m.AuthFailures,
			m.DialErrors,
			m.HandshakeErrors,
			m.BytesProxied,
			m.BuildInfo,
		)
	}
	return m
}

// SetBuildInfo populates the build_info gauge with a constant 1 value and
// the supplied labels.
func (m *Metrics) SetBuildInfo(version, goVersion, goos, goarch string) {
	m.BuildInfo.WithLabelValues(version, goVersion, goos, goarch).Set(1)
}

// NoOp returns a Metrics whose collectors are unregistered and safe to use
// when metrics are disabled. Increments are recorded in the local Counter
// objects but never exported.
func NoOp() *Metrics { return New(nil) }
