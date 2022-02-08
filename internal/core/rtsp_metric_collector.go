package core

import "github.com/prometheus/client_golang/prometheus"

var (
	rtspSubsystem  = "rtsp"
	rtspsSubsystem = "rtsps"

	rtspSessionsDescName           = "sessions"
	rtspSessionsDescHelp           = "" // TODO: add a HELP message to the metric description
	rtspSessionsDescVariableLabels = []string{"state"}
)

type rtspCollector struct {
	metrics *metrics

	// Descriptors
	rtspSessionsDesc  *prometheus.Desc
	rtspsSessionsDesc *prometheus.Desc
}

func (c rtspCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.rtspsSessionsDesc
	descs <- c.rtspsSessionsDesc
}

func (c rtspCollector) Collect(metrics chan<- prometheus.Metric) {
	if !interfaceIsEmpty(c.metrics.rtspServer) {
		c.collectRTSPSessions(c.metrics.rtspServer, c.rtspSessionsDesc, prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: rtspSubsystem,
			Name:      rtspSessionsDescName,
			Help:      rtspSessionsDescHelp,
		}, metrics)
	}

	if !interfaceIsEmpty(c.metrics.rtspsServer) {
		c.collectRTSPSessions(c.metrics.rtspsServer, c.rtspsSessionsDesc, prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: rtspsSubsystem,
			Name:      rtspSessionsDescName,
			Help:      rtspSessionsDescHelp,
		}, metrics)
	}
}

func (c rtspCollector) collectRTSPSessions(rtspServer metricsRTSPServer, desc *prometheus.Desc, opts prometheus.GaugeOpts, metrics chan<- prometheus.Metric) {
	res := rtspServer.onAPISessionsList(rtspServerAPISessionsListReq{})
	if res.err != nil {
		metrics <- prometheus.NewInvalidMetric(desc, res.err)
		return
	}

	count := prometheus.NewGaugeVec(opts, []string{"state"})
	defer count.Collect(metrics)

	for _, i := range res.data.Items {
		count.WithLabelValues(i.State).Inc()
	}
}

func newRTSPCollector(metrics *metrics) rtspCollector {
	return rtspCollector{
		metrics: metrics,

		// Descriptors
		rtspSessionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, rtspSubsystem, rtspSessionsDescName),
			rtspSessionsDescHelp, rtspSessionsDescVariableLabels, nil,
		),

		rtspsSessionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, rtspsSubsystem, rtspSessionsDescName),
			rtspSessionsDescHelp, rtspSessionsDescVariableLabels, nil,
		),
	}
}
