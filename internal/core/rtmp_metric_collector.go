package core

import "github.com/prometheus/client_golang/prometheus"

var (
	rtmpSubsystem = "rtmp"

	rtmpConnsDescName           = "conns"
	rtmpConnsDescHelp           = "" // TODO: add a HELP message to the metric description
	rtmpConnsDescVariableLabels = []string{"state"}
)

type rtmpConnCollector struct {
	metrics *metrics

	// Descriptors
	connsDesc *prometheus.Desc
}

func (c rtmpConnCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.connsDesc
}

func (c rtmpConnCollector) Collect(metrics chan<- prometheus.Metric) {
	if interfaceIsEmpty(c.metrics.rtmpServer) {
		return
	}

	res := c.metrics.rtmpServer.onAPIConnsList(rtmpServerAPIConnsListReq{})
	if res.err != nil {
		metrics <- prometheus.NewInvalidMetric(c.connsDesc, res.err)
		return
	}

	count := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: rtmpSubsystem,
		Name:      rtmpConnsDescName,
		Help:      rtmpConnsDescHelp,
	}, rtmpConnsDescVariableLabels)
	defer count.Collect(metrics)

	for _, i := range res.data.Items {
		count.WithLabelValues(i.State).Inc()
	}
}

func newRTMPCollector(metrics *metrics) rtmpConnCollector {
	return rtmpConnCollector{
		metrics: metrics,

		// Descriptors
		connsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, rtmpSubsystem, rtmpConnsDescName),
			rtmpConnsDescHelp, rtmpConnsDescVariableLabels, nil,
		),
	}
}
