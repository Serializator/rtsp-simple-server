package core

import "github.com/prometheus/client_golang/prometheus"

var (
	hlsSubsystem = "hls"

	hlsMuxersDescName           = "muxers"
	hlsMuxersDescHelp           = "" // TODO: add a HELP message to the metric description
	hlsMuxersDescVariableLabels = []string{"name"}
)

type hlsCollector struct {
	metrics *metrics

	// Descriptors
	muxersDesc *prometheus.Desc
}

func (c hlsCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.muxersDesc
}

func (c hlsCollector) Collect(metrics chan<- prometheus.Metric) {
	if interfaceIsEmpty(c.metrics.hlsServer) {
		return
	}

	res := c.metrics.hlsServer.onAPIHLSMuxersList(hlsServerAPIMuxersListReq{})
	if res.err != nil {
		metrics <- prometheus.NewInvalidMetric(c.muxersDesc, res.err)
		return
	}

	for name := range res.data.Items {
		metrics <- prometheus.MustNewConstMetric(c.muxersDesc, prometheus.GaugeValue, 1, name)
	}
}

func newHLSCollector(metrics *metrics) hlsCollector {
	return hlsCollector{
		metrics: metrics,

		// Descriptors
		muxersDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, hlsSubsystem, hlsMuxersDescName),
			hlsMuxersDescHelp, hlsMuxersDescVariableLabels, nil,
		),
	}
}
