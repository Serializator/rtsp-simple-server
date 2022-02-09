package core

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	pathSubsystem = "" // TODO: use a proper subsystem (such as "path")

	pathPathsDescName           = "paths" // TODO: should be "path", resulting in a "{namespace}_{subsystem}_total" ("rtspss_path_paths")
	pathPathsDescHelp           = "The name and state of path"
	pathPathsDescVariableLabels = []string{"name", "state"}
)

type pathCollector struct {
	metrics *metrics

	// Descriptors
	pathsDesc *prometheus.Desc
}

func (c pathCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.pathsDesc
}

func (c pathCollector) Collect(metrics chan<- prometheus.Metric) {
	res := c.metrics.pathManager.onAPIPathsList(pathAPIPathsListReq{})
	if res.err != nil {
		metrics <- prometheus.NewInvalidMetric(c.pathsDesc, res.err)
		return
	}

	for name, p := range res.data.Items {
		var state string
		if p.SourceReady {
			state = "ready"
		} else {
			state = "notReady"
		}

		metrics <- prometheus.MustNewConstMetric(c.pathsDesc, prometheus.GaugeValue, 1, name, state)
	}
}

func newPathCollector(metrics *metrics) pathCollector {
	return pathCollector{
		metrics: metrics,

		// Descriptors
		pathsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, pathSubsystem, pathPathsDescName),
			pathPathsDescHelp, pathPathsDescVariableLabels, nil,
		),
	}
}
