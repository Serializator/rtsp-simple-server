package core

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"net/http"
	"sync"

	"github.com/aler9/rtsp-simple-server/internal/logger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO: use a proper namespace which prefixes the metrics
var namespace = ""

type metricsPathManager interface {
	onAPIPathsList(req pathAPIPathsListReq) pathAPIPathsListRes
}

type metricsRTSPServer interface {
	onAPISessionsList(req rtspServerAPISessionsListReq) rtspServerAPISessionsListRes
}

type metricsRTMPServer interface {
	onAPIConnsList(req rtmpServerAPIConnsListReq) rtmpServerAPIConnsListRes
}

type metricsHLSServer interface {
	onAPIHLSMuxersList(req hlsServerAPIMuxersListReq) hlsServerAPIMuxersListRes
}

type metricsParent interface {
	Log(logger.Level, string, ...interface{})
}

type metrics struct {
	parent metricsParent

	ln          net.Listener
	server      *http.Server
	mutex       sync.Mutex
	pathManager metricsPathManager
	rtspServer  metricsRTSPServer
	rtspsServer metricsRTSPServer
	rtmpServer  metricsRTMPServer
	hlsServer   metricsHLSServer
}

func newMetrics(
	address string,
	parent metricsParent,
) (*metrics, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	m := &metrics{
		parent: parent,
		ln:     ln,
	}

	prometheus.MustRegister(
		newPathCollector(m),
		newRTSPCollector(m),
		newRTMPCollector(m),
		newHLSCollector(m),
	)

	m.server = &http.Server{Handler: promhttp.Handler()}

	m.log(logger.Info, "listener opened on "+address)

	go m.run()

	return m, nil
}

func (m *metrics) close() {
	m.log(logger.Info, "listener is closing")
	m.server.Shutdown(context.Background())
}

func (m *metrics) log(level logger.Level, format string, args ...interface{}) {
	m.parent.Log(level, "[metrics] "+format, args...)
}

func (m *metrics) run() {
	err := m.server.Serve(m.ln)
	if err != http.ErrServerClosed {
		panic(err)
	}
}

// onPathManagerSet is called by pathManager.
func (m *metrics) onPathManagerSet(s metricsPathManager) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.pathManager = s
}

// onRTSPServer is called by rtspServer (plain).
func (m *metrics) onRTSPServerSet(s metricsRTSPServer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.rtspServer = s
}

// onRTSPServer is called by rtspServer (plain).
func (m *metrics) onRTSPSServerSet(s metricsRTSPServer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.rtspsServer = s
}

// onRTMPServerSet is called by rtmpServer.
func (m *metrics) onRTMPServerSet(s metricsRTMPServer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.rtmpServer = s
}

// onHLSServerSet is called by hlsServer.
func (m *metrics) onHLSServerSet(s metricsHLSServer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.hlsServer = s
}
