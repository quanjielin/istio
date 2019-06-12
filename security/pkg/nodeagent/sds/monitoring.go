package sds

import (
	"fmt"
	"net"
	"net/http"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"
	"istio.io/pkg/log"
	"istio.io/pkg/version"
)

const (
	metricsPath = "/metrics"
	versionPath = "/version"
)

//StartSelfMonitoring start the self monitoring for Galley
func StartSelfMonitoring(stop <-chan struct{}, port uint) {
	log.Info("*****StartSelfMonitoring-1")
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		log.Errorf("Unable to listen on monitoring port %v: %v", port, err)
		return
	}

	mux := http.NewServeMux()

	log.Info("*****StartSelfMonitoring-2")

	registry := prometheus.DefaultRegisterer.(*prometheus.Registry)
	exporter, err := ocprom.NewExporter(ocprom.Options{Registry: registry})
	if err != nil {
		log.Errorf("could not set up prometheus exporter: %v", err)
	} else {
		log.Info("*****StartSelfMonitoring-3")
		view.RegisterExporter(exporter)
		mux.Handle(metricsPath, exporter)
	}

	//mux.Handle(metricsPath, promhttp.Handler())
	log.Info("*****StartSelfMonitoring-3")
	mux.HandleFunc(versionPath, func(out http.ResponseWriter, req *http.Request) {
		if _, err := out.Write([]byte(version.Info.String())); err != nil {
			log.Errorf("Unable to write version string: %v", err)
		}
	})

	log.Info("*****StartSelfMonitoring-4")
	version.Info.RecordComponentBuildTag("nodeagent")

	server := &http.Server{
		Handler: mux,
	}
	log.Info("*****StartSelfMonitoring-6")

	go func() {
		log.Info("*****StartSelfMonitoring-7")
		if err := server.Serve(lis); err != nil {
			log.Errorf("Monitoring http server failed: %v", err)
			return
		}
	}()

	log.Info("*****StartSelfMonitoring-8")
	<-stop
	err = server.Close()
	log.Debugf("Monitoring server terminated: %v", err)
}
