package sds

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"istio.io/pkg/log"
)

//StartProfiling start the profiling for Galley
func StartProfiling(stop <-chan struct{}, port uint) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		log.Errorf("Unable to listen on profiling port %v: %v", port, err)
		return
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//Redirect ROOT to /debug/pprof/ for convenience
		http.Redirect(w, r, "/debug/pprof/", http.StatusSeeOther)
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		if err := server.Serve(lis); err != nil {
			log.Errorf("Profiling http server failed: %v", err)
			return
		}
	}()

	<-stop
	err = server.Close()
	log.Debugf("Profiling http server terminated: %v", err)
}
