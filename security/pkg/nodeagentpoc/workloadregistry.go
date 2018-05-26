package nodeagent

import (
	"sync"

	"istio.io/istio/pilot/pkg/model"
)

type workload struct {
	proxy    model.Proxy
	jwtToken string
}

type workloadRegistry struct {
	cache sync.Map
}

func (r *workloadRegistry) AddWorkload(w model.Proxy, jwtToken string) {
	r.cache.Store(w.ID, &workload{
		proxy:    w,
		jwtToken: jwtToken,
	})
}
