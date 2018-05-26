package nodeagent

import (
	"sync"
)

type secret struct {
	certificateChain []byte
	privateKey       []byte
}

// TODO(quanlin): key rotation job to refresh cache.
type secretStore struct {
	cache sync.Map
}

func (ss *secretStore) GetSecret(id string) (*secret, error) {
	val, found := ss.cache.Load(id)
	if !found {
		//just for test
		return &secret{
			certificateChain: []byte("123"),
			privateKey:       []byte("456"),
		}, nil
		//return nil, nil
	}

	return val.(*secret), nil
}

func (ss *secretStore) PutSecret(id string, secret *secret) {
	ss.cache.Store(id, secret)
}
