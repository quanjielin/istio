package nodeagent

import (
	"context"
	"io"
	"sync"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	authapi "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/log"
)

const (
	typePrefix = "type.googleapis.com/envoy.api.v2."

	// SecretType is used for cluster discovery. Typically first request received
	SecretType = typePrefix + "Secret"
)

var (
	versionMutex sync.Mutex
	// version is update by registry events.
	version = time.Now()
)

type discoveryStream interface {
	Send(*xdsapi.DiscoveryResponse) error
	Recv() (*xdsapi.DiscoveryRequest, error)
	grpc.ServerStream
}

type sdsConnection struct {
	// PeerAddr is the address of the client envoy, from network layer
	PeerAddr string

	// Time of connection, for debugging
	Connect time.Time

	modelNode *model.Proxy

	// doneChannel will be closed when the client is closed.
	doneChannel chan int

	// current list of clusters monitored by the client
	Secret *authapi.Secret

	// SDS streams implement this interface
	stream discoveryStream
}

type sdservice struct {
	secretStore      secretStore
	workloadRegistry workloadRegistry
	caClient         caClient
}

// newSDService creates Secret Discovery Service which implements envoy v2 SSDS API.
func newSDService() *sdservice {
	return &sdservice{
		secretStore:      secretStore{},
		workloadRegistry: workloadRegistry{},
		//TODO(quanlin) - caclient
	}
}

// register adds the SDS handle to the grpc server
func (s *sdservice) register(rpcs *grpc.Server) {
	sds.RegisterSecretDiscoveryServiceServer(rpcs, s)
}

func (s *sdservice) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	log.Infof("******************StreamSecrets stream %+v", stream)
	peerInfo, ok := peer.FromContext(stream.Context())

	log.Infof("******************StreamSecrets peerInfo %+v", peerInfo)

	peerAddr := "Unknown peer address"
	if ok {
		peerAddr = peerInfo.Addr.String()
	}

	var discReq *xdsapi.DiscoveryRequest
	var receiveError error
	reqChannel := make(chan *xdsapi.DiscoveryRequest, 1)

	con := newSDSConnection(peerAddr, stream)
	defer close(con.doneChannel)

	go receiveThread(con, reqChannel, &receiveError)

	for {
		// Block until either a request is received or the ticker ticks
		select {
		case discReq, ok = <-reqChannel:
			if !ok {
				// Remote side closed connection.
				return receiveError
			}

			log.Infof("***************StreamSecrets node %+v", discReq.Node)
			if discReq.Node.Id == "" {
				log.Infof("Missing node id %s", discReq.String())
				continue
			}
			nt, err := model.ParseServiceNode(discReq.Node.Id)
			if err != nil {
				return err
			}
			nt.Metadata = model.ParseMetadata(discReq.Node.Metadata)
			con.modelNode = &nt

			if err := s.pushSds(*con.modelNode, con); err != nil {
				log.Errorf("Closing EDS connection, failure to push %v", err)
				return err
			}
		}
	}
}

func (s *sdservice) FetchSecrets(ctx context.Context, discReq *xdsapi.DiscoveryRequest) (*xdsapi.DiscoveryResponse, error) {
	proxy, err := model.ParseServiceNode(discReq.Node.Id)
	if err != nil {
		return nil, err
	}

	proxy.Metadata = model.ParseMetadata(discReq.Node.Metadata)

	s.workloadRegistry.AddWorkload(proxy, "" /*jwt token*/)

	secret, err := s.secretStore.GetSecret(proxy.ID)
	if err != nil {
		log.Warnf("SDS: config failure, closing grpc %v", err)
		return nil, err
	}

	return sdsDiscoveryResponse(secret, proxy)
}

func (s *sdservice) pushSds(proxy model.Proxy, con *sdsConnection) error {
	secret, err := s.secretStore.GetSecret(proxy.ID)
	if err != nil {
		log.Warnf("SDS: config failure, closing grpc %v", err)
		return err
	}
	response, err := sdsDiscoveryResponse(secret, proxy)
	if err != nil {
		log.Errorf("SDS: Failed to construct response %v", err)
		return err
	}

	if err = con.stream.Send(response); err != nil {
		log.Errorf("SDS: Send failure, closing grpc %v", err)
		return err
	}

	log.Infof("SDS: PUSH for node:%s addr:%q", proxy, con.PeerAddr)
	return nil
}

// SdsDiscoveryResponse returns a list of listeners for the given environment and source node.
func sdsDiscoveryResponse(s *secret, node model.Proxy) (*xdsapi.DiscoveryResponse, error) {
	secret := &authapi.Secret{
		//TODO
		Name: "",
		Type: &authapi.Secret_TlsCertificate{
			TlsCertificate: &authapi.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: s.certificateChain,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: s.privateKey,
					},
				},
			},
		},
	}

	resp := &xdsapi.DiscoveryResponse{
		TypeUrl:     SecretType,
		VersionInfo: versionInfo(),
		Nonce:       nonce(),
	}

	if secret == nil {
		log.Errorf("Nil secret")
		return resp, nil
	}

	ms, err := types.MarshalAny(secret)
	if err != nil {
		return nil, err
	}

	resp.Resources = append(resp.Resources, *ms)

	return resp, nil
}

func newSDSConnection(peerAddr string, stream discoveryStream) *sdsConnection {
	return &sdsConnection{
		doneChannel: make(chan int, 1),
		PeerAddr:    peerAddr,
		Secret:      &authapi.Secret{},
		Connect:     time.Now(),
		stream:      stream,
	}
}

func receiveThread(con *sdsConnection, reqChannel chan *xdsapi.DiscoveryRequest, errP *error) {
	defer close(reqChannel) // indicates close of the remote side.
	for {
		req, err := con.stream.Recv()
		log.Infof("********************receiveThread %+v", req)
		if err != nil {
			if status.Code(err) == codes.Canceled || err == io.EOF {
				log.Infof("SDS: %q terminated %v", con.PeerAddr, err)
				return
			}
			*errP = err
			log.Errorf("SDS: %q terminated with errors %v", con.PeerAddr, err)
			return
		}
		reqChannel <- req
	}
}

func nonce() string {
	return time.Now().String()
}

func versionInfo() string {
	versionMutex.Lock()
	defer versionMutex.Unlock()
	return version.String()
}
