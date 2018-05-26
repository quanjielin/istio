package nodeagent

import (
	"net"

	"google.golang.org/grpc"
	"istio.io/istio/pkg/log"
)

const (
	maxStreams   = 100000
	sdsUdsSocket = "/tmp/gotest1.sock"
)

// NodeAgentArgs provides all of the configuration parameters for the Pilot discovery service.
type NodeAgentArgs struct {
	SDSUdsSocket string
}

type Server struct {
	envoySds          *sdservice
	grpcServer        *grpc.Server
	grpcListeningAddr net.Addr

	stop chan bool
}

func NewServer(args NodeAgentArgs) (*Server, error) {
	s := &Server{}
	if err := s.initDiscoveryService(&args); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() {
	s.stop <- true
}

func (s *Server) initDiscoveryService(args *NodeAgentArgs) error {
	// Set up discovery service
	s.envoySds = newSDService()
	s.initGrpcServer()
	s.envoySds.register(s.grpcServer)

	socket := args.SDSUdsSocket
	log.Infof("*******************arg.socket is %q", socket)
	if socket == "" {
		socket = "/tmp/gotest1.sock"
	}

	grpcListener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	s.grpcListeningAddr = grpcListener.Addr()

	go func() {
		if err = s.grpcServer.Serve(grpcListener); err != nil {
			log.Warna(err)
		}
	}()

	go func() {
		<-s.stop
		grpcListener.Close()
		s.grpcServer.Stop()
	}()

	return nil
}

func (s *Server) initGrpcServer() {
	grpcOptions := s.grpcServerOptions()
	s.grpcServer = grpc.NewServer(grpcOptions...)
}

func (s *Server) grpcServerOptions() []grpc.ServerOption {
	grpcOptions := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(uint32(maxStreams)),
	}
	return grpcOptions
}
