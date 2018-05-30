package sds

import (
	"net"

	"google.golang.org/grpc"

	"istio.io/istio/pkg/log"
)

const maxStreams = 100000

// SDSArgs provides all of the configuration parameters for secret discovery service.
type SDSArgs struct {
	SDSUdsSocket string
}

// Server is the grpc server that exposes SDS through UDS.
type Server struct {
	envoySds          *sdservice
	grpcServer        *grpc.Server
	grpcListeningAddr net.Addr

	closing chan bool
}

// NewServer creates and starts the Grpc server for SDS.
func NewServer(args SDSArgs, st secretStore) (*Server, error) {
	s := &Server{
		envoySds: newSDService(st),
		closing:  make(chan bool, 1),
	}
	if err := s.initDiscoveryService(&args, st); err != nil {
		log.Errorf("Failed to initialize secret discovery service: %v", err)
		return nil, err
	}
	return s, nil
}

// Close closes the Grpc server.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.closing <- true
}

func (s *Server) initDiscoveryService(args *SDSArgs, st secretStore) error {
	s.initGrpcServer()
	s.envoySds.register(s.grpcServer)

	grpcListener, err := net.Listen("unix", args.SDSUdsSocket)
	if err != nil {
		log.Errorf("Failed to listen on unix socket %q: %v", args.SDSUdsSocket, err)
		return err
	}
	s.grpcListeningAddr = grpcListener.Addr()

	go func() {
		if err = s.grpcServer.Serve(grpcListener); err != nil {
			log.Errorf("SDS grpc server failed to start: %v", err)
		}
	}()

	go func() {
		<-s.closing
		if grpcListener != nil {
			grpcListener.Close()
		}

		if s.grpcServer != nil {
			s.grpcServer.Stop()
		}
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
