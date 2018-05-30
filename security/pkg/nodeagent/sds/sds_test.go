package sds

import (
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"testing"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	authapi "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	socket               string
	fakeCertificateChain = []byte{01}
	fakePrivateKey       = []byte{02}
)

func TestStreamSecrets(t *testing.T) {
	guid, err := exec.Command("uuidgen").Output()
	if err != nil {
		t.Fatal(err)
	}

	socket = fmt.Sprintf("/tmp/gotest%q.sock", guid)
	testHelper(t, socket, sdsRequestStream)
}

func TestFetchSecrets(t *testing.T) {
	guid, err := exec.Command("uuidgen").Output()
	if err != nil {
		t.Fatal(err)
	}

	socket = fmt.Sprintf("/tmp/gotest%q.sock", guid)
	testHelper(t, socket, sdsRequestFetch)
}

type secretCallback func(string, *api.DiscoveryRequest) (*api.DiscoveryResponse, error)

func testHelper(t *testing.T, testSocket string, cb secretCallback) {
	arg := SDSArgs{
		SDSUdsSocket: testSocket,
	}
	st := &mockSecretStore{}
	server, err := NewServer(arg, st)
	defer server.Close()

	if err != nil {
		t.Fatalf("failed to start grpc server for sds: %v", err)
	}

	req := &api.DiscoveryRequest{
		ResourceNames: []string{"test"},
		Node: &core.Node{
			Id: "sidecar~127.0.0.1~id~local",
		},
	}

	wait := 300 * time.Millisecond
	for try := 0; try < 5; try++ {
		time.Sleep(wait)
		// Try to call the server
		resp, err := cb(testSocket, req)
		if err == nil {
			//Verify secret.
			var pb authapi.Secret
			if err := types.UnmarshalAny(&resp.Resources[0], &pb); err != nil {
				t.Fatalf("UnmarshalAny SDS response failed: %v", err)
			}

			certificateChainGot := pb.GetTlsCertificate().GetCertificateChain()
			certificateChainWant := &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: fakeCertificateChain,
				},
			}
			if !reflect.DeepEqual(certificateChainWant, certificateChainGot) {
				t.Errorf("certificate Chain: got %+v, want %+v", certificateChainGot, certificateChainWant)
			}

			privateKeyGot := pb.GetTlsCertificate().GetPrivateKey()
			privateKeyWant := &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{
					InlineBytes: fakePrivateKey,
				},
			}
			if !reflect.DeepEqual(privateKeyWant, privateKeyGot) {
				t.Errorf("private key: got %+v, want %+v", privateKeyGot, privateKeyWant)
			}

			return
		}

		wait *= 2
	}

	t.Fatalf("failed to start grpc server for SDS")
}

// unixDialer connect a target with specified timeout.
func unixDialer(socket string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", socket, timeout)
}

func sdsRequestStream(socket string, req *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithDialer(unixDialer))

	conn, err := grpc.Dial(socket, opts...)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sdsClient := sds.NewSecretDiscoveryServiceClient(conn)
	stream, err := sdsClient.StreamSecrets(context.Background())
	if err != nil {
		return nil, err
	}
	err = stream.Send(req)
	if err != nil {
		return nil, err
	}
	res, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func sdsRequestFetch(socket string, req *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithDialer(unixDialer))

	conn, err := grpc.Dial(socket, opts...)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sdsClient := sds.NewSecretDiscoveryServiceClient(conn)
	resp, err := sdsClient.FetchSecrets(context.Background(), req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type mockSecretStore struct {
}

func (*mockSecretStore) getSecret() *secret {
	return &secret{
		certificateChain: fakeCertificateChain,
		privateKey:       fakePrivateKey,
	}
}
