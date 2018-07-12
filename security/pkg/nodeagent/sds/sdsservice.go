// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sds implements secret discovery service in NodeAgent.
package sds

import (
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	authapi "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"istio.io/istio/pkg/log"
	"istio.io/istio/security/pkg/pki/util"
)

// BEGIN - quanlin local test.
type Secret struct {
	certificateChain string
	privateKey       string
}

var (
	secrets = []Secret{
		{
			certificateChain: `-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIJAI3dmBBDwTQCMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl
MQ4wDAYDVQQKDAVJc3RpbzENMAsGA1UECwwEVGVzdDEQMA4GA1UEAwwHUm9vdCBD
QTEiMCAGCSqGSIb3DQEJARYTdGVzdHJvb3RjYUBpc3Rpby5pbzAgFw0xODA1MDgx
OTQ5MjRaGA8yMTE4MDQxNDE5NDkyNFowWTELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExEjAQBgNVBAcMCVN1bm55dmFsZTEOMAwGA1UECgwFSXN0aW8x
ETAPBgNVBAMMCElzdGlvIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAtqwOeCRGd9H91ieHQmDX0KR6RHEVHxN6X3VsL8RXu8GtaULP3IFmitbY2uLo
VpdB4JxuDmuIDYbktqheLYD4g55klq13OInlEMtLk/u2H0Fvz70HRjDFAfOqY8OT
Ijs2+iM1H5OFVNrKxSHao/wiqbU3ZOZHu7ts6jcLrh8O+P17KRREaP7mapH1cETD
y/wA3qgE42ARfbO/0DPX2VQJuTewk1NJWQVdCkE7VWYR6F5PMTyBChT3lsqHalrL
EQCT5Ytcio+KPO6Y1qstrbFv++FAMQrthKlVcuPc6meOpszPjNqSQNCXpA99R6sl
AEzTSxmEpQrMUMPToHT6NRxs1wIDAQABozUwMzALBgNVHQ8EBAMCAgQwDAYDVR0T
BAUwAwEB/zAWBgNVHREEDzANggtjYS5pc3Rpby5pbzANBgkqhkiG9w0BAQsFAAOC
AQEAGpB9V2K7fEYYxmatjQLuNw0s+vKa5JkJrJO3H6Y1LAdKTJ3k7Cpr15zouM6d
5KogHfFHXPI6MU2ZKiiE38UPQ5Ha4D2XeuAwN64cDyN2emDnQ0UFNm+r4DY47jd3
jHq8I3reVSXeqoHcL0ViuGJRY3lrk8nmEo15vP1stmo5bBdnSlASDDjEjh1FHeXL
/Ha465WYESLcL4ps/xrcXN4JtV1nDGJVGy4WmusL+5D9nHC53/srZczZX3By48+Y
hhZwPFxt/EVB0YISgMOnMHzmWmnNWRiDuI6eZxUx0L9B9sD4s7zrQYYQ1bV/CPYX
iwlodzJwNdfIBfD/AC/GdnaWow==
-----END CERTIFICATE-----`,
			privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtqwOeCRGd9H91ieHQmDX0KR6RHEVHxN6X3VsL8RXu8GtaULP
3IFmitbY2uLoVpdB4JxuDmuIDYbktqheLYD4g55klq13OInlEMtLk/u2H0Fvz70H
RjDFAfOqY8OTIjs2+iM1H5OFVNrKxSHao/wiqbU3ZOZHu7ts6jcLrh8O+P17KRRE
aP7mapH1cETDy/wA3qgE42ARfbO/0DPX2VQJuTewk1NJWQVdCkE7VWYR6F5PMTyB
ChT3lsqHalrLEQCT5Ytcio+KPO6Y1qstrbFv++FAMQrthKlVcuPc6meOpszPjNqS
QNCXpA99R6slAEzTSxmEpQrMUMPToHT6NRxs1wIDAQABAoIBADyw4YXNF5SLsjhK
ncfSASIS44SFxayzff7lNnKQW03IRWMpjYIHhBgw1Y+zv9m1G3ASyQYFeAh2ftqp
CdE4fljMcUMWkvu35OE1igC6qoGr7ggpF5eccHf7iurmeaXv4o4s0GOTUcMlhiUE
4G2HQcT8rlDZqY+X79HJRBovu3vBvCktYMmzCXugrudwFkpbi5Dd3sFuPiKrXndY
oDPtjU2cb7Cg9DO8PZwab7tGWaFjstwXhIOE636uLog9xM9EC3D2qp9QFOVkmCH4
t4MzUCHcbIXRcunlil2+CYIFPDylJL6bFlpfVhtNubdgC35bsSql+h1QgZMezpAY
ZK9p7nECgYEA4hMKOAac1pnlfsXjf3jzZuZLBPIV/WpNZNsAIL/4aErSL0C3woRx
hj8q4onA0BD078r8n9zh3x/el17B/f43FoDydSkONlcUKaayHYlIhB1ULHPIEDVG
zlXIpkSi4Qui+51sZLnxXcmPbCT4LUN5nkWkZRHRboaufBAx+SdDRdUCgYEAzto/
cyEJ9p+e9chHSWv17pfeBu87XROwFS66hyWcnA5qDThbpvFakOGdCeKMKCS2ALW5
LsLx+PvN/V94AoJaMDsR3b2CH+/+cLWMLKqAiZzkha/Jr9FRyFPFs2nkZVkeekc8
FMXMwvs16hbBs3KHizJ5UswrGzOKWlPdpfxMofsCgYAoost/bpDacicyNlfCHfeC
U3rAlNMnDeiDbGoFePwpoulM3REqwau2Obx3o9MokyOzxoTKJ2XiOVRFWR79jKhS
PzNVo9+OHPDe27vAW2DRfoQWyWj4oNrtU7YRTN0KHpFZMN6+7D1aYlSJV8vUNwCx
VktKb315pHPQkQiqhEgvUQKBgFYSTnCTgNfUV4qiCbetaqobG1H7XdI/DPfjd84g
gmgVP1+84bY3m53Jo1SnpfZWQD1PYHzqtVELRg12GjPBFdIX4jlIT8sGS/OON4Om
dtHMLPLL0LqN+N/Iq+0Z1OWvDZWH6qIiJC/F5AtB6NvIfkoXeJBRUGaDLcCkQQh+
UUzdAoGBAKnmA0y3Up9QAowB1F7vvP9B4GzJ3qI/YNAkBE5keQePz/utetTStV+j
xcvcLWv3ZSpjpXSNwOBfdjdQirYFZQZtcAf9JxBkr0HaQ7w7MLxLp06O0YglH1Su
XyPkmABFTunZEBnpCd9NFXgzM3jQGvSZJOj1n0ZALZ1BM9k54e62
-----END RSA PRIVATE KEY-----`,
		},
		{
			certificateChain: `-----BEGIN CERTIFICATE-----
MIIDDDCCAnWgAwIBAgIJAPOCjrJP13nQMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMQ0wCwYDVQQKEwRMeWZ0MRkwFwYDVQQLExBMeWZ0IEVuZ2luZWVyaW5nMRAw
DgYDVQQDEwdUZXN0IENBMB4XDTE3MDcwOTAxMzkzMloXDTE5MDcwOTAxMzkzMlow
ejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xDTALBgNVBAoTBEx5ZnQxGTAXBgNVBAsTEEx5ZnQgRW5naW5l
ZXJpbmcxFDASBgNVBAMTC1Rlc3QgU2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDARNUJMFkWF0E6mbdz/nkydVC4TU2SgR95vhJhWpG6xKkCNoXkJxNz
XOmFUUIXQyq7FnIWACYuMrE2KXnomeCGP9A6M21lumNseYSLX3/b+ao4E6gimm1/
Gp8C3FaoAs8Ep7VE+o2DMIfTIPJhFf6RBFPundGhEm8/gv+QObVhKQIDAQABo4Gd
MIGaMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUF
BwMCBggrBgEFBQcDATAeBgNVHREEFzAVghNzZXJ2ZXIxLmV4YW1wbGUuY29tMB0G
A1UdDgQWBBRCcUr8mIigWlR61OX/gmDY5vBV6jAfBgNVHSMEGDAWgBQ7eKRRTxaE
kxxIKHoMrSuWQcp9eTANBgkqhkiG9w0BAQsFAAOBgQAtn05e8U41heun5L7MKflv
tJM7w0whavdS8hLe63CxnS98Ap973mSiShKG+OxSJ0ClMWIZPy+KyC+T8yGIaynj
wEEuoSGRWmhzcMMnZWxqQyD95Fsx6mtdnq/DJxiYzmH76fALe/538j8pTcoygSGD
NWw1EW8TEwlFyuvCrlWQcg==
-----END CERTIFICATE-----`,
			privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDARNUJMFkWF0E6mbdz/nkydVC4TU2SgR95vhJhWpG6xKkCNoXk
JxNzXOmFUUIXQyq7FnIWACYuMrE2KXnomeCGP9A6M21lumNseYSLX3/b+ao4E6gi
mm1/Gp8C3FaoAs8Ep7VE+o2DMIfTIPJhFf6RBFPundGhEm8/gv+QObVhKQIDAQAB
AoGBAJM64kukC0QAUMHX/gRD5HkAHuzSvUknuXuXUincmeWEPMtmBwdb6OgZSPT+
8XYwx+L14Cz6tkIALXWFM0YrtyKfVdELRRs8dw5nenzK3wOeo/N/7XL4kwim4kV3
q817RO6NUN76vHOsvQMFsPlEfCZpOTIGJEJBI7eFLP0djOMlAkEA/yWEPfQoER/i
X6uNyXrU51A6gxyZg7rPNP0cxxRhDedtsJPNY6Tlu90v9SiTgQLUTp7BINH24t9a
MST1tmax+wJBAMDpeRy52q+sqLXI1C2oHPuXrXzeyp9pynV/9tsYL9+qoyP2XcEZ
DaI0tfXDJXOdYIaDnSfB50eqQUnaTmQjtCsCQGUFGaLd9K8zDJIMforzUzByl3gp
7q41XK0COk6oRvUWWFu9aWi2dS84mDBc7Gn8EMtAF/9CopmZDUC//XlGl9kCQQCr
6yWw8PywFHohzwEwUyLJIKpOnyoKGTiBsHGpXYvEk4hiEzwISzB4PutuQuRMfZM5
LW/Pr6FSn6shivjTi3ITAkACMTBczBQ+chMBcTXDqyqwccQOIhupxani9wfZhsrm
ZXbTTxnUZioQ2l/7IWa+K2O2NrWWT7b3KpCAob0bJsQz
-----END RSA PRIVATE KEY-----`,
		},
	}
)

// END - quanlin local test.

const (
	// SecretType is used for secret discovery service to construct response.
	SecretType = "type.googleapis.com/envoy.api.v2.auth.Secret"

	// CredentialTokenHeaderKey is the header key in gPRC header which is used to
	// pass credential token from envoy's SDS request to SDS service.
	CredentialTokenHeaderKey = "authorization"
)

var (
	sdsClients      = map[string]*sdsConnection{}
	sdsClientsMutex sync.RWMutex

	previousRequestTime = time.Now()
)

type discoveryStream interface {
	Send(*xdsapi.DiscoveryResponse) error
	Recv() (*xdsapi.DiscoveryRequest, error)
	grpc.ServerStream
}

// sdsEvent represents a secret event that results in a push.
type sdsEvent struct {
	endStream bool
}

type sdsConnection struct {
	// PeerAddr is the address of the client envoy, from network layer.
	PeerAddr string

	// Time of connection, for debugging.
	Connect time.Time

	// The ID of proxy from which the connection comes from.
	proxyID string

	// Sending on this channel results in  push.
	pushChannel chan *sdsEvent

	// doneChannel will be closed when the client is closed.
	doneChannel chan int

	// SDS streams implement this interface.
	stream discoveryStream

	// The secret associated with the proxy.
	secret *SecretItem
}

type sdsservice struct {
	st SecretManager
}

// newSDSService creates Secret Discovery Service which implements envoy v2 SDS API.
func newSDSService(st SecretManager) *sdsservice {
	return &sdsservice{
		st: st,
	}
}

// register adds the SDS handle to the grpc server
func (s *sdsservice) register(rpcs *grpc.Server) {
	sds.RegisterSecretDiscoveryServiceServer(rpcs, s)
}

func (s *sdsservice) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	log.Infof("**************StreamSecrets is called")
	fmt.Printf("++++++++++++++StreamSecrets is called")
	ctx := stream.Context()

	// quanlin - localtest
	/*
		token, err := getCredentialToken(ctx)
		if err != nil {
			return err
		}*/
	token := "fakeToken"

	peerAddr := "Unknown peer address"
	peerInfo, ok := peer.FromContext(ctx)
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
		// Block until a request is received.
		select {
		case discReq, ok = <-reqChannel:
			if !ok {
				// Remote side closed connection.
				return receiveError
			}

			spiffeID, err := parseDiscoveryRequest(discReq)
			if err != nil {
				continue
			}
			con.proxyID = discReq.Node.Id

			secret, err := s.st.GetSecret(ctx, discReq.Node.Id, spiffeID, token)
			if err != nil {
				log.Errorf("Failed to get secret for proxy %q from secret cache: %v", discReq.Node.Id, err)
				return err
			}
			con.secret = secret

			addConn(discReq.Node.Id, con)
			defer removeConn(discReq.Node.Id)

			if err := pushSDS(con); err != nil {
				log.Errorf("SDS failed to push: %v", err)
				return err
			}
		case <-con.pushChannel:
			if con.secret == nil {
				// Secret is nil indicates close streaming connection to proxy, so that proxy
				// could connect again with updated token.
				return fmt.Errorf("streaming connection closed")
			}

			if err := pushSDS(con); err != nil {
				log.Errorf("SDS failed to push: %v", err)
				return err
			}
		}
	}
}

func (s *sdsservice) FetchSecrets(ctx context.Context, discReq *xdsapi.DiscoveryRequest) (*xdsapi.DiscoveryResponse, error) {
	log.Infof("**************FetchSecrets is called")
	fmt.Printf("++++++++++++++FetchSecrets is called")

	token, err := getCredentialToken(ctx)
	if err != nil {
		return nil, err
	}

	spiffeID, err := parseDiscoveryRequest(discReq)
	if err != nil {
		return nil, err
	}

	secret, err := s.st.GetSecret(ctx, discReq.Node.Id, spiffeID, token)
	if err != nil {
		log.Errorf("Failed to get secret for proxy %q from secret cache: %v", discReq.Node.Id, err)
		return nil, err
	}

	return sdsDiscoveryResponse(secret, discReq.Node.Id)
}

// NotifyProxy send notification to proxy about secret update,
// SDS will close streaming connection is secret is nil.
func NotifyProxy(proxyID string, secret *SecretItem) error {
	cli := sdsClients[proxyID]
	if cli == nil {
		log.Infof("No sdsclient with id %q can be found", proxyID)
		return fmt.Errorf("no sdsclient with id %q can be found", proxyID)
	}
	cli.secret = secret

	cli.pushChannel <- &sdsEvent{}
	return nil
}

func parseDiscoveryRequest(discReq *xdsapi.DiscoveryRequest) (string /*spiffeID*/, error) {
	if discReq.Node.Id == "" {
		return "", fmt.Errorf("discovery request %+v missing node id", discReq)
	}

	if len(discReq.ResourceNames) != 1 || !strings.HasPrefix(discReq.ResourceNames[0], util.URIScheme) {
		return "", fmt.Errorf("discovery request %+v has invalid resourceNames %+v", discReq, discReq.ResourceNames)
	}
	return discReq.ResourceNames[0], nil
}

func getCredentialToken(ctx context.Context) (string, error) {
	metadata, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("unable to get metadata from incoming context")
	}

	if h, ok := metadata[CredentialTokenHeaderKey]; ok {
		if len(h) != 1 {
			return "", fmt.Errorf("credential token must have 1 value in gRPC metadata but got %d", len(h))
		}
		return h[0], nil
	}

	return "", fmt.Errorf("no credential token is found")
}

func addConn(proxyID string, conn *sdsConnection) {
	sdsClientsMutex.Lock()
	defer sdsClientsMutex.Unlock()
	sdsClients[proxyID] = conn
}

func removeConn(proxyID string) {
	sdsClientsMutex.Lock()
	defer sdsClientsMutex.Unlock()
	delete(sdsClients, proxyID)
}

func pushSDS(con *sdsConnection) error {
	response, err := sdsDiscoveryResponse(con.secret, con.proxyID)
	if err != nil {
		log.Errorf("SDS: Failed to construct response %v", err)
		return err
	}

	if err = con.stream.Send(response); err != nil {
		log.Errorf("SDS: Send response failure %v", err)
		return err
	}

	log.Infof("SDS: push for proxy:%q addr:%q", con.proxyID, con.PeerAddr)
	return nil
}

func sdsDiscoveryResponse(s *SecretItem, proxyID string) (*xdsapi.DiscoveryResponse, error) {
	//TODO(quanlin): use timestamp for versionInfo and nouce for now, may change later.
	t := time.Now().String()
	resp := &xdsapi.DiscoveryResponse{
		TypeUrl:     SecretType,
		VersionInfo: t,
		Nonce:       t,
	}

	if s == nil {
		log.Errorf("SDS: got nil secret for proxy %q", proxyID)
		return resp, nil
	}

	secret := &authapi.Secret{
		Name: s.SpiffeID,
		Type: &authapi.Secret_TlsCertificate{
			TlsCertificate: &authapi.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: s.CertificateChain,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: s.PrivateKey,
					},
				},
			},
		},
	}

	elapsed := time.Since(previousRequestTime)

	tlsCertificate := &authapi.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{[]byte(secrets[0].certificateChain)},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{[]byte(secrets[0].privateKey)},
		},
	}

	if math.Floor(math.Mod(elapsed.Seconds()/10, 2)) == 1 {
		tlsCertificate = &authapi.TlsCertificate{
			CertificateChain: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{[]byte(secrets[1].certificateChain)},
			},
			PrivateKey: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{[]byte(secrets[1].privateKey)},
			},
		}
	}

	secret = &authapi.Secret{
		Name: s.SpiffeID,
		Type: &authapi.Secret_TlsCertificate{
			TlsCertificate: tlsCertificate,
		},
	}
	log.Infof("********distribute secret %+v\n", secret)

	// END - quanlin local test.

	ms, err := types.MarshalAny(secret)
	if err != nil {
		log.Errorf("Failed to mashal secret for proxy %q: %v", proxyID, err)
		return nil, err
	}
	resp.Resources = append(resp.Resources, *ms)

	return resp, nil
}

func newSDSConnection(peerAddr string, stream discoveryStream) *sdsConnection {
	return &sdsConnection{
		doneChannel: make(chan int, 1),
		pushChannel: make(chan *sdsEvent, 1),
		PeerAddr:    peerAddr,
		Connect:     time.Now(),
		stream:      stream,
	}
}

func receiveThread(con *sdsConnection, reqChannel chan *xdsapi.DiscoveryRequest, errP *error) {
	defer close(reqChannel) // indicates close of the remote side.
	for {
		req, err := con.stream.Recv()
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
