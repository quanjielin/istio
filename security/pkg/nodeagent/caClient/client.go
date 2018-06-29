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

package ca

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"istio.io/istio/pkg/log"
	capb "istio.io/istio/security/proto/ca/v1alpha1"
)

// Client interface defines the clients need to implement to talk to CA for CSR.
type Client interface {
	CSRSign(ctx context.Context, csrPEM []byte, /*PEM-encoded certificate request*/
		subjectID string, certValidTTLInSec int64) ([]byte /*PEM-encoded certificate chain*/, error)
}

type caClient struct {
	client capb.IstioCertificateServiceClient
}

// NewCAClient create an CA client.
func NewCAClient(addr string, dialOptions []grpc.DialOption) (Client, error) {
	conn, err := grpc.Dial(addr, dialOptions...)
	if err != nil {
		log.Errorf("Failed to connect to CA: %v", err)
		return nil, err
	}

	return &caClient{
		client: capb.NewIstioCertificateServiceClient(conn),
	}, nil
}

func (cl *caClient) CSRSign(ctx context.Context, csrPEM []byte, /*PEM-encoded certificate request*/
	subjectID string, certValidTTLInSec int64) ([]byte /*PEM-encoded certificate chain*/, error) {
	req := &capb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		SubjectId:        subjectID,
		ValidityDuration: certValidTTLInSec,
	}

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", fmt.Sprintf("Bearer %s", subjectID)))
	resp, err := cl.client.CreateCertificate(ctx, req)
	if err != nil {
		log.Errorf("Failed to create certificate: %v", err)
		return nil, err
	}

	if len(resp.CertChain) == 0 {
		log.Errorf("Got empty cert chain")
		return nil, errors.New("empty cert chain")
	}

	// Returns the leaf cert(Leaf cert is element '0', Root cert is element 'n').
	return []byte(resp.CertChain[0]), nil
}
