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

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/metadata"

	"istio.io/istio/pkg/cmd"
	"istio.io/istio/security/pkg/nodeagent/cache"
	"istio.io/istio/security/pkg/nodeagent/sds"
	capb "istio.io/istio/security/proto/ca/v1alpha1"
)

var (
	cacheOptions  cache.Options
	serverOptions sds.Options

	// RootCmd defines the command for node agent.
	RootCmd = &cobra.Command{
		Use:   "nodeagent",
		Short: "Node agent",
		RunE: func(c *cobra.Command, args []string) error {
			stop := make(chan struct{})

			// TODO(quanlin): use real caClient when it's ready.
			caClient := &mockCAClient{}
			sc := cache.NewSecretCache(caClient, cacheOptions)
			defer sc.Close()

			server, err := sds.NewServer(serverOptions, sc)
			defer server.Stop()
			if err != nil {
				return fmt.Errorf("failed to create sds service: %v", err)
			}

			cmd.WaitSignal(stop)

			return nil
		},
	}
)

func init() {

	RootCmd.PersistentFlags().StringVar(&serverOptions.UDSPath, "sdsUdsPath",
		"/var/run/sds/uds_path", "Unix domain socket through which SDS server communicates with proxies")
	/*
		RootCmd.PersistentFlags().StringVar(&serverOptions.UDSPath, "sdsUdsPath",
			"/tmp/uds_path", "Unix domain socket through which SDS server communicates with proxies")*/

	//local test through TLS using '/etc/istio/nodeagent-sds-cert.pem' and '/etc/istio/nodeagent-sds-key.pem'
	RootCmd.PersistentFlags().StringVar(&serverOptions.CertFile, "sdsCertFile", "", "SDS gRPC TLS server-side certificate")
	RootCmd.PersistentFlags().StringVar(&serverOptions.KeyFile, "sdsKeyFile", "", "SDS gRPC TLS server-side key")

	RootCmd.PersistentFlags().DurationVar(&cacheOptions.SecretTTL, "secretTtl",
		time.Hour, "Secret's TTL")
	RootCmd.PersistentFlags().DurationVar(&cacheOptions.RotationInterval, "secretRotationInterval",
		10*time.Minute, "Secret rotation job running interval")
	RootCmd.PersistentFlags().DurationVar(&cacheOptions.EvictionDuration, "secretEvictionDuration",
		24*time.Hour, "Secret eviction time duration")
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// TODO(quanlin): remove mockCAClient when real caClient when it's ready.
type mockCAClient struct {
}

func (c *mockCAClient) CSRSign(ctx context.Context, csrPEM []byte, subjectID string,
	certValidTTLInSec int64) ([]byte /*PEM-encoded certificate chain*/, error) {
	req := &capb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		SubjectId:        subjectID,
		ValidityDuration: certValidTTLInSec,
	}

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", fmt.Sprintf("Bearer %s", subjectID)))
	log.Printf("*****request to CA is %+v \n", *req)
	log.Printf("*****request.Csr to CA is %+v \n", req.Csr)
	log.Printf("*****request.SubjectId to CA is %+v \n", req.SubjectId)
	log.Printf("*****request.ValidityDuration to CA is %+v \n", req.ValidityDuration)
	log.Printf("*****ctx to CA is %+v \n", ctx)

	return csrPEM, nil
}
