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

package model

import (
	"reflect"
	"testing"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/config/grpc_credential/v2alpha"
	"github.com/gogo/protobuf/types"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
)

func TestConstructSdsSecretConfig(t *testing.T) {
	cases := []struct {
		serviceAccount string
		metadata       map[string]string
		expectedConfig *v2alpha.FileBasedMetadataConfig
	}{
		{
			serviceAccount: "spiffe://cluster.local/ns/bar/sa/foo",
			metadata:       map[string]string{model.NodeMetadataSdsTrustJwt: "1"},
			expectedConfig: &v2alpha.FileBasedMetadataConfig{
				SecretData: &core.DataSource{
					Specifier: &core.DataSource_Filename{
						Filename: K8sSATrustworthyJwtFileName,
					},
				},
				HeaderKey: K8sSAJwtTokenHeaderKey,
			},
		},
		{
			serviceAccount: "spiffe://cluster.local/ns/bar/sa/foo",
			metadata:       map[string]string{model.NodeMetadataSdsTrustJwt: "0"},
			expectedConfig: &v2alpha.FileBasedMetadataConfig{
				SecretData: &core.DataSource{
					Specifier: &core.DataSource_Filename{
						Filename: K8sSAJwtFileName,
					},
				},
				HeaderKey: K8sSAJwtTokenHeaderKey,
			},
		},
		{
			serviceAccount: "",
			expectedConfig: nil,
		},
	}

	for _, c := range cases {
		expected := &auth.SdsSecretConfig{
			Name:      c.serviceAccount,
			SdsConfig: constructsdsconfighelper(c.metadata, K8sSAJwtTokenHeaderKey, c.expectedConfig),
		}
		if c.serviceAccount == "" {
			expected = nil
		}
		if got := ConstructSdsSecretConfig(c.serviceAccount, c.metadata); !reflect.DeepEqual(got, expected) {
			t.Errorf("ConstructSdsSecretConfig: got(%+v) != want(%+v)\n", got, expected)
		}
	}
}

func TestConstructSdsSecretConfigForGatewayListener(t *testing.T) {
	cases := []struct {
		serviceAccount string
		sdsUdsPath     string
		expected       *auth.SdsSecretConfig
	}{
		{
			serviceAccount: "spiffe://cluster.local/ns/bar/sa/foo",
			sdsUdsPath:     "/tmp/sdsuds.sock",
			expected: &auth.SdsSecretConfig{
				Name: "spiffe://cluster.local/ns/bar/sa/foo",
				SdsConfig: &core.ConfigSource{
					InitialFetchTimeout: features.InitialFetchTimeout,
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType: core.ApiConfigSource_GRPC,
							GrpcServices: []*core.GrpcService{
								{
									TargetSpecifier: &core.GrpcService_GoogleGrpc_{
										GoogleGrpc: &core.GrpcService_GoogleGrpc{
											TargetUri:  "/tmp/sdsuds.sock",
											StatPrefix: SDSStatPrefix,
										},
									},
								},
							},
							RefreshDelay: nil,
						},
					},
				},
			},
		},
		{
			serviceAccount: "",
			sdsUdsPath:     "/tmp/sdsuds.sock",
			expected:       nil,
		},
		{
			serviceAccount: "spiffe://cluster.local/ns/bar/sa/foo",
			sdsUdsPath:     "",
			expected:       nil,
		},
	}

	for _, c := range cases {
		if got := ConstructSdsSecretConfigForGatewayListener(c.serviceAccount, c.sdsUdsPath); !reflect.DeepEqual(got, c.expected) {
			t.Errorf("ConstructSdsSecretConfig: got(%#v) != want(%#v)\n", got, c.expected)
		}
	}
}

func constructLocalChannelCredConfig() *core.GrpcService_GoogleGrpc_ChannelCredentials {
	return &core.GrpcService_GoogleGrpc_ChannelCredentials{
		CredentialSpecifier: &core.GrpcService_GoogleGrpc_ChannelCredentials_LocalCredentials{
			LocalCredentials: &core.GrpcService_GoogleGrpc_GoogleLocalCredentials{},
		},
	}
}

func constructGCECallCredConfig() *core.GrpcService_GoogleGrpc_CallCredentials {
	return &core.GrpcService_GoogleGrpc_CallCredentials{
		CredentialSpecifier: &core.GrpcService_GoogleGrpc_CallCredentials_GoogleComputeEngine{
			GoogleComputeEngine: &types.Empty{},
		},
	}
}

func constructsdsconfighelper(metadata map[string]string, headerKey string, metaConfig *v2alpha.FileBasedMetadataConfig) *core.ConfigSource {
	tokenFileName := K8sSAJwtFileName
	if metadata[model.NodeMetadataSdsTrustJwt] == "1" {
		tokenFileName = K8sSATrustworthyJwtFileName
	}

	any := findOrMarshalFileBasedMetadataConfig(tokenFileName, headerKey, metaConfig)
	return &core.ConfigSource{
		InitialFetchTimeout: features.InitialFetchTimeout,
		ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				ApiType: core.ApiConfigSource_GRPC,
				GrpcServices: []*core.GrpcService{
					{
						TargetSpecifier: &core.GrpcService_GoogleGrpc_{
							GoogleGrpc: &core.GrpcService_GoogleGrpc{
								TargetUri:              WorkloadSdsUdsPath,
								StatPrefix:             SDSStatPrefix,
								CredentialsFactoryName: "envoy.grpc_credentials.file_based_metadata",
								ChannelCredentials:     constructLocalChannelCredConfig(),
								CallCredentials: []*core.GrpcService_GoogleGrpc_CallCredentials{
									{
										CredentialSpecifier: &core.GrpcService_GoogleGrpc_CallCredentials_FromPlugin{
											FromPlugin: &core.GrpcService_GoogleGrpc_CallCredentials_MetadataCredentialsFromPlugin{
												Name: "envoy.grpc_credentials.file_based_metadata",
												ConfigType: &core.GrpcService_GoogleGrpc_CallCredentials_MetadataCredentialsFromPlugin_TypedConfig{
													TypedConfig: any},
											},
										},
									},
								},
							},
						},
					},
				},
				RefreshDelay: nil,
			},
		},
	}
}
