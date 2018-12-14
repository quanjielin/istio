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

// Package stsclient is for oauth token exchange integration.
package stsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"istio.io/istio/pkg/log"
	"istio.io/istio/security/pkg/nodeagent/plugin"
)

var (
	secureTokenEndpoint = "https://securetoken.googleapis.com/v1/identitybindingtoken"
	tlsFlag             = true
)

const (
	httpTimeOutInSec = 5
	contentType      = "application/json"
	scope            = "https://www.googleapis.com/auth/cloud-platform"
)

type federatedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"` // Expiration time in seconds
}

// Plugin for google securetoken api interaction.
type Plugin struct {
	//iamClient iam.IAMCredentialsClient
	secureHTTPClient *http.Client
}

// NewPlugin returns an instance of the google iam client plugin
func NewPlugin() plugin.Plugin {
	/*
		var opts grpc.DialOption
		if tlsFlag {
			pool, err := x509.SystemCertPool()
			if err != nil {
				log.Errorf("could not get SystemCertPool: %v", err)
				return nil
			}
			creds := credentials.NewClientTLSFromCert(pool, "")
			opts = grpc.WithTransportCredentials(creds)
		} else {
			opts = grpc.WithInsecure()
		}

		conn, err := grpc.Dial(iamEndpoint, opts)
		if err != nil {
			log.Errorf("Failed to connect to endpoint %q: %v", iamEndpoint, err)
			return nil
		} */

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Errorf("could not get SystemCertPool: %v", err)
		return nil
	}

	return Plugin{
		secureHTTPClient: &http.Client{
			Timeout: httpTimeOutInSec * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		},
	}
}

// ExchangeToken exchange oauth access token from trusted domain and k8s sa jwt.
func (p Plugin) ExchangeToken(ctx context.Context, trustDomain, k8sSAjwt string) (
	string /*access token*/, time.Time /*expireTime*/, error) {
	log.Info("*********start exchange token with secure token service")
	var jsonStr = constructFederatedTokenRequest(trustDomain, k8sSAjwt)
	req, err := http.NewRequest("POST", secureTokenEndpoint, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", contentType)

	resp, err := p.secureHTTPClient.Do(req)
	if err != nil {
		log.Errorf("*******failed to call securetoken api: %v", err)
		return "", time.Now(), errors.New("failed to exchange token")
	}
	defer resp.Body.Close()
	log.Infof("***securetoken response Status: %v", resp.Status)
	log.Infof("***sresponse Headers: %v", resp.Header)

	body, _ := ioutil.ReadAll(resp.Body)
	log.Infof("response Body:", string(body))
	respData := &federatedTokenResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
		fmt.Printf("****failed to unmarshal response data: %+v", err)
	}

	return respData.AccessToken, time.Now().Add(time.Second * time.Duration(respData.ExpiresIn)), nil
}

func constructFederatedTokenRequest(aud, jwt string) []byte {
	values := map[string]string{
		"audience":           aud,
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
		"scope":              scope,
	}
	jsonValue, _ := json.Marshal(values)
	return jsonValue
}
