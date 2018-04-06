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
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	jwtfilter "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/jwt_authn/v2alpha"
	"github.com/gogo/protobuf/types"

	authn "istio.io/api/authentication/v1alpha1"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/log"
)

const (
	// Defautl cache duration for JWT public key. This should be moved to a global config.
	jwtPublicKeyCacheSeconds = 60 * 5

	// OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string /.well-known/openid-configuration to the Issuer.
	// according to https://openid.net/specs/openid-connect-discovery-1_0.html
	openIDDiscoveryCfgUrlSuffix = "/.well-known/openid-configuration"
)

// GetConsolidateAuthenticationPolicy returns the authentication policy for
// service specified by hostname and port, if defined.
// If not, it generates and output a policy that is equivalent to the legacy flag
// and/or service annotation. Once these legacy flags/config deprecated,
// this function can be placed by a call to store.AuthenticationPolicyByDestination
// directly.
func GetConsolidateAuthenticationPolicy(mesh *meshconfig.MeshConfig, store IstioConfigStore, hostname string, port *Port) *authn.Policy {
	config := store.AuthenticationPolicyByDestination(hostname, port)
	if config == nil {
		legacyPolicy := consolidateAuthPolicy(mesh, port.AuthenticationPolicy)
		log.Debugf("No authentication policy found for  %s:%d. Fallback to legacy authentication mode %v\n",
			hostname, port.Port, legacyPolicy)
		return legacyAuthenticationPolicyToPolicy(legacyPolicy)
	}

	return config.Spec.(*authn.Policy)
}

// consolidateAuthPolicy returns service auth policy, if it's not INHERIT. Else,
// returns mesh policy.
func consolidateAuthPolicy(mesh *meshconfig.MeshConfig,
	serviceAuthPolicy meshconfig.AuthenticationPolicy) meshconfig.AuthenticationPolicy {
	if serviceAuthPolicy != meshconfig.AuthenticationPolicy_INHERIT {
		return serviceAuthPolicy
	}
	// TODO: use AuthenticationPolicy for mesh policy and remove this conversion
	switch mesh.AuthPolicy {
	case meshconfig.MeshConfig_MUTUAL_TLS:
		return meshconfig.AuthenticationPolicy_MUTUAL_TLS
	case meshconfig.MeshConfig_NONE:
		return meshconfig.AuthenticationPolicy_NONE
	default:
		// Never get here, there are no other enum value for mesh.AuthPolicy.
		panic(fmt.Sprintf("Unknown mesh auth policy: %v\n", mesh.AuthPolicy))
	}
}

// If input legacy is AuthenticationPolicy_MUTUAL_TLS, return a authentication policy equivalent
// to it. Else, returns nil (implies no authentication is used)
func legacyAuthenticationPolicyToPolicy(legacy meshconfig.AuthenticationPolicy) *authn.Policy {
	if legacy == meshconfig.AuthenticationPolicy_MUTUAL_TLS {
		return &authn.Policy{
			Peers: []*authn.PeerAuthenticationMethod{{
				Params: &authn.PeerAuthenticationMethod_Mtls{}}},
		}
	}
	return nil
}

// RequireTLS returns true and pointer to mTLS params if the policy use mTLS for (peer) authentication.
// (note that mTLS params can still be nil). Otherwise, return (false, nil).
func RequireTLS(policy *authn.Policy) (bool, *authn.MutualTls) {
	if policy == nil {
		return false, nil
	}
	if len(policy.Peers) > 0 {
		for _, method := range policy.Peers {
			switch method.GetParams().(type) {
			case *authn.PeerAuthenticationMethod_Mtls:
				return true, method.GetMtls()
			default:
				continue
			}
		}
	}
	return false, nil
}

// ParseJwksURI parses the input URI and returns the corresponding hostname, port, and whether SSL is used.
// URI must start with "http://" or "https://", which corresponding to "http" or "https" scheme.
// Port number is extracted from URI if available (i.e from postfix :<port>, eg. ":80"), or assigned
// to a default value based on URI scheme (80 for http and 443 for https).
// Port name is set to URI scheme value.
// Note: this is to replace [buildJWKSURIClusterNameAndAddress]
// (https://github.com/istio/istio/blob/master/pilot/pkg/proxy/envoy/v1/mixer.go#L401),
// which is used for the old EUC policy.
func ParseJwksURI(jwksURI string) (string, *Port, bool, error) {
	u, err := url.Parse(jwksURI)
	if err != nil {
		return "", nil, false, err
	}
	var useSSL bool
	var portNumber int
	switch u.Scheme {
	case "http":
		useSSL = false
		portNumber = 80
	case "https":
		useSSL = true
		portNumber = 443
	default:
		return "", nil, false, fmt.Errorf("URI scheme %q is not supported", u.Scheme)
	}

	if u.Port() != "" {
		portNumber, err = strconv.Atoi(u.Port())
		if err != nil {
			return "", nil, useSSL, err
		}
	}

	return u.Hostname(), &Port{
		Name: u.Scheme,
		Port: portNumber,
	}, useSSL, nil
}

// JwksURIClusterName returns cluster name for the jwks URI. This should be used
// to override the name for outbound cluster that are added for Jwks URI so that they
// can be referred correctly in the JWT filter config.
func JwksURIClusterName(hostname string, port *Port) string {
	const clusterPrefix = "jwks."
	const maxClusterNameLength = 189 - len(clusterPrefix)
	name := hostname + "|" + port.Name
	if len(name) > maxClusterNameLength {
		prefix := name[:maxClusterNameLength-sha1.Size*2]
		sum := sha1.Sum([]byte(name))
		name = fmt.Sprintf("%s%x", prefix, sum)
	}
	return clusterPrefix + name
}

// CollectJwtSpecs returns a list of all JWT specs (ponters) defined the policy. This
// provides a convenient way to iterate all Jwt specs.
func CollectJwtSpecs(policy *authn.Policy) []*authn.Jwt {
	ret := []*authn.Jwt{}
	if policy == nil {
		return ret
	}
	for _, method := range policy.Peers {
		switch method.GetParams().(type) {
		case *authn.PeerAuthenticationMethod_Jwt:
			ret = append(ret, method.GetJwt())
		}
	}
	for _, method := range policy.Origins {
		ret = append(ret, method.Jwt)
	}
	return ret
}

// ConvertPolicyToJwtConfig converts policy into Jwt filter config for envoy. The
// config is still incomplete though: the jwks_uri_envoy_cluster has not been set
// yet; it should be filled by pilot, accordingly how those clusters are added.
// Also note,  the Jwt filter implementation is in Istio proxy, but it is under
// upstreamming process
// (https://github.com/envoyproxy/data-plane-api/pull/530/files).
// The output of this function should use the Envoy data-plane-api proto once
// this migration finished.
func ConvertPolicyToJwtConfig(policy *authn.Policy) *jwtfilter.JwtAuthentication {
	log.Infof("*********************ConvertPolicyToJwtConfig - quanjie*********************")
	policyJwts := CollectJwtSpecs(policy)
	if len(policyJwts) == 0 {
		return nil
	}
	ret := &jwtfilter.JwtAuthentication{
		AllowMissingOrFailed: true,
	}
	for _, policyJwt := range policyJwts {
		jwksUri, err := getJwksUri(policyJwt)
		if err != nil {
			log.Errorf("Cannot get jwks_uri %q: %v", policyJwt.Issuer, err)
			continue
		}

		log.Infof("****************ConvertPolicyToJwtConfig jwksUri is %q", jwksUri)

		hostname, port, _, err := ParseJwksURI(jwksUri)
		if err != nil {
			log.Errorf("Cannot parse jwks_uri %q: %v", jwksUri, err)
			continue
		}
		log.Infof("*********************ConvertPolicyToJwtConfig JwksUri %s, hostname %s, port %+v*********************", jwksUri, hostname, port)

		jwt := &jwtfilter.JwtRule{
			Issuer:    policyJwt.Issuer,
			Audiences: policyJwt.Audiences,
			JwksSourceSpecifier: &jwtfilter.JwtRule_RemoteJwks{
				RemoteJwks: &jwtfilter.RemoteJwks{
					HttpUri: &core.HttpUri{
						Uri: jwksUri,
						HttpUpstreamType: &core.HttpUri_Cluster{
							Cluster: JwksURIClusterName(hostname, port),
						},
					},
					CacheDuration: &types.Duration{Seconds: jwtPublicKeyCacheSeconds},
				},
			},
			Forward: true,
		}
		for _, location := range policyJwt.JwtHeaders {
			jwt.FromHeaders = append(jwt.FromHeaders, &jwtfilter.JwtHeader{
				Name: location,
			})
		}
		jwt.FromParams = policyJwt.JwtParams
		ret.Rules = append(ret.Rules, jwt)
	}

	log.Infof("*********************ConvertPolicyToJwtConfig - return %+v*********************", ret)
	return ret
}

func getJwksUri(policyJwt *authn.Jwt) (string, error) {
	// Return directly if policyJwt.JwksUri is set, this could happen if policyJwt.Issuer is an email address.
	if policyJwt.JwksUri != "" {
		return policyJwt.JwksUri, nil
	}

	// If policyJwt.Issuer isn't set, try to get it through OpenID Discovery.
	// according https://openid.net/specs/openid-connect-discovery-1_0.html,
	// OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string /.well-known/openid-configuration to the Issuer.
	discoveryUrl := policyJwt.Issuer + openIDDiscoveryCfgUrlSuffix
	log.Infof("*********************getJwksUri - discoveryUrl %s*********************", discoveryUrl)

	resp, err := http.Get(discoveryUrl)
	if err != nil {
		log.Errorf("*********************getJwksUri - failure to get openID discovery configuration, %v", err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("*********************getJwksUri - failure to read openID discovery configuration, %v", err)
		return "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return "", err
	}

	jwksUri, ok := data["jwks_uri"].(string)
	if !ok {
		return "", fmt.Errorf("Invalid jwks_uri %v in openID discovery configuration", data["jwks_uri"])
	}

	return jwksUri, nil
}
