package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	stpb "istio.io/istio/security/proto/providers/google/iam"
)

var (
	addr = flag.String("addr", "securetoken.googleapis.com:443", "Address of grpc server.")
)

func main() {
	flag.Parse()
	testUseHttpClient()
}

// GetFederatedToken generates an OAuth2.0 access token by providing a third-party
// Json Web Token conforming to OAuth2 token exchange spec.
func testUseHttpClient() {
	url := "https://securetoken.googleapis.com/v1/identitybindingtoken"
	contentType := "application/json"
	//var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidGVzdGdhaWExQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU3NjI4MzU4NywiaWF0IjoxNTQ0NzQzNTg3LCJpc3MiOiJodHRwczovL3Rlc3QtY29udGFpbmVyLnNhbmRib3guZ29vZ2xlYXBpcy5jb20vdjFhbHBoYTEvcHJvamVjdHMvaXN0aW9ub2RlYWdlbnR0ZXN0cHJvajIvbG9jYXRpb25zL3VzLWNlbnRyYWwxLWEvY2x1c3RlcnMvdGtjbHVzdGVyNSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6IjQzY2Y3ODQzLWY0MmQtMTFlOC04Mjg2LTQyMDEwYTgwMDAwMyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiI0M2E5MGFhZC1mNDJkLTExZTgtODI4Ni00MjAxMGE4MDAwMDMifX0sIm5iZiI6MTU0NDc0MzU4Nywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.OIXbd6pmF04mgD9YMHeJypiUEVrRB5iyz4ZkT_jvcMyDEdGd8ba3QaAidhh75-s1G-yV_7GjXN_DFqNoIzD5ccbZUjhazGeNG9PCUNhlz1W9Lzbh_JjNftfrEswAMO5fvQ0177Yv-jc4rhYoSsQr3VIc1vjAHYKBnNXcjvONEm02hu-PoEVxkKvpaAdio-I5qh8DBXlFiLsvbOsgEYdwaOmYji69HFuz7hv-LM1gWhvHvl5mEQ5q6yARJ-A9WFQRFmWXF0tPmwa4pvkjwqwWOVxeE1FeytJNSc9xvw39d5AuTUNMMWoQPTpujjiicSUfAjEVkKuyAgV0DoRMdQM4Ng"
	var jsonStr = getFederatedToken(jwt)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", contentType)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("*******failed to call securetoken api: %v", err)
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
}

func getFederatedToken(jwt string) []byte {
	values := map[string]string{
		"audience":           "testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
	}
	jsonValue, _ := json.Marshal(values)

	/*
		body.Set("audience", "testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com")
		body.Set("grantType", "urn:ietf:params:oauth:grant-type:token-exchange")
		body.Set("requestedTokenType", "urn:ietf:params:oauth:token-type:access_token")
		body.Set("subjectTokenType", "urn:ietf:params:oauth:token-type:jwt")
		body.Set("subjectToken", jwt)
		body.Add("scope", "https://www.googleapis.com/auth/cloud-platform")
		result := body.Encode() */
	log.Printf("******getFederatedToken %q", jsonValue)
	return jsonValue
}

func testUsegRPC() {
	creds, err := credentials.NewClientTLSFromFile("/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/testclient/roots.pem", "")
	if err != nil {
		log.Fatalf("Unable to read root certificate file: %v", err)
	}

	//conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	log.Print("**********before creating client.....")
	c := stpb.NewCertificateServiceClient(conn)
	log.Print("**********after creating client.....")

	callGetFederatedToken(c)
	//callGenerateAccessToken(c)
}

func callGetFederatedToken(c stpb.CertificateServiceClient) {
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidGVzdGdhaWExQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU3NjE5NzE1OCwiaWF0IjoxNTQ0NjU3MTU4LCJpc3MiOiJodHRwczovL3Rlc3QtY29udGFpbmVyLnNhbmRib3guZ29vZ2xlYXBpcy5jb20vdjFhbHBoYTEvcHJvamVjdHMvaXN0aW9ub2RlYWdlbnR0ZXN0cHJvajIvbG9jYXRpb25zL3VzLWNlbnRyYWwxLWEvY2x1c3RlcnMvdGtjbHVzdGVyNSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6IjQzY2Y3ODQzLWY0MmQtMTFlOC04Mjg2LTQyMDEwYTgwMDAwMyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiI0M2E5MGFhZC1mNDJkLTExZTgtODI4Ni00MjAxMGE4MDAwMDMifX0sIm5iZiI6MTU0NDY1NzE1OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.qp-h5tS-yx9ULNvvWmcsIn0pBpRsOwVU9S_xdbcvnXolfS399PyBYYrgrG67MLy5PMBsnNmWy_n013DJosBy_A2pMZdR3fYt7IpbZvFZ-FqVkvhJ1TQFFlpz8a2CZrW5-QEkQXcQ4qZ5dVMJmebG3OeEnx48bxgEoFCTp2pR6GZFdm599l4Ye5-XZdNwNapsqvgmNqh5_NHXeha5hosn_-_5DJT2YAgWU1m7Rf81-nlJHTtSNCfDXtCIs7zYgrHHfDbyvOJL27SDXuiX9YiO4QH19iDeArtYB6v2X5PgBiUE1MzQ-2AG3fQRnCUi0jH-PMbtInwGl9AbhJjHbgYO_g"
	//token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidmF1bHQiXSwiZXhwIjoxNTM4Njk4ODA1LCJpYXQiOjE1Mzg2OTE2MDUsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9na2Utb2lkYy9iZWUwNjBlNGEzZWQ2NTMyYjg0YzRjYjI5MTY0MzcxNjUwNGExNWY5NGMwNzBjMDE3OGU5NzdjNjU1MzUwNjZkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJoZWxsb3BvZCIsInVpZCI6ImE1MmVjNzk1LWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2lucyIsInVpZCI6ImE1MWZjYjNmLWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9fSwibmJmIjoxNTM4NjkxNjA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.bL-Awy10Bg8i4AEqvv8z-A2CnA9ypjKiKBHIeyayLn1C3btplN72agY20eJq0vz57bVpfp76ISSVyfTK0O4txfbwqW1wz_-uPI9FuPy0iLlE7B_pY_io2vdhFeKWiaYzsomw_fu0NAI1w5u5Uwr13Jue3jAIDlKwS7Tkcr3MV73-FWp4mKJIoCXaq58BGdEybK3rootroot@helc"
	req := constructGetFederatedTokenRequest(token)
	ctx := context.Background()

	//ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token))
	//ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Content-Type", "application/x-www-form-urlencoded"))

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token, "Content-Type", "application/json"))

	log.Print("**********before GenerateIdentityBindingAccessToken.....")
	r, err := c.GetFederatedToken(ctx, req)
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.Data)
}

func constructGetFederatedTokenRequest(jwt string) *stpb.GetFederatedTokenRequest {

	req := &stpb.GetFederatedTokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:token-exchange",
		Audience:  "testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		//Name:               "projects/-/serviceAccounts/testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectToken:       jwt,
		Scope:              []string{"https://www.googleapis.com/auth/cloud-platform"},
		//Jwt:                token,
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	}
	return req
}
