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

type federatedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	//ExpiresIn       string `json:"expires_in"`
	ExpiresIn int64 `json:"expires_in"` // Expiration time in seconds
}

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
	//jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidGVzdGdhaWExQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU3NjM3MDY2NCwiaWF0IjoxNTQ0ODMwNjY0LCJpc3MiOiJodHRwczovL3Rlc3QtY29udGFpbmVyLnNhbmRib3guZ29vZ2xlYXBpcy5jb20vdjEvcHJvamVjdHMvaXN0aW9ub2RlYWdlbnR0ZXN0cHJvajIvbG9jYXRpb25zL3VzLWNlbnRyYWwxLWEvY2x1c3RlcnMvdGtjbHVzdGVyNiIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6IjQxMmFkODczLWZmZjktMTFlOC1hZjFiLTQyMDEwYTgwMDAwOCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiI0MTFkNzJmNy1mZmY5LTExZTgtYWYxYi00MjAxMGE4MDAwMDgifX0sIm5iZiI6MTU0NDgzMDY2NCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.TKf9kTKygDF2OqgqzmbJmaa5TPwzRgt_lxUA1L_22GQtAaJ97lguQEVWphrSXYdwWA9W0mSAbJO2hL2RBV2wyssLdI12vwmHoJPnSVE0miJYnWr4N5bJTA2oi99965J9asdZgNnteTanAhBVQPjBYhB1qXwPhf0p8-mVs1byahMHOPsCcXfjASskCzs8LOtEM2-7UPK9Ucialde2oGGQFXBLqqxxpdevQRy4pQEJu4o8QTkulrjQeAMArSHIkzrtPWCzirSuigYFxoQ_mt0zqZ-sH0gD2qb5FxOh_K_d-dqM2MFRKf3cip9z4uSO9Be3pCG7xMNukShjjw_pW6l9mA"
	jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsia3ViZS1mZWRlcmF0aW5nLWlkQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU0NTE3MjM2NiwiaWF0IjoxNTQ1MTI5MTY2LCJpc3MiOiJodHRwczovL3Rlc3QtY29udGFpbmVyLnNhbmRib3guZ29vZ2xlYXBpcy5jb20vdjEvcHJvamVjdHMvaXN0aW9ub2RlYWdlbnR0ZXN0cHJvajIvbG9jYXRpb25zL3VzLWNlbnRyYWwxLWMvY2x1c3RlcnMvbXBpLWNsdXN0ZXItMSIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6ImI2NWFmZDdhLTAyNWYtMTFlOS1iY2YzLTQyMDEwYTgwMDAxMSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiJiNjRmNTc2OC0wMjVmLTExZTktYmNmMy00MjAxMGE4MDAwMTEifX0sIm5iZiI6MTU0NTEyOTE2Niwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.UNRVL8xBOeT4e0dnjHFbKAgUGE1YfqRHIiaDE9naM62PJSQp3EHtA9vePH_w1CQQah_MP9X4Bxiz4OtgCc2kIPnU9xSLIqHW8e0ganM_Q5HPoHsGQRXAkbpJr9fEgFOk6Z1bPT07NzfyfCovae9rCt0lIpO9zO8OA1PetP8V2B71VQ1GtsTDDV0mX-ywwaBAMCwF_4bcGWa707PsW94ApbGMlxiy_SVbrswjO944OCufjgbHooz_dKVMe7uzpYl515Ds5IHw1oSFJoICdO3VPF3WhdCvluUNbYY5oZTivjYqw-l6EdeqHWTxmlKszGVnwxMF9SpmoSjntcyjWQMz-g"
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

	respData := &federatedTokenResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
		fmt.Printf("****failed to unmarshal response data: %+v", err)
	}

	fmt.Printf("******access token is %q", respData.AccessToken)
}

func getFederatedToken(jwt string) []byte {
	values := map[string]string{
		//"audience":           "testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		"audience":           "kube-federating-id@istionodeagenttestproj2.iam.gserviceaccount.com",
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
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidGVzdGdhaWExQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU3NjM3MDY2NCwiaWF0IjoxNTQ0ODMwNjY0LCJpc3MiOiJodHRwczovL3Rlc3QtY29udGFpbmVyLnNhbmRib3guZ29vZ2xlYXBpcy5jb20vdjEvcHJvamVjdHMvaXN0aW9ub2RlYWdlbnR0ZXN0cHJvajIvbG9jYXRpb25zL3VzLWNlbnRyYWwxLWEvY2x1c3RlcnMvdGtjbHVzdGVyNiIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6IjQxMmFkODczLWZmZjktMTFlOC1hZjFiLTQyMDEwYTgwMDAwOCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiI0MTFkNzJmNy1mZmY5LTExZTgtYWYxYi00MjAxMGE4MDAwMDgifX0sIm5iZiI6MTU0NDgzMDY2NCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.TKf9kTKygDF2OqgqzmbJmaa5TPwzRgt_lxUA1L_22GQtAaJ97lguQEVWphrSXYdwWA9W0mSAbJO2hL2RBV2wyssLdI12vwmHoJPnSVE0miJYnWr4N5bJTA2oi99965J9asdZgNnteTanAhBVQPjBYhB1qXwPhf0p8-mVs1byahMHOPsCcXfjASskCzs8LOtEM2-7UPK9Ucialde2oGGQFXBLqqxxpdevQRy4pQEJu4o8QTkulrjQeAMArSHIkzrtPWCzirSuigYFxoQ_mt0zqZ-sH0gD2qb5FxOh_K_d-dqM2MFRKf3cip9z4uSO9Be3pCG7xMNukShjjw_pW6l9mA"
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
