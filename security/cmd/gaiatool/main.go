package main

import (
	"context"
	"flag"
	"log"

	"github.com/golang/protobuf/ptypes/duration"
	credpb "google.golang.org/genproto/googleapis/iam/credentials/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var (
	addr = flag.String("addr", "iamcredentials.googleapis.com:443", "Address of grpc server.")
)

func main() {

	flag.Parse()

	creds, err := credentials.NewClientTLSFromFile("/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/gaiatool/roots.pem", "")
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
	c := credpb.NewIAMCredentialsClient(conn)
	log.Print("**********after creating client.....")

	callIdentityBindingAccessToken(c)
	//callGenerateAccessToken(c)
}

func callIdentityBindingAccessToken(c credpb.IAMCredentialsClient) {
	// k8sa
	//quanlingcptoken
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidGVzdGdhaWExQGlzdGlvbm9kZWFnZW50dGVzdHByb2oyLmlhbS5nc2VydmljZWFjY291bnQuY29tIl0sImV4cCI6MTU3MjAzMTAyMSwiaWF0IjoxNTQwNDkxMDIxLCJpc3MiOiJodHRwczovL3N0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vZ2tlLW9pZGMvZjgzYTQ1NjdhYzE1NWI3YWJjZjI4NTI5ZThmNDViNTFlMTA2MDE0NGI5OGJhMmY5YzU0MDQyMGJkMzc1NDAzNyIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsInBvZCI6eyJuYW1lIjoidHJ5ZnNhMSIsInVpZCI6IjNjNGNmMzMxLWQ4ODEtMTFlOC04YTM2LTQyMDEwYWYwMDAxYSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2luczEiLCJ1aWQiOiIzYzQxMDZjNi1kODgxLTExZTgtOGEzNi00MjAxMGFmMDAwMWEifX0sIm5iZiI6MTU0MDQ5MTAyMSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6amVua2luczEifQ.hK9m3-Nwd8B7jLeW4P3mecUwtUVgNcgGcQRAMpZRp9KYzhlP_LYW4UlVpSyU6dcH2qbIpmVnHKO2xOyU7Z4HiY6R9S6Pz7cKd6HLL5SxuJK9HBSivWJN_1DZW0urJMN1Xy06V8RxvOAzvozh3XgQMczsS48_UuMKRDbtytGGFZeydXl3Mz_Yp2Z8bAKMv03ARNX1LHiFdore0f4FLPeohT2WSkcymlS5Z-ScJW_VSTybpznvWOwxGTnvbdYJ2MzmbWkWHgF-yFLu5fbbCzrVDCtZyLzE5FZmdhehcQ6lR_u0lZdRFqOIkVuioUPshguZ88RxNcoi5mJFQxbuecKrmw"
	req := constructcallIdentityBindingAccessTokenRequest(token)
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token))

	log.Print("**********before GenerateIdentityBindingAccessToken.....")
	r, err := c.GenerateIdentityBindingAccessToken(ctx, req)
	if err != nil {
		log.Fatalf("GenerateIdentityBindingAccessToken failed: %v", err)
	}
	log.Printf("Result: %s", r.AccessToken)
}

func constructcallIdentityBindingAccessTokenRequest(token string) *credpb.GenerateIdentityBindingAccessTokenRequest {

	req := &credpb.GenerateIdentityBindingAccessTokenRequest{
		Name:  "projects/-/serviceAccounts/testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		Scope: []string{"https://www.googleapis.com/auth/cloud-platform"},
		Jwt:   token,
	}
	return req
}

func callGenerateAccessToken(c credpb.IAMCredentialsClient) {
	req := constructGenerateAccessTokenRequest()
	ctx := context.Background()

	// Got from https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateAccessToken, first get token for
	// 'nodeagenttestaccount1@istionodeagenttestproj2.iam.gserviceaccount.com'
	token := "Bearer ya29.c.EloxBoJqVeSQpOQt7sKG14hCyOOQ3sZ7W-pSJbJRmymgyqmxFstN9cGGaLnHei7wDmopETGL5oCdm2fjE-oKQ-k9iZ6FB1CF9zdTORXqfm4K6jZa_PZkLEOnFf0"
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token))
	log.Print("**********before GenerateAccessToken.....")
	r, err := c.GenerateAccessToken(ctx, req)
	if err != nil {
		log.Fatalf("GenerateAccessToken failed: %v", err)
	}
	log.Printf("Result: %s", r.AccessToken)
}

func constructGenerateAccessTokenRequest() *credpb.GenerateAccessTokenRequest {
	req := &credpb.GenerateAccessTokenRequest{
		Name:  "projects/-/serviceAccounts/testgaia1@istionodeagenttestproj2.iam.gserviceaccount.com",
		Scope: []string{"https://www.googleapis.com/auth/cloud-platform"},
		Lifetime: &duration.Duration{
			Seconds: 3600,
		},
	}
	return req
}
