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
	//token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidmF1bHQiXSwiZXhwIjoxNTM5MDQ2NDk2LCJpYXQiOjE1MzkwMzkyOTYsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9na2Utb2lkYy9iZWUwNjBlNGEzZWQ2NTMyYjg0YzRjYjI5MTY0MzcxNjUwNGExNWY5NGMwNzBjMDE3OGU5NzdjNjU1MzUwNjZkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJoZWxsb3BvZCIsInVpZCI6ImE1MmVjNzk1LWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2lucyIsInVpZCI6ImE1MWZjYjNmLWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9fSwibmJmIjoxNTM5MDM5Mjk2LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.IrarCNl4jVYvymkRJ151VinCOK8oWjniwb3NxeMKeQhNosmMK9B8OupfLakDo89WD-xq-47P8c1cLCBwP-_Rg2xHTAPQ0OyR_yuZuNURfLHqLEh2BqcpzKWwk0FjPK9uVFru3jQEAqaSg-sW8dIcAf6qy14y1ui-irV4MiaWNzLpqBQjkt4IaDq3ikk5gBBwDFAAP1GSy1IoXvmZrwu5SMtAwC09QmI3qe5xlPvWsxfZ_ui95gMfCdrxEolg3zKr46YvVY6oyfEO6rhna04WzaSauL38PJ183-qPbEqOWoZvDxVCv5uVI6dx-PIHrYgqcNSoMPc7moj38052ogQ-MQ"
	//token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidmF1bHQiXSwiZXhwIjoxNTM4Njk4ODA1LCJpYXQiOjE1Mzg2OTE2MDUsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9na2Utb2lkYy9iZWUwNjBlNGEzZWQ2NTMyYjg0YzRjYjI5MTY0MzcxNjUwNGExNWY5NGMwNzBjMDE3OGU5NzdjNjU1MzUwNjZkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJoZWxsb3BvZCIsInVpZCI6ImE1MmVjNzk1LWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2lucyIsInVpZCI6ImE1MWZjYjNmLWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9fSwibmJmIjoxNTM4NjkxNjA1LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.bL-Awy10Bg8i4AEqvv8z-A2CnA9ypjKiKBHIeyayLn1C3btplN72agY20eJq0vz57bVpfp76ISSVyfTK0O4txfbwqW1wz_-uPI9FuPy0iLlE7B_pY_io2vdhFeKWiaYzsomw_fu0NAI1w5u5Uwr13Jue3jAIDlKwS7Tkcr3MV73-FWp4mKJIoCXaq58BGdEybK3rootroot@helc"

	//quanlingcptoken
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsidmF1bHQiXSwiZXhwIjoxNTM5MTE2MDAwLCJpYXQiOjE1MzkxMDg4MDAsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9na2Utb2lkYy9iZWUwNjBlNGEzZWQ2NTMyYjg0YzRjYjI5MTY0MzcxNjUwNGExNWY5NGMwNzBjMDE3OGU5NzdjNjU1MzUwNjZkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJoZWxsb3BvZCIsInVpZCI6ImE1MmVjNzk1LWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiamVua2lucyIsInVpZCI6ImE1MWZjYjNmLWM4MjMtMTFlOC04ZGZjLTQyMDEwYTgwMDAwNyJ9fSwibmJmIjoxNTM5MTA4ODAwLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpqZW5raW5zIn0.BjE2SkBGn9mVWNKBEB6EuqSz3Efk4VF_8iV78fVfqfkZp7ogixGkzWPBCQkN78u2TZsJCRzGC7Z_he5qWJG6mGmoYActdga1aVnNI1ObjpIntAqy03GPmmJi81FmmSuhyfH04l_uusZtur_YEB8qtC7Kbiz4gVa3BUpXo5zoHNNxuEFHdZnC8fINhFp-tB7TY9O6TknPr1R7m76rJQmDjbSzeGCtS4q1Qf35VcnwYEPq0reex-NktfyBHk3agVQ2pivmBH-N2Xnah5-6atJhgNCXIaCTaVV0E9bvt8w3Zr7HH3hooZUf7-nidBcl26G9xWBLhJ86degsr5R_hEaLrg"
	req := constructcallIdentityBindingAccessTokenRequest(token)
	ctx := context.Background()
	//ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token))

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
