package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"

	//pb "cloud.google.com/go/ca/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/metadata"
	capb "istio.io/istio/security/proto/ca/v1alpha1"
)

var (
	addr = flag.String("addr", "prod-istioca.sandbox.googleapis.com:443", "Address of grpc server.")
	//addr         = flag.String("addr", "prod-istioca.sandbox.googleapis.com:80", "Address of grpc server.")
	keyfile      = flag.String("keyfile", "/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/key.json", "Path to a Google service account key file.")
	audience     = flag.String("audience", "fakecauser1@istionodeagenttestproj1.iam.gserviceaccount.com", "Audience.")
	rootCertFile = flag.String("rootCertFile", "/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/roots.pem", "Root certificates file.")
)

func main() {
	flag.Parse()

	creds, err := credentials.NewClientTLSFromFile("/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/roots.pem", "")
	if err != nil {
		log.Fatalf("Unable to read root certificate file: %v", err)
	}

	//conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := capb.NewIstioCertificateServiceClient(conn)
	callByToken(c)
}

func callByToken(c capb.IstioCertificateServiceClient) {
	req, token := constructRequest()
	ctx := context.Background()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token))

	r, err := c.CreateCertificate(ctx, req)
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.CertChain)
}

func constructRequest() (*capb.IstioCertificateRequest, string) {
	token := "Bearer ya29.c.ElsGBulq1AItv25e-9k2-Mfsl9XZl_mL9i78DV_uAjw1hbcD8MRz5x1OgCRcK2naB-amBo_1KBxEFSLzfavMLLpHq1u5AJj5Y5dwxQwQ9H2vuQoqITWjBRAJo4B2"
	gaiaID := "100196431587596687555"
	content, err := ioutil.ReadFile("/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/csr.csr")
	if err != nil {
		log.Fatalf("failed to read pem file %q", err)
	}

	csr := string(content)
	log.Printf("csr is %q", csr)

	req := &capb.IstioCertificateRequest{
		SubjectId:        gaiaID,
		ValidityDuration: 3600,
		Csr:              csr}
	return req, token
}

func prev() {
	flag.Parse()

	// Set up a connection to the server.
	//creds, err := credentials.NewClientTLSFromFile(*rootCertFile, "")

	creds, err := credentials.NewClientTLSFromFile("/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/roots.pem", "")
	if err != nil {
		log.Fatalf("Unable to read root certificate file: %v", err)
	}

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := capb.NewIstioCertificateServiceClient(conn)

	/*
		if *keyfile != "" {
			log.Printf("Authenticating using Google service account key in %s\n", *keyfile)
			keyBytes, err := ioutil.ReadFile(*keyfile)
			if err != nil {
				log.Fatalf("Unable to read service account key file %s: %v", *keyfile, err)
			}

			tokenSource, err := google.JWTAccessTokenSourceFromJSON(keyBytes, *audience)
			if err != nil {
				log.Fatalf("Error building JWT access token source: %v", err)
			}
			jwt, err := tokenSource.Token()
			if err != nil {
				log.Fatalf("Unable to generate JWT token: %v", err)
			}
			*token = jwt.AccessToken
			// NOTE: the generated JWT token has a 1h TTL.
			// Make sure to refresh the token before it expires by calling TokenSource.Token() for each outgoing requests.
			// Calls to this particular implementation of TokenSource.Token() are cheap.
			log.Printf("*********token is %s\n", *token)
		}

		ctx := context.Background()
		if *token != "" {
			log.Printf("Using authentication token: %s", *token)
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", fmt.Sprintf("Bearer %s", *token)))
		}*/

	ctx := context.Background()
	// Contact the server and print out its response.
	scope := "https://www.googleapis.com/auth/cloud-platform"
	perRPCCred, err := oauth.NewServiceAccountFromFile(*keyfile, scope)
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}

	//TODO(quanlin):use token to initialize credentials.PerRPCCredentials
	_, err = oauth.NewApplicationDefault(ctx, scope)
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}

	r, err := c.CreateCertificate(ctx, &capb.IstioCertificateRequest{SubjectId: "foo"}, grpc.PerRPCCredentials(perRPCCred))
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.CertChain)

}

func callByKeyFile(c capb.IstioCertificateServiceClient) {
	ctx := context.Background()
	// Contact the server and print out its response.
	scope := "https://www.googleapis.com/auth/cloud-platform"
	perRPCCred, err := oauth.NewServiceAccountFromFile(*keyfile, scope)
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}

	req, _ := constructRequest()
	r, err := c.CreateCertificate(ctx, req, grpc.PerRPCCredentials(perRPCCred))
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.CertChain)
}

/*
func constructRequest() (*capb.IstioCertificateRequest, string) {
	//token := "Bearer ya29.c.ElsFBrKgKHLUpgVjght3yzMWGCwj9GE2TXTi4sFDmm7MFcrvzFbewYeUZiwj21PCTHgreMO5mrq775q0v5CFrU_eJC0VG70EsTFbir1ItNbXyvr4R4kq7_ujATyy"
	token := "Bearer ya29.c.ElsFBrKgKHLUpgVjght3yzMWGCwj9GE2TXTi4sFDmm7MFcrvzFbewYeUZiwj21PCTHgreMO5mrq775q0v5CFrU_eJC0VG70EsTFbir1ItNbXyvr4R4kq7_ujATyy"
	csr := `-----BEGIN CERTIFICATE REQUEST-----
	MIICmjCCAYICAQAwCzEJMAcGA1UEChMAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
	MIIBCgKCAQEAtgxV4vQf1qld3kfoGk07yrYj0adQHZt/HkO9Zwe6BBrjgtkDqCnQ
	OjRDbsLWYiGIrktAUHfyE55Eq4g7OnB43IEhslkTIY+7pZQmJZIx0OFrFNwAfrF7
	i6CukDtGuwxi9DV9kKjTAcEaZFtR1APvMPpr/volZwKKrCIpnC1D2ljrJyYS3nhV
	gBe1xk4Zu+pG/NiXvYvvBLvZPW/VwUpfb+uf1LcnHQzWGYB87L12+1+/xbbc3cdQ
	/3Hb1sHVWc6Y5X4g1hlqmY+aNkTnSNSkoHb3gBUniK1k8fFv5zC6+iSK1f4Uo2yN
	wcdBk9v90sYhoHxG6YCvu8RucnYmge0RWwIDAQABoEowSAYJKoZIhvcNAQkOMTsw
	OTA3BgNVHREEMDAuhixzcGlmZmU6Ly9jbHVzdGVyLmxvY2FsL25zL2RlZmF1bHQv
	c2EvZGVmYXVsdDANBgkqhkiG9w0BAQsFAAOCAQEAI/ldAj7GxYQtLtxDgA7mzOAu
	YPtFtihGIT4qiNBAW5nfac6tjre9UZgRLqX3zmBSLXKW0a6MLN4FaMaBlB3z0O7J
	eR8TtOmOIv9Wu6fxfzG6CVuPSw2w6BMJ8i0Lyohyjez8yEeZkSLpxWgUiV/WX2se
	L/efqUT0034KivhGV86/TjqZ/UA0Zu5MAYO0KanZjB3KpLxt6t/IH9tVHL71jAtJ
	iIJCAI7WU62k5pAjHmvuTDDkXKq+XnHdLk/9mefNWkIEiBZedUcLRQS6ZgsEub6u
	tABUauBaXFhfjAQ6pKL0PO9Gyo4eUhI2+vGYh83fKxkygh7UTczvd6ZJRzAhYg==
	-----END CERTIFICATE REQUEST-----`
	req := &capb.IstioCertificateRequest{
		SubjectId:        token,
		ValidityDuration: 3600,
		Csr:              csr}
	return req, token
}*/
