package main

import (
	"context"
	"flag"
	"log"

	pb "cloud.google.com/go/ca/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

const defaultName = "world"

var (
	addr         = flag.String("addr", "fake-istioca.sandbox.googleapis.com:443", "Address of grpc server.")
	token        = flag.String("token", "", "Authentication token.")
	keyfile      = flag.String("keyfile", "/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/key.json", "Path to a Google service account key file.")
	audience     = flag.String("audience", "fakecauser1@istionodeagenttestproj1.iam.gserviceaccount.com", "Audience.")
	rootCertFile = flag.String("rootCertFile", "/usr/local/google/home/quanlin/go/src/istio.io/istio/security/cmd/istioca_client/roots.pem", "Root certificates file.")
)

func main() {
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

	c := pb.NewIstioCertificateServiceClient(conn)

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
	scope := "https://www.googleapis.com/auth/xapi.zoo"
	perRPCCred, err := oauth.NewServiceAccountFromFile(*keyfile, scope)
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}

	//TODO(quanlin):use token to initialize credentials.PerRPCCredentials
	_, err = oauth.NewApplicationDefault(ctx, scope)
	if err != nil {
		log.Fatalf("failed to create service account: %v", err)
	}

	r, err := c.CreateCertificate(ctx, &pb.IstioCertificateRequest{SubjectId: "foo"}, grpc.PerRPCCredentials(perRPCCred))
	if err != nil {
		log.Fatalf("Call failed: %v", err)
	}
	log.Printf("Result: %s", r.CertChain)

}
