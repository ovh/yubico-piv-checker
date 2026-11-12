package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ovh/yubico-piv-checker/lib/checker"
)

func init() {
	log.SetOutput(os.Stderr)
}

func loadCertificatePool(filePath string) (*x509.CertPool, error) {
	if filePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA certificates")
	}

	return pool, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  Certificate mode: %s -cert <certificate> -attestation <attestation> -key-cert <key-certificate> [-ca <ca-file>]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  SSH Key mode (legacy): %s <ssh-key> <attestation> <key-certificate>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nFlags:\n")
	fmt.Fprintf(os.Stderr, "  -cert string\n")
	fmt.Fprintf(os.Stderr, "      User certificate from slot 9a\n")
	fmt.Fprintf(os.Stderr, "  -attestation string\n")
	fmt.Fprintf(os.Stderr, "        Attestation certificate for slot 9a\n")
	fmt.Fprintf(os.Stderr, "  -key-cert string\n")
	fmt.Fprintf(os.Stderr, "        Attestation key from slot f9\n")
	fmt.Fprintf(os.Stderr, "  -ca string\n")
	fmt.Fprintf(os.Stderr, "        Path to the CA certificate to validate cert from slot 9a\n")
}

func main() {
	var (
		certFlag        = flag.String("cert", "", "User certificate file or content")
		attestationFlag = flag.String("attestation", "", "Attestation certificate file or content")
		keyCertFlag     = flag.String("key-cert", "", "Key certificate file or content")
		caFlag          = flag.String("ca", "", "Trusted CA certificates file (optional)")
	)

	flag.Parse()

	// Check if using new certificate mode
	if *certFlag != "" || *attestationFlag != "" || *keyCertFlag != "" {
		if *certFlag == "" || *attestationFlag == "" || *keyCertFlag == "" {
			fmt.Fprintf(os.Stderr, "Error: -cert, -attestation, and -key-cert are all required for certificate mode\n\n")
			printUsage()
			os.Exit(-1)
		}

		// Read certificate content
		userCert := *certFlag
		attestation := *attestationFlag
		keyCert := *keyCertFlag

		// Load trusted CAs if provided
		trustedCAs, err := loadCertificatePool(*caFlag)
		if err != nil {
			log.Fatalf("Failed to load trusted CAs: %v", err)
		}

		// Verify certificate
		r, err := checker.VerifyCertificate(userCert, attestation, keyCert, trustedCAs)
		if err != nil {
			log.Fatal(err)
		}

		err = json.NewEncoder(os.Stdout).Encode(r)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		// Backwards compatibility
		if len(os.Args) != 4 {
			fmt.Fprintf(os.Stderr, "Error: Wrong number of arguments for SSH key mode\n\n")
			printUsage()
			os.Exit(-1)
		}

		r, err := checker.VerifySSHKey(os.Args[1], os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}

		err = json.NewEncoder(os.Stdout).Encode(r)
		if err != nil {
			log.Fatal(err)
		}
	}
}
