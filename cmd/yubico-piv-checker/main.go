package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ovh/yubico-piv-checker/lib/checker"
)

func init() {
	log.SetOutput(os.Stderr)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s ssh-key attestation key-certificate\n", os.Args[0])
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
