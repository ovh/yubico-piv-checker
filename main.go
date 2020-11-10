package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/errors"
)

func init() {
	log.SetOutput(os.Stderr)
}

func ParseCertificate(cert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("Invalid PEM type")
	}

	return x509.ParseCertificate(block.Bytes)
}

func VerifySSHKey(sshKey string, attestation string, keyCertificate string) (*Result, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse SSH Key %q", sshKey)
	}

	// Parse attestation and check associated public key
	att, err := ParseCertificate(attestation)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse attestation")
	}
	attPubKey, err := ssh.NewPublicKey(att.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to compute SSH Key from attestation")
	}
	if !bytes.Equal(sshPubKey.Marshal(), attPubKey.Marshal()) {
		return nil, errors.New("SSH Key doesn't match attestation")
	}

	// Parse key certificate and verify attestation signature
	keyCert, err := ParseCertificate(keyCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse Key Certificate")
	}
	err = keyCert.CheckSignature(att.SignatureAlgorithm, att.RawTBSCertificate, att.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid attestation signature")
	}

	// Parse YubicoCA and verify keyCertificate signature
	yubiCert, err := ParseCertificate(yubicoCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse Yubico Certificate")
	}
	err = yubiCert.CheckSignature(keyCert.SignatureAlgorithm, keyCert.RawTBSCertificate, keyCert.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid Key Certificate signature")
	}

	var r Result
	r.SSHKey.FingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
	r.SSHKey.FingerprintSHA = ssh.FingerprintSHA256(sshPubKey)

	// Extract Key Metadata
	for _, e := range att.Extensions {
		if e.Id.Equal(oidExtensionYubikeySerialNumber) {
			var serialNumber int
			if _, err := asn1.Unmarshal(e.Value, &serialNumber); err == nil {
				r.Yubikey.SerialNumber = serialNumber
			}
		} else if e.Id.Equal(oidExtensionYubikeyFirmware) && len(e.Value) == 3 {
			r.Yubikey.FirmwareVersion = fmt.Sprintf("%d.%d.%d", e.Value[0], e.Value[1], e.Value[2])
		} else if e.Id.Equal(oidExtensionYubikeyPolicy) && len(e.Value) == 2 {
			r.Yubikey.PinPolicy = YubicoPinPolicy(e.Value[0])
			r.Yubikey.TouchPolicy = YubicoTouchPolicy(e.Value[1])
		}
	}

	return &r, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s ssh-key attestation key-certificate\n", os.Args[0])
		os.Exit(-1)
	}

	r, err := VerifySSHKey(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	err = json.NewEncoder(os.Stdout).Encode(r)
	if err != nil {
		log.Fatal(err)
	}
}
