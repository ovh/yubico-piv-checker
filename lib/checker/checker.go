package checker

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/ovh/yubico-piv-checker/lib/types"

	"golang.org/x/crypto/ssh"
)

func parseCertificate(cert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type")
	}

	return x509.ParseCertificate(block.Bytes)
}

func VerifySSHKey(sshKey string, attestation string, keyCertificate string) (*types.Result, error) {
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH Key %q: %w", sshKey, err)
	}

	// Parse attestation and check associated public key
	att, err := parseCertificate(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}
	attPubKey, err := ssh.NewPublicKey(att.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute SSH Key from attestation: %w", err)
	}
	if !bytes.Equal(sshPubKey.Marshal(), attPubKey.Marshal()) {
		return nil, fmt.Errorf("SSH Key doesn't match attestation")
	}

	// Parse key certificate and verify attestation signature
	keyCert, err := parseCertificate(keyCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Key Certificate: %w", err)
	}
	err = keyCert.CheckSignature(att.SignatureAlgorithm, att.RawTBSCertificate, att.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation signature: %w", err)
	}
	err = yubiCert.CheckSignature(keyCert.SignatureAlgorithm, keyCert.RawTBSCertificate, keyCert.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid Key Certificate signature: %w", err)
	}

	var r types.Result
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
			r.Yubikey.PinPolicy = types.YubicoPinPolicy(e.Value[0])
			r.Yubikey.TouchPolicy = types.YubicoTouchPolicy(e.Value[1])
		}
	}

	return &r, nil
}
