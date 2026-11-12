package checker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

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

// deriveSSHKeyFromCertificate extracts the public key from an x509 certificate
// and converts it to an SSH public key, supporting RSA, ECDSA, and Ed25519
func deriveSSHKeyFromCertificate(cert *x509.Certificate) (ssh.PublicKey, string, error) {
	var keyType string

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = "RSA"
	case *ecdsa.PublicKey:
		keyType = "ECDSA"
	case ed25519.PublicKey:
		keyType = "Ed25519"
	default:
		return nil, "", fmt.Errorf("unsupported key type: %T", pub)
	}

	sshPubKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert certificate public key to SSH key: %w", err)
	}

	return sshPubKey, keyType, nil
}

// validateCertificateChain validates that the certificate was signed by a trusted CA
func validateCertificateChain(cert *x509.Certificate, trustedRoots *x509.CertPool) ([]string, error) {
	opts := x509.VerifyOptions{
		Roots: trustedRoots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Extract the CA chain
	var caChain []string
	if len(chains) > 0 {
		for _, cert := range chains[0] {
			caChain = append(caChain, cert.Subject.CommonName)
		}
	}

	return caChain, nil
}

// formatKeyUsage converts x509.KeyUsage to human-readable strings
func formatKeyUsage(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// VerifyCertificate verifies an x509 certificate against Yubikey PIV attestation
// and validates the certificate chain against trusted CAs
func VerifyCertificate(userCert string, attestation string, keyCertificate string, trustedCARoots *x509.CertPool) (*types.Result, error) {
	// Parse user certificate
	cert, err := parseCertificate(userCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user certificate: %w", err)
	}

	// Derive SSH key from certificate
	sshPubKey, keyType, err := deriveSSHKeyFromCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to derive SSH key from certificate: %w", err)
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
		return nil, fmt.Errorf("certificate public key doesn't match attestation")
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

	// Verify key certificate against Yubikey CA
	_, err = keyCert.Verify(x509.VerifyOptions{Roots: yubiCertPoolRoots, Intermediates: yubiCertPoolIntermediates})
	if err != nil {
		return nil, fmt.Errorf("invalid Key Certificate signature: %w", err)
	}

	// Validate user certificate against trusted CAs if provided
	var caChain []string
	var isValidCA bool
	if trustedCARoots != nil {
		caChain, err = validateCertificateChain(cert, trustedCARoots)
		if err != nil {
			// Don't fail completely, just mark as not validated
			isValidCA = false
		} else {
			isValidCA = true
		}
	}

	if !isValidCA && trustedCARoots != nil {
		return nil, fmt.Errorf("user certificate validation against trusted CAs failed")
	}

	// Build result
	var r types.Result

	// SSH Key information
	r.SSHKey.FingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
	r.SSHKey.FingerprintSHA = ssh.FingerprintSHA256(sshPubKey)
	r.SSHKey.Type = keyType
	r.SSHKey.PublicKey = string(ssh.MarshalAuthorizedKey(sshPubKey))

	// Certificate information
	r.Certificate.Subject = cert.Subject.String()
	r.Certificate.Issuer = cert.Issuer.String()
	r.Certificate.SerialNumber = hex.EncodeToString(cert.SerialNumber.Bytes())
	r.Certificate.NotBefore = cert.NotBefore.Format(time.RFC3339)
	r.Certificate.NotAfter = cert.NotAfter.Format(time.RFC3339)
	r.Certificate.KeyUsage = formatKeyUsage(cert.KeyUsage)
	r.Certificate.IsValidCA = isValidCA
	r.Certificate.TrustedCAPath = caChain

	// Extract Yubikey Metadata from attestation
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

// VerifySSHKey is maintained for backward compatibility
// Deprecated: Use VerifyCertificate instead
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

	_, err = keyCert.Verify(x509.VerifyOptions{Roots: yubiCertPoolRoots, Intermediates: yubiCertPoolIntermediates})
	if err != nil {
		return nil, fmt.Errorf("invalid Key Certificate signature: %w", err)
	}

	var r types.Result
	r.SSHKey.FingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
	r.SSHKey.FingerprintSHA = ssh.FingerprintSHA256(sshPubKey)

	// Determine key type from SSH key
	switch sshPubKey.Type() {
	case "ssh-rsa":
		r.SSHKey.Type = "RSA"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		r.SSHKey.Type = "ECDSA"
	case "ssh-ed25519":
		r.SSHKey.Type = "Ed25519"
	default:
		r.SSHKey.Type = "Unknown"
	}

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
