package types

//go:generate enumer -type YubicoPinPolicy -json -text -trimprefix PinPolicy
//go:generate enumer -type YubicoTouchPolicy -json -text -trimprefix TouchPolicy

type YubicoPinPolicy byte

const (
	PinPolicyNever YubicoPinPolicy = iota + 1
	PinPolicyOncePerSession
	PinPolicyAlways
)

type YubicoTouchPolicy byte

const (
	TouchPolicyNever YubicoTouchPolicy = iota + 1
	TouchPolicyAlways
	TouchPolicyCached15s
)

type SSHKey struct {
	FingerprintMD5 string
	FingerprintSHA string
	Type           string // RSA, ECDSA, Ed25519
	PublicKey      string
}

type Certificate struct {
	Subject       string
	Issuer        string
	SerialNumber  string
	NotBefore     string
	NotAfter      string
	KeyUsage      []string
	IsValidCA     bool
	TrustedCAPath []string // Chain of trusted CAs
}

type Yubikey struct {
	SerialNumber    int
	FirmwareVersion string
	PinPolicy       YubicoPinPolicy
	TouchPolicy     YubicoTouchPolicy
}

type Result struct {
	SSHKey      SSHKey
	Certificate Certificate
	Yubikey     Yubikey
}
