package main

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

type Result struct {
	SSHKey struct {
		FingerprintMD5 string
		FingerprintSHA string
	}
	Yubikey struct {
		SerialNumber    int
		FirmwareVersion string
		PinPolicy       YubicoPinPolicy
		TouchPolicy     YubicoTouchPolicy
	}
}
