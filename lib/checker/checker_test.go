package checker_test

import (
	"testing"

	"github.com/maxatome/go-testdeep/td"
	"github.com/ovh/yubico-piv-checker/lib/checker"
	"github.com/ovh/yubico-piv-checker/lib/types"
)

var sshKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClBrnz47s5ER1vnhBSaKIYddvDBty9LFoLOJ3/EmJahzMex80vZA61QO+vRAjM64gwDHgtmoSjiwCAq20J7EZgqJDOuxgX5zLG7rA6xxooQEvVMkmKlHkIeCnBlOwhtr5YjQ4hk0DboLK+955c7kiqW7dJkzHVnzyYG0ILQiSlrY+cCEa/UceGv74fgMQe71B8UC32N27IxN/gssqgHSvgMiQ8nMNQJW2h0mIT3/pKceu+gt4qscZCYYq9Qoz6tPIDZA7KaBZb0Y7kSAenEwjsTQvy5/iE8ELPRBZtmHdW/R78bljX/UZ5sEN5lw9MRHz2zFhFPxdcfpnnQopFH0QJ`

var attestation = `-----BEGIN CERTIFICATE-----
MIIDDjCCAfagAwIBAgIQC30eN1m5fD/2maEAvc5okDANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw
MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl
c3RhdGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKUGufPj
uzkRHW+eEFJoohh128MG3L0sWgs4nf8SYlqHMx7HzS9kDrVA769ECMzriDAMeC2a
hKOLAICrbQnsRmCokM67GBfnMsbusDrHGihAS9UySYqUeQh4KcGU7CG2vliNDiGT
QNugsr73nlzuSKpbt0mTMdWfPJgbQgtCJKWtj5wIRr9Rx4a/vh+AxB7vUHxQLfY3
bsjE3+CyyqAdK+AyJDycw1AlbaHSYhPf+kpx676C3iqxxkJhir1CjPq08gNkDspo
FlvRjuRIB6cTCOxNC/Ln+ITwQs9EFm2Yd1b9HvxuWNf9RnmwQ3mXD0xEfPbMWEU/
F1x+medCikUfRAkCAwEAAaM8MDowEQYKKwYBBAGCxAoDAwQDBAMFMBMGCisGAQQB
gsQKAwcEBQIDWxouMBAGCisGAQQBgsQKAwgEAgMBMA0GCSqGSIb3DQEBCwUAA4IB
AQCPj0beqrn+4SgVfwTnECiKKZ/apSIznU1e4BVhZk912lzDm2T2gFK5i7IwaocK
xhVdClB+i8O4S0U17jZ+80Am0672iJVsK7Z6c2jj/N83nKq5Mbj3Ycp7wfsu2AnK
XpGIbDYb2L2ZPf95ayL/bMTQlb7tntlTijsjet0XDSAARhzP4EjCJ5jZL2IOC4dU
APsYsYd5o9dyGTWEwckvLdP1lDJlVT8d0+BfpiqA68gbG1QHuPVLkUTuijMQp4yo
ZQrjIgBsY9/Av/jcy3QhA+PZ89ziJ15LgOd7xIxEUWiJBxOSkhy1o1+huLMP+yl3
z9m9buobWgFKI098M+XQOAXk
-----END CERTIFICATE-----`

var keyCertificate = `-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIJAIDJ0Mz+WTdUMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV
BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw
MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0
dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbtblxQC
Xlyh/2yI/e/4MAWboIXhQDDhsT2GBoE/wCF3Yan1dQ5VfFMxa4aIaJIVfxvjw574
q/7MbS9oVFqqrqc5f7hS/kW0fCYuzgpCEcod3hOcJOIPjplDmBHhOaR3punP57Je
n8MKS6iU/qwa1aKLpYvBcV1Q2Ep9pQMtSqJ1GXXwSNe0V8LNTRh9gJlolHJdp9OS
9YTYlvB3O0TSd2QLAxOnUkfEwXdsi33n3usgcCEqMsPRnz6ULeOMeWPEnW/rZr7E
mbNcf/VFDwxytbWm/rHva02EQvJ7scVRcnA8hPWY9S5iiOplM69FJ7Y2u8nCoz/3
PwyKPwluYkWL4QIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEAwQwDQYJKoZIhvcN
AQELBQADggEBAGYtvFFppUdbMuEvcQoI/1NmSi0YSjoNq2Yxv6HlIOWOrtmU1CNU
NyE1rmb8jWIDQJp7iDbxUjTpRiGTqZUx1I6DOA2Jl1UJFIV40G3WZno8s8VEc+S7
3U/f5jbuSYrn27uOw7a10jl7eGhZO4I2Kp0sIcmPzT8Y/GoRlPVj6V+g8yOOlvUA
lSnC/SnEdd7eN4+nLZ19v3HfpP6XK14YGApdHl4M1Qq1ucngpG2K4VEVl5V/OrmI
IbgcOpOvXvLmyhy8yoGCP27LS0qO9AT7tJiLcGJXnG3sN2D7ewsRHj1Sszfi6QKt
LL62+racaCSKom8Ty1yBgNiZmcho8+buAfU=
-----END CERTIFICATE-----`

func TestCheck(t *testing.T) {
	result, err := checker.VerifySSHKey(sshKey, attestation, keyCertificate)
	td.Require(t).CmpNoError(err)

	td.Cmp(t, result, td.Struct(
		&types.Result{
			SSHKey: types.SSHKey{
				FingerprintMD5: "46:00:b0:eb:d1:fd:b7:86:ea:da:09:7a:49:dd:e3:56",
				FingerprintSHA: "SHA256:V0yDye/t5QVSC6nAnQ8MsgYUS/bZZKQmB0cYk6+UgqI",
			},
			Yubikey: types.Yubikey{
				SerialNumber:    5970478,
				FirmwareVersion: "4.3.5",
				PinPolicy:       types.PinPolicyAlways,
				TouchPolicy:     types.TouchPolicyNever,
			},
		},
	))
}
