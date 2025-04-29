package checker_test

import (
	"testing"

	"github.com/maxatome/go-testdeep/td"
	"github.com/ovh/yubico-piv-checker/lib/checker"
	"github.com/ovh/yubico-piv-checker/lib/types"
)

type TestKey struct {
	sshKey         string
	attestation    string
	keyCertificate string
	expected       types.Result
}

var tests = []TestKey{
	{
		sshKey: `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClBrnz47s5ER1vnhBSaKIYddvDBty9LFoLOJ3/EmJahzMex80vZA61QO+vRAjM64gwDHgtmoSjiwCAq20J7EZgqJDOuxgX5zLG7rA6xxooQEvVMkmKlHkIeCnBlOwhtr5YjQ4hk0DboLK+955c7kiqW7dJkzHVnzyYG0ILQiSlrY+cCEa/UceGv74fgMQe71B8UC32N27IxN/gssqgHSvgMiQ8nMNQJW2h0mIT3/pKceu+gt4qscZCYYq9Qoz6tPIDZA7KaBZb0Y7kSAenEwjsTQvy5/iE8ELPRBZtmHdW/R78bljX/UZ5sEN5lw9MRHz2zFhFPxdcfpnnQopFH0QJ`,
		attestation: `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
		keyCertificate: `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
		expected: types.Result{
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
	},
	{
		sshKey: `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRO5gTpfStu+5V1iFTBw5bNtBJ5WX9ApRuKONm0xzf6ZMLDNacqFFXkOtTllmIZhbE/6pkj/xFWJbSYaoPgr7o5s/UMRGIL3PzpTwXps9KzCbA6X4IXiY4nEQicGqBuKT+Azhzayt/+v8oJfDA/xdhXbTAHx9auMJsV/xfH0y3X66deoIFTmOcyKw7ZIlh7yVnhVi86Ekemhrjzi0WLJ1BBfnPuP/CynImbL0G8AJ5tJTob6766N0jS4w85VU6Vi6lKSfYkYLALZt6p/6ijVxP49N/80Klh5yC/MD1sKPZm/NzSk978FE9rIAsGz4Retulo620nR+x28SsM16paZp9 PIV AUTH pubkey`,
		attestation: `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIQAQZAHf5lzS87WROEsDVieTANBgkqhkiG9w0BAQsFADAi
MSAwHgYDVQQDDBdZdWJpS2V5IFBJViBBdHRlc3RhdGlvbjAgFw0yNDEyMDEwMDAw
MDBaGA85OTk5MTIzMTIzNTk1OVowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0
ZXN0YXRpb24gOWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRO5gT
pfStu+5V1iFTBw5bNtBJ5WX9ApRuKONm0xzf6ZMLDNacqFFXkOtTllmIZhbE/6pk
j/xFWJbSYaoPgr7o5s/UMRGIL3PzpTwXps9KzCbA6X4IXiY4nEQicGqBuKT+Azhz
ayt/+v8oJfDA/xdhXbTAHx9auMJsV/xfH0y3X66deoIFTmOcyKw7ZIlh7yVnhVi8
6Ekemhrjzi0WLJ1BBfnPuP/CynImbL0G8AJ5tJTob6766N0jS4w85VU6Vi6lKSfY
kYLALZt6p/6ijVxP49N/80Klh5yC/MD1sKPZm/NzSk978FE9rIAsGz4Retulo620
nR+x28SsM16paZp9AgMBAAGjTjBMMBEGCisGAQQBgsQKAwMEAwUHBDAUBgorBgEE
AYLECgMHBAYCBAHzPo0wEAYKKwYBBAGCxAoDCAQCAwEwDwYKKwYBBAGCxAoDCQQB
BDANBgkqhkiG9w0BAQsFAAOCAQEAOX0LlaciiuPtcxziExLQgboc+IypeV4izAVX
1zbdNw8+iMLXxxSjAratrIIc9MyqalcKB+E/JbZyXOJsMdBfvNqPHqPwDQZ1ybMb
SBqFuEAXyDeicsAAjFlr1PXkSSKD1iyrdvjGBZQytVtO4FYT4Rk7+Wio9IEV/2g+
lO+yUfMr0CQqtDwjVLRtVSUqxMQdMrtlIsXoTM12ORJauTy+dOoFY5VSJr3bf1Oi
VbOz+liM5CMCWi0YqtG4v4LufQdfdSA6f66VDyATUUu9kKEdNph0AGY36ek9Oswx
QPhDxaNdNcJKPnFH4ryTCXIa2cSxsqRAeJyFvrNvSw5ZappXmA==
-----END CERTIFICATE-----`,
		keyCertificate: `-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIJAJXcF5k7Lbf8MA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNV
BAMMGll1YmljbyBQSVYgQXR0ZXN0YXRpb24gQiAxMCAXDTI0MTIwMTAwMDAwMFoY
Dzk5OTkxMjMxMjM1OTU5WjAiMSAwHgYDVQQDDBdZdWJpS2V5IFBJViBBdHRlc3Rh
dGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALfGsJlUJlSFW9U1
LiPJe2J0HEy0wacxa53c0UEexr/ZtgmrIf/CVh8kqE4qpMs5igeyqxqZqLjdNqZZ
mdYFfHJL6AKSppCcWYnaHN6rSj6OgBpidg9uaQlNx+03fXn7GJHQhWYgvTX9qczm
fkqh2rh4a14Bg2ipgBePwwvPUidHSdqytfMgq+H1YzbouamXyHdcpW/OPPOeoTwv
+X4fr3bldpwABqHDT/mM/znh16dhQu7QlPFgnG3rNK6ddCIdVuFs+LqYlU7Ute+f
QbVp8FiravxczUb1GRRKMNkWGtA6m5P87zyAw8vUbnMlsflj6paHAwOpzXfAT4/G
k65UhqUCAwEAAaMpMCcwEQYKKwYBBAGCxAoDAwQDBQcEMBIGA1UdEwEB/wQIMAYB
Af8CAQAwDQYJKoZIhvcNAQELBQADggEBAEsyUM3GxUCWSHliTfcF9+r5BEILfR/5
2cdpRfaJWSdW+/bHUffdGWRD6PckY3AQBpgap3zBgzE5yq2Kv3A1bnAFo6DHjPCn
waos9hFm/YVidxjWvi0brHwKHHGGQdSmQzLAG7/aabpfaVfEurQDBBUoZAnBxdMP
tLaS+HGhAVbTgyh9glZrfqZi/aoM57JB5yBZ8GCzUazN6CdE5TnEs+ooVQXfQNP2
wNkM2IMOE/CNXa/UVp9s3JH7hloW/VNoynK5SlMrJ+acoehM3fDM4NgIpE+q8ei8
+sjUk8NEdie+vPIEgpS8ZEGX1030kuRfw47GG4CJEN9fbB2jaqzU/Mg=
-----END CERTIFICATE-----`,
		expected: types.Result{
			SSHKey: types.SSHKey{
				FingerprintMD5: "fb:d8:74:4b:c7:70:6b:1b:18:ea:a1:d4:71:90:fe:cc",
				FingerprintSHA: "SHA256:7bhN1DGrz1RfrP4XFxofylRN8ePE6cDdgwguu5cqFKU",
			},
			Yubikey: types.Yubikey{
				SerialNumber:    32718477,
				FirmwareVersion: "5.7.4",
				PinPolicy:       types.PinPolicyAlways,
				TouchPolicy:     types.TouchPolicyNever,
			},
		},
	},
}

func TestCheck(t *testing.T) {
	for _, v := range tests {
		result, err := checker.VerifySSHKey(v.sshKey, v.attestation, v.keyCertificate)
		td.Require(t).CmpNoError(err)
		td.Require(t).Cmp(result, &v.expected)
	}
}
