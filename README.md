yubico-piv-checker
==========

`yubico-piv-checker` checks that a SSH keypair was generated on device by a Yubikey.
If the signature is valid, it will extract key metadata like the serial number of the YubiKey or its firmware version.

See [PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html) and [Using PIV for SSH through PKCS #11](https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html) on Yubico's website for more informations.

## Usage
```
yubico-piv-checker ssh-key attestation key-certificate
```

### In a nutshell
```
$ yubico-piv-checker "$(yubico-piv-tool --action=read-certificate --slot=9a --key-format=SSH)" \
                     "$(yubico-piv-tool --action=attest --slot=9a)" \
                     "$(yubico-piv-tool --action=read-certificate --slot=f9)"

{
  "SSHKey": {
    "FingerprintMD5": "89:a6:6e:73:7c:9b:d3:cd:e6:e2:96:36:9e:4c:37:41",
    "FingerprintSHA": "SHA256:dMc4uhZhaAlqqt9CGn7jXBAh9/tgid3aj4KCKs7G9n4"
  },
  "Yubikey": {
    "SerialNumber": 5970478,
    "FirmwareVersion": "4.3.5",
    "PinPolicy": "Always",
    "TouchPolicy": "Never"
  }
}
```

### SSH Key
See Yubico's [documentation](https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html) on how to generate and use SSH with a yubikey.

The public ssh key can be obtained with `yubico-piv-tool`:

```
$ yubico-piv-tool --action=read-certificate --slot=9a --key-format=SSH
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUXG4e/v2d163pczmKY7DdYpwQ+etPw70SwmUQAn+6B0EJ34mtUPvRkgOyYgXPghfzzo03IFGrRvzbJTSh/PvjVAwWDsJjAu33WYY3pfBbyxgP32jDnwzi9COMPmJcfueLYOezRa4HjG6cLsaLWfx0i/EKCFDAN5MAAhNgs4ln+qIk8jBtYArOC301HourLW5nBFxKG75ICYS4cAoL4G1a/S6lnNExFws9xArvhpPyFp/3SoRaqVfVJj9l0YdP/LAejn2QklU2YEM0fOEMR1aDjByYbrtkKdaixDfFZ7KQ8U/4n95VDBkPCRDKkqTxfAnvnE83WhNwujdZTF91iHQL
```

### Attestation
The attestation can be obtained with `yubico-piv-tool`:
```
$ yubico-piv-tool --action=attest --slot=9a
-----BEGIN CERTIFICATE-----
MIIDDjCCAfagAwIBAgIQHVhKX2smMe9N8/DOnR9T/TANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw
MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl
c3RhdGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANRcbh7+
/Z3XrelzOYpjsN1inBD560/DvRLCZRACf7oHQQnfia1Q+9GSA7JiBc+CF/POjTcg
UatG/NslNKH8++NUDBYOwmMC7fdZhjel8FvLGA/faMOfDOL0I4w+Ylx+54tg57NF
rgeMbpwuxotZ/HSL8QoIUMA3kwACE2CziWf6oiTyMG1gCs4LfTUei6stbmcEXEob
vkgJhLhwCgvgbVr9LqWc0TEXCz3ECu+Gk/IWn/dKhFqpV9UmP2XRh0/8sB6OfZCS
VTZgQzR84QxHVoOMHJhuu2Qp1qLEN8VnspDxT/if3lUMGQ8JEMqSpPF8Ce+cTzda
E3C6N1lMX3WIdAsCAwEAAaM8MDowEQYKKwYBBAGCxAoDAwQDBAMFMBMGCisGAQQB
gsQKAwcEBQIDWxouMBAGCisGAQQBgsQKAwgEAgMBMA0GCSqGSIb3DQEBCwUAA4IB
AQBT3eom3hKZ30bcv4XTpNs/WcyvJC5qrtggbzuRrmaZdkbpqXfTs7lJGT8uqbeq
lZQNTQFY+DUw0IdfYEI9AcJhsTrfw/QG+O/vBoQpafD9TyCQ9NSghj9zTxx3Lh3Y
VI8TM39HPxUrW6r4xE/s6/MG1LSs49Gg2FJZ/QqIbQ+vf2UIFwbUtCFaUZBMtc9i
HAxCp3Bma/Ni0CtJxBO/O7c0893M8lreF+8oG6AhaJLfL3lrmIpukt1H/smf7ZEL
de83n+2nj5oMNcGsghPscMGimJwaTdj77GP72f1enNNCNlEZeRBTBH/pRKKoUX1h
GEwi2IKkrRcOTkwYIUhG+xoB
-----END CERTIFICATE-----
```

### Key Certificate
The YubiKey comes with a pre-loaded attestation certificate signed by a [Yubico PIV CA](https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem) in slot f9.

This certificate can be extracted with `yubico-piv-tool`:
```
$ yubico-piv-tool --action=read-certificate --slot=f9
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

## Related

- [yubico-piv-tool](https://developers.yubico.com/yubico-piv-tool/) - The Yubico PIV tool is used for interacting with the Personal Identity Verification (PIV) application on a YubiKey.

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
