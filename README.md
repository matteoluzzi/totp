# TOTP

A from-scratch Go implementation of the TOTP (Time-based One-Time Password)
algorithm, following [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
and [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) (HOTP), compatible
with standard authenticator apps (Google Authenticator, Microsoft Authenticator, etc.).

> **Disclaimer:** this is a learning project built to get familiar with Go —
> it has not been audited or hardened for production use. The secret
> is stored unencrypted on disk and error handling favors simplicity over
> robustness.

## How it works

1. **Secret**: on first run, a random 128-bit secret is generated
   (`generate128BitRandomSecret`), Base32-encoded and saved to a file
   (`$TMPDIR/totp_secret.txt`). On subsequent runs the secret is read back and
   decoded from there, so the generated code stays stable across runs.
2. **Time counter**: the current Unix timestamp is divided into 30-second
   windows (`numOfSteps`) and serialized as an 8-byte big-endian integer.
3. **HMAC-SHA1**: the counter is signed with HMAC-SHA1 using the secret as the
   key, producing a 20-byte digest.
4. **Dynamic Truncation**: the 20-byte digest is reduced to a 6-digit numeric
   code (`dynamicTruncate`), following the dynamic truncation algorithm
   described in RFC 4226 §5.3.
5. **QR code**: the secret is wrapped into an `otpauth://totp/...` URI and
   rendered as a QR code directly in the terminal, ready to be scanned by an
   authenticator app.
6. **Validation**: the program prompts for the code shown by the authenticator
   app and compares it (`validateTOTP`) against the one recomputed for the
   current time window.

## Usage

```bash
go run main.go
```

On first run a new secret is generated and saved, then a QR code is printed to
the terminal:

<img width="501" height="653" alt="image" src="https://github.com/user-attachments/assets/9202ff79-a68c-4494-a3c3-fa22313d8eab" />


Scan it with an authenticator app (e.g. Google Authenticator), then enter the
6-digit code shown by the app when prompted by the program, to verify it
matches the one computed locally.

