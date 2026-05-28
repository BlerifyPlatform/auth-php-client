# Test fixtures

`test_private_key.pem.b64` / `test_public_key.pem.b64` are a **throwaway** RSA
keypair used only by the unit tests to sign and verify a JWT assertion. They are
not used anywhere outside the test suite and protect nothing.

They exist as fixtures (instead of generating a key at runtime with
`openssl_pkey_new()`) so the tests don't depend on the environment having a
usable OpenSSL config (`OPENSSL_CONF`). Signing/verifying with a supplied PEM has
no such dependency.

They are base64-encoded so the committed files contain no `-----BEGIN PRIVATE
KEY-----` header — this keeps secret scanners from flagging a test key as a leak.

Regenerate them with:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/k.pem
base64 -w0 /tmp/k.pem > test_private_key.pem.b64
openssl rsa -in /tmp/k.pem -pubout | base64 -w0 > test_public_key.pem.b64
rm /tmp/k.pem
```
