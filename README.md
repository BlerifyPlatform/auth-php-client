# blerify/auth-php-client

Service-account authentication for PHP clients of the Blerify platform.

It signs a short-lived **JWT client assertion** with a service-account private
key and exchanges it at the Blerify IAM token endpoint for an **access token**,
which is then sent as `Authorization: Bearer <token>` on API calls. This is the
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) `private_key_jwt` client
authentication flow.

The token-acquisition logic was extracted from `blerify/mdl` (`php-mdl`) so it
can be reused by any PHP service that calls Blerify — without depending on the
mDL library.

## Requirements

- PHP >= 8.1 with `ext-curl`, `ext-openssl`, `ext-json`
- A Blerify **service-account credentials** JSON file (issued by the Blerify
  portal when a service account is created)

## Install

```bash
composer require blerify/auth-php-client
```

## Usage

```php
use Blerify\Auth\ServiceAccountTokenProvider;

$tokens = ServiceAccountTokenProvider::fromFile(__DIR__ . '/credentials.json');

// Returns a cached token until shortly before it expires.
$accessToken = $tokens->getAccessToken();

// Use it on any Blerify API request (e.g. via the gateway):
//   Authorization: Bearer {$accessToken}
```

### Runnable example

A complete runnable example lives in [`index.php`](index.php):

```bash
composer install
# Generate the service-account credentials JSON from the Blerify portal and
# save it as config/credentials.json
php index.php
```

It loads the credentials file, obtains a token, and shows how to attach it as a
`Bearer` header. The credentials JSON is generated from the Blerify portal;
`config/credentials.example.json` documents its shape, and real credentials
files under `config/` are git-ignored.

### Credentials file

The service-account JSON is generated from the Blerify portal (create a service
account, then download its credentials file). It contains (other fields are ignored):

| Field | Used for |
|---|---|
| `client_id` | `iss` / `sub` of the assertion, and the `client_id` form field |
| `organization_id` | sent as the `organization_id` form field |
| `private_key` | PEM key that signs the assertion (RS256) |
| `token_uri` | the Blerify IAM token endpoint |
| `iam_audience` | the `aud` of the assertion |

## What happens on the wire

The provider builds and signs this assertion:

```jsonc
// header
{ "alg": "RS256", "typ": "JWT" }
// payload
{
  "iss": "<client_id>",
  "sub": "<client_id>",
  "aud": "<iam_audience>",
  "iat": 1700000000,
  "exp": 1700003600,   // iat + 3600
  "jti": "<uuid-v4>"
}
```

and POSTs it as `application/x-www-form-urlencoded` to `token_uri`:

```
POST {token_uri}
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&organization_id={organization_id}&client_assertion={signed_jwt}
```

The endpoint responds with a standard OAuth2 token response; the `access_token`
field is what gets used as the Bearer token.

## Customizing the transport

`getAccessToken()` uses cURL by default. To use a different HTTP stack (or to
test without a network), implement `Blerify\Auth\TokenEndpointClient` and pass
it in:

```php
$tokens = new ServiceAccountTokenProvider($credentials, $myTokenEndpointClient);
```

## Development

```bash
composer install
composer test        # runs PHPUnit
```

Unit tests use a throwaway RSA keypair fixture (`tests/fixtures/`) to verify the
signed assertion's claims and signature, the form sent to the endpoint, token
caching and renewal, and error handling — no network or real credentials
required.
