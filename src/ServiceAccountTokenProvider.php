<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Blerify\Auth\Exception\AuthException;
use Firebase\JWT\JWT;
use Ramsey\Uuid\Uuid;

/**
 * Obtains a Blerify access token for a service account.
 *
 * Flow (RFC 7523 private_key_jwt), as accepted by Blerify IAM at
 * `POST /auth/v2/protocol/openid-connect/token`:
 *
 *   1. Sign a short-lived JWT *client assertion* with the service-account
 *      private key (RS256).
 *   2. POST `{client_id, organization_id, client_assertion}` to the token
 *      endpoint as `application/x-www-form-urlencoded`.
 *   3. Receive an access token and cache it until shortly before it expires.
 *
 * The returned access token is sent on subsequent API calls as:
 *   `Authorization: Bearer <access_token>`
 */
final class ServiceAccountTokenProvider
{
    /** Lifetime of the signed client assertion (not the returned access token). */
    private const ASSERTION_TTL_SECONDS = 3600;

    /** Refresh the cached access token this many seconds before it expires. */
    private const RENEW_SKEW_SECONDS = 60;

    private ?string $cachedToken = null;
    private int $cachedExpiresAt = 0;

    public function __construct(
        private readonly ServiceAccountCredentials $credentials,
        private readonly TokenEndpointClient $tokenClient = new CurlTokenEndpointClient(),
        private readonly string $signingAlgorithm = 'RS256',
    ) {
    }

    /**
     * Convenience constructor that loads credentials from a service-account file.
     */
    public static function fromFile(string $path, ?TokenEndpointClient $tokenClient = null): self
    {
        return new self(
            ServiceAccountCredentials::fromFile($path),
            $tokenClient ?? new CurlTokenEndpointClient(),
        );
    }

    public function organizationId(): string
    {
        return $this->credentials->organizationId;
    }

    /**
     * Build and sign a fresh client-assertion JWT.
     *
     * Exposed mainly for testing and for callers that want the raw assertion;
     * normal usage only needs {@see getAccessToken()}.
     *
     * @param int|null $now override the current time (seconds since epoch)
     */
    public function createAssertion(?int $now = null): string
    {
        $now ??= time();

        $payload = [
            'iss' => $this->credentials->clientId,
            'sub' => $this->credentials->clientId,
            'aud' => $this->credentials->audience,
            'iat' => $now,
            'exp' => $now + self::ASSERTION_TTL_SECONDS,
            'jti' => Uuid::uuid4()->toString(),
        ];

        return JWT::encode($payload, $this->credentials->privateKey, $this->signingAlgorithm);
    }

    /**
     * Return a valid access token, reusing the cached one until it is close to
     * expiry.
     *
     * @param int|null $now override the current time (seconds since epoch)
     */
    public function getAccessToken(?int $now = null): string
    {
        $now ??= time();

        if ($this->cachedToken !== null && $this->cachedExpiresAt - self::RENEW_SKEW_SECONDS > $now) {
            return $this->cachedToken;
        }

        $assertion = $this->createAssertion($now);

        $response = $this->tokenClient->postForm($this->credentials->tokenUri, [
            'client_id' => $this->credentials->clientId,
            'organization_id' => $this->credentials->organizationId,
            'client_assertion' => $assertion,
        ]);

        if (!isset($response['access_token']) || !is_string($response['access_token'])) {
            throw new AuthException('Token endpoint response did not contain an access_token');
        }

        $expiresIn = isset($response['expires_in']) && is_numeric($response['expires_in'])
            ? (int) $response['expires_in']
            : self::ASSERTION_TTL_SECONDS;

        $this->cachedToken = $response['access_token'];
        $this->cachedExpiresAt = $now + $expiresIn;

        return $this->cachedToken;
    }
}
