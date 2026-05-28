<?php

declare(strict_types=1);

namespace Blerify\Auth\Tests;

use Blerify\Auth\Exception\AuthException;
use Blerify\Auth\ServiceAccountCredentials;
use Blerify\Auth\ServiceAccountTokenProvider;
use Blerify\Auth\Tests\Support\FakeTokenEndpointClient;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;

final class ServiceAccountTokenProviderTest extends TestCase
{
    private const NOW = 1_700_000_000;

    private string $privateKey;
    private string $publicKey;

    protected function setUp(): void
    {
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($res, 'RSA keypair generation failed');

        openssl_pkey_export($res, $privatePem);
        $this->privateKey = $privatePem;
        $this->publicKey = openssl_pkey_get_details($res)['key'];
    }

    protected function tearDown(): void
    {
        // Reset firebase/php-jwt's static clock override used in decode assertions.
        JWT::$timestamp = null;
    }

    private function credentials(): ServiceAccountCredentials
    {
        return new ServiceAccountCredentials(
            clientId: 'client-123',
            organizationId: 'org-abc',
            privateKey: $this->privateKey,
            tokenUri: 'https://api.example.com/auth/v2/protocol/openid-connect/token',
            audience: 'https://iam.example.com/realms/org-abc',
        );
    }

    /** @return array<string,mixed> */
    private function decodeWithClockAt(string $jwt, int $now): array
    {
        JWT::$timestamp = $now;

        return (array) JWT::decode($jwt, new Key($this->publicKey, 'RS256'));
    }

    public function testAssertionHasExpectedClaimsAndSignature(): void
    {
        $provider = new ServiceAccountTokenProvider($this->credentials());
        $assertion = $provider->createAssertion(self::NOW);

        $claims = $this->decodeWithClockAt($assertion, self::NOW);

        $this->assertSame('client-123', $claims['iss']);
        $this->assertSame('client-123', $claims['sub']);
        $this->assertSame('https://iam.example.com/realms/org-abc', $claims['aud']);
        $this->assertSame(self::NOW, $claims['iat']);
        $this->assertSame(self::NOW + 3600, $claims['exp']);
        $this->assertNotEmpty($claims['jti']);
    }

    public function testEachAssertionHasAUniqueJti(): void
    {
        $provider = new ServiceAccountTokenProvider($this->credentials());

        $a = $this->decodeWithClockAt($provider->createAssertion(self::NOW), self::NOW);
        $b = $this->decodeWithClockAt($provider->createAssertion(self::NOW), self::NOW);

        $this->assertNotSame($a['jti'], $b['jti']);
    }

    public function testGetAccessTokenReturnsTokenAndSendsCorrectForm(): void
    {
        $fake = new FakeTokenEndpointClient(['access_token' => 'tok-xyz', 'expires_in' => 3600]);
        $provider = new ServiceAccountTokenProvider($this->credentials(), $fake);

        $token = $provider->getAccessToken(self::NOW);

        $this->assertSame('tok-xyz', $token);
        $this->assertSame('https://api.example.com/auth/v2/protocol/openid-connect/token', $fake->lastTokenUri);
        $this->assertSame('client-123', $fake->lastForm['client_id']);
        $this->assertSame('org-abc', $fake->lastForm['organization_id']);

        // The assertion put on the wire must verify against the public key.
        $claims = $this->decodeWithClockAt($fake->lastForm['client_assertion'], self::NOW);
        $this->assertSame('client-123', $claims['iss']);
        $this->assertSame('https://iam.example.com/realms/org-abc', $claims['aud']);
    }

    public function testTokenIsCachedUntilNearExpiry(): void
    {
        $fake = new FakeTokenEndpointClient(['access_token' => 'tok-1', 'expires_in' => 3600]);
        $provider = new ServiceAccountTokenProvider($this->credentials(), $fake);

        $provider->getAccessToken(self::NOW);
        $provider->getAccessToken(self::NOW + 100);

        $this->assertSame(1, $fake->calls, 'a still-fresh token should be served from cache');
    }

    public function testTokenRefreshesNearExpiry(): void
    {
        $fake = new FakeTokenEndpointClient(['access_token' => 'tok-1', 'expires_in' => 3600]);
        $provider = new ServiceAccountTokenProvider($this->credentials(), $fake);

        $provider->getAccessToken(self::NOW);
        $provider->getAccessToken(self::NOW + 3600); // past the renew skew

        $this->assertSame(2, $fake->calls, 'an expiring token should be refreshed');
    }

    public function testFallsBackToAssertionTtlWhenExpiresInAbsent(): void
    {
        $fake = new FakeTokenEndpointClient(['access_token' => 'tok-1']); // no expires_in
        $provider = new ServiceAccountTokenProvider($this->credentials(), $fake);

        $provider->getAccessToken(self::NOW);
        $provider->getAccessToken(self::NOW + 100);

        $this->assertSame(1, $fake->calls, 'should treat missing expires_in as the 3600s default');
    }

    public function testMissingAccessTokenThrows(): void
    {
        $fake = new FakeTokenEndpointClient(['error' => 'invalid_client']);
        $provider = new ServiceAccountTokenProvider($this->credentials(), $fake);

        $this->expectException(AuthException::class);
        $provider->getAccessToken(self::NOW);
    }
}
