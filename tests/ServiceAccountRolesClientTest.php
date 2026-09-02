<?php

declare(strict_types=1);

namespace Blerify\Auth\Tests;

use Blerify\Auth\Exception\AuthException;
use Blerify\Auth\ServiceAccountCredentials;
use Blerify\Auth\ServiceAccountRole;
use Blerify\Auth\ServiceAccountRolesClient;
use Blerify\Auth\ServiceAccountTokenProvider;
use Blerify\Auth\Tests\Support\FakeHttpGetClient;
use Blerify\Auth\Tests\Support\FakeTokenEndpointClient;
use PHPUnit\Framework\TestCase;

final class ServiceAccountRolesClientTest extends TestCase
{
    private function tokenProvider(): ServiceAccountTokenProvider
    {
        $b64 = file_get_contents(__DIR__ . '/fixtures/test_private_key.pem.b64');
        self::assertNotFalse($b64, 'missing key fixture: test_private_key.pem.b64');

        $credentials = new ServiceAccountCredentials(
            clientId: 'client-123',
            organizationId: 'org-abc',
            privateKey: (string) base64_decode($b64, true),
            tokenUri: 'https://api.example.com/auth/v2/protocol/openid-connect/token',
            audience: 'https://iam.example.com/realms/org-abc',
        );

        return new ServiceAccountTokenProvider(
            $credentials,
            new FakeTokenEndpointClient(['access_token' => 'tok-xyz', 'expires_in' => 3600]),
        );
    }

    public function testFetchesOwnRolesWithBearerTokenAndNoParameters(): void
    {
        $http = new FakeHttpGetClient([
            ['name' => 'credentials.api', 'projectId' => 'd56624f1-1b32-4fbd-9156-9d108cf5a244', 'projectName' => 'My Project'],
            ['name' => 'notifications.api', 'projectId' => null, 'projectName' => null],
        ]);
        $client = new ServiceAccountRolesClient('https://api.example.com', $this->tokenProvider(), $http);

        $roles = $client->getOwnRoles('11111111-2222-3333-4444-555555555555');

        $this->assertSame('https://api.example.com/api/v1/iam/serviceAccounts/me/roles', $http->lastUrl);
        $this->assertSame('Bearer tok-xyz', $http->lastHeaders['Authorization']);
        $this->assertSame('11111111-2222-3333-4444-555555555555', $http->lastHeaders['correlation-id']);

        $this->assertCount(2, $roles);
        $this->assertSame('credentials.api', $roles[0]->name);
        $this->assertSame('d56624f1-1b32-4fbd-9156-9d108cf5a244', $roles[0]->projectId);
        $this->assertSame('My Project', $roles[0]->projectName);
        $this->assertSame('notifications.api', $roles[1]->name);
        $this->assertNull($roles[1]->projectId);
        $this->assertNull($roles[1]->projectName);
    }

    public function testGeneratesACorrelationIdWhenNotSupplied(): void
    {
        $http = new FakeHttpGetClient([]);
        $client = new ServiceAccountRolesClient('https://api.example.com', $this->tokenProvider(), $http);

        $client->getOwnRoles();

        $this->assertNotEmpty($http->lastHeaders['correlation-id']);
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
            $http->lastHeaders['correlation-id'],
        );
    }

    public function testTrimsTrailingSlashOnBaseUrl(): void
    {
        $http = new FakeHttpGetClient([]);
        $client = new ServiceAccountRolesClient('https://api.example.com/', $this->tokenProvider(), $http);

        $client->getOwnRoles();

        $this->assertSame('https://api.example.com/api/v1/iam/serviceAccounts/me/roles', $http->lastUrl);
    }

    public function testToleratesResponsesWithoutTheProjectNameField(): void
    {
        // Older backend versions return only name/projectId.
        $http = new FakeHttpGetClient([
            ['name' => 'credentials.api', 'projectId' => 'abc'],
        ]);
        $client = new ServiceAccountRolesClient('https://api.example.com', $this->tokenProvider(), $http);

        $roles = $client->getOwnRoles();

        $this->assertSame('abc', $roles[0]->projectId);
        $this->assertNull($roles[0]->projectName);
    }

    public function testRoleWithoutANameIsRejected(): void
    {
        $http = new FakeHttpGetClient([
            ['projectId' => 'abc'],
        ]);
        $client = new ServiceAccountRolesClient('https://api.example.com', $this->tokenProvider(), $http);

        $this->expectException(AuthException::class);
        $client->getOwnRoles();
    }

    public function testRoleFromArrayMapsAllFields(): void
    {
        $role = ServiceAccountRole::fromArray([
            'name' => 'verifications.api',
            'projectId' => 'p-1',
            'projectName' => 'Verifications',
        ]);

        $this->assertSame('verifications.api', $role->name);
        $this->assertSame('p-1', $role->projectId);
        $this->assertSame('Verifications', $role->projectName);
    }
}
