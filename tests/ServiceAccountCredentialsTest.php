<?php

declare(strict_types=1);

namespace Blerify\Auth\Tests;

use Blerify\Auth\Exception\AuthException;
use Blerify\Auth\ServiceAccountCredentials;
use PHPUnit\Framework\TestCase;

final class ServiceAccountCredentialsTest extends TestCase
{
    /** @return array<string,string> */
    private function validData(): array
    {
        return [
            'client_id' => 'cid',
            'organization_id' => 'org',
            'private_key' => '-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----',
            'token_uri' => 'https://api.example.com/auth/v2/protocol/openid-connect/token',
            'iam_audience' => 'https://iam.example.com/realms/org',
        ];
    }

    public function testFromArrayMapsFieldsAndIgnoresExtras(): void
    {
        $creds = ServiceAccountCredentials::fromArray($this->validData() + [
            'client_email' => 'sa@example.com',
            'type' => 'service_account',
            'universe_domain' => 'blerify.com',
        ]);

        $this->assertSame('cid', $creds->clientId);
        $this->assertSame('org', $creds->organizationId);
        $this->assertSame('https://api.example.com/auth/v2/protocol/openid-connect/token', $creds->tokenUri);
        $this->assertSame('https://iam.example.com/realms/org', $creds->audience);
    }

    public function testFromArrayRejectsMissingField(): void
    {
        $data = $this->validData();
        unset($data['organization_id']);

        $this->expectException(AuthException::class);
        ServiceAccountCredentials::fromArray($data);
    }

    public function testFromArrayRejectsEmptyField(): void
    {
        $data = $this->validData();
        $data['token_uri'] = '';

        $this->expectException(AuthException::class);
        ServiceAccountCredentials::fromArray($data);
    }

    public function testFromFileMissingThrows(): void
    {
        $this->expectException(AuthException::class);
        ServiceAccountCredentials::fromFile('/nonexistent/path/creds.json');
    }

    public function testFromFileInvalidJsonThrows(): void
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'sa');
        file_put_contents($path, 'not-json');
        try {
            $this->expectException(AuthException::class);
            ServiceAccountCredentials::fromFile($path);
        } finally {
            @unlink($path);
        }
    }

    public function testFromFileRoundTrip(): void
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'sa');
        file_put_contents($path, (string) json_encode($this->validData()));
        try {
            $creds = ServiceAccountCredentials::fromFile($path);
            $this->assertSame('cid', $creds->clientId);
            $this->assertSame('org', $creds->organizationId);
        } finally {
            @unlink($path);
        }
    }
}
