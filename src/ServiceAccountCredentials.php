<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Blerify\Auth\Exception\AuthException;

/**
 * Immutable view over a Blerify service-account credentials file.
 *
 * The credentials JSON is issued by the Blerify portal when a service account
 * is created. The fields used by this library:
 *
 *   - client_id        OAuth2 client identifier
 *   - organization_id  Blerify organization the service account belongs to
 *   - private_key      PEM private key used to sign the client assertion
 *   - token_uri        Blerify IAM token endpoint
 *                      (e.g. https://<host>/auth/v2/protocol/openid-connect/token)
 *   - iam_audience     audience the client assertion is addressed to
 *
 * Any other fields present in the file (client_email, private_key_id, type,
 * universe_domain, ...) are ignored.
 */
final class ServiceAccountCredentials
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $organizationId,
        public readonly string $privateKey,
        public readonly string $tokenUri,
        public readonly string $audience,
    ) {
    }

    /**
     * Load credentials from a service-account JSON file.
     */
    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new AuthException("Service-account credentials file not found: {$path}");
        }
        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new AuthException("Unable to read credentials file: {$path}");
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            throw new AuthException("Credentials file is not valid JSON: {$path}");
        }

        return self::fromArray($data);
    }

    /**
     * Build credentials from an already-decoded associative array.
     *
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        foreach (['client_id', 'organization_id', 'private_key', 'token_uri', 'iam_audience'] as $key) {
            if (!isset($data[$key]) || !is_string($data[$key]) || $data[$key] === '') {
                throw new AuthException("Missing or invalid credential field: {$key}");
            }
        }

        return new self(
            clientId: $data['client_id'],
            organizationId: $data['organization_id'],
            privateKey: $data['private_key'],
            tokenUri: $data['token_uri'],
            audience: $data['iam_audience'],
        );
    }
}
