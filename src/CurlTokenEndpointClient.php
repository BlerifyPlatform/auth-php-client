<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Blerify\Auth\Exception\AuthException;

/**
 * Default {@see TokenEndpointClient} backed by cURL.
 */
final class CurlTokenEndpointClient implements TokenEndpointClient
{
    public function __construct(private readonly int $timeoutSeconds = 10)
    {
    }

    public function postForm(string $tokenUri, array $form): array
    {
        $ch = curl_init($tokenUri);
        if ($ch === false) {
            throw new AuthException('Failed to initialize cURL');
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeoutSeconds);

        $body = curl_exec($ch);
        if ($body === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new AuthException("Token request transport error: {$error}");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status !== 200) {
            throw new AuthException("Token endpoint returned HTTP {$status}: {$body}");
        }

        $decoded = json_decode((string) $body, true);
        if (!is_array($decoded)) {
            throw new AuthException('Token endpoint returned a non-JSON body');
        }

        return $decoded;
    }
}
