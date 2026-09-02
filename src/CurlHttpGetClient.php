<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Blerify\Auth\Exception\AuthException;

/**
 * Default {@see HttpGetClient} backed by cURL.
 */
final class CurlHttpGetClient implements HttpGetClient
{
    public function __construct(private readonly int $timeoutSeconds = 10)
    {
    }

    public function getJson(string $url, array $headers): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new AuthException('Failed to initialize cURL');
        }

        $headerLines = ['Accept: application/json'];
        foreach ($headers as $name => $value) {
            $headerLines[] = "{$name}: {$value}";
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headerLines);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeoutSeconds);

        $body = curl_exec($ch);
        if ($body === false) {
            $error = curl_error($ch);
            throw new AuthException("Request transport error: {$error}");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($status !== 200) {
            throw new AuthException("Endpoint returned HTTP {$status}: {$body}");
        }

        $decoded = json_decode((string) $body, true);
        if (!is_array($decoded)) {
            throw new AuthException('Endpoint returned a non-JSON body');
        }

        return $decoded;
    }
}
