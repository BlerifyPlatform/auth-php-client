<?php

/**
 * Runnable usage example for blerify/auth-php-client.
 *
 *   1. composer install
 *   2. Generate the service-account credentials JSON from the Blerify portal
 *      and save it as config/credentials.json
 *      (config/credentials.example.json shows the expected shape)
 *   3. php index.php
 *
 * The library's job is to turn a service-account credentials file into a
 * Bearer access token. This example obtains a token and shows how to attach it
 * to an authenticated request.
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Blerify\Auth\Exception\AuthException;
use Blerify\Auth\ServiceAccountTokenProvider;

// Initialize the token provider from the service-account credentials file.
$tokens = ServiceAccountTokenProvider::fromFile(__DIR__ . '/config/credentials.json');

// Step 1: Obtain an access token (signs a JWT assertion, exchanges it, caches it).
echo "\n1. Request access token: ";
try {
    $accessToken = $tokens->getAccessToken();
} catch (AuthException $e) {
    echo "Error\n" . $e->getMessage() . "\n";
    exit(1);
}
echo "Ok\n";
echo "   token (truncated): " . substr($accessToken, 0, 24) . "...\n";

// Subsequent calls reuse the cached token until it is close to expiry.
$accessToken = $tokens->getAccessToken();

// Step 2: Use it as a Bearer token on any Blerify API request (via the gateway).
echo "\n2. Call an authenticated endpoint:\n";
$apiBase = 'https://api.demo.blerify.com';

// Replace with the endpoint your integration consumes, then uncomment:
// $response = authenticatedGet($apiBase . '/api/v1/your/endpoint', $accessToken);
// handleResponse($response);

echo "   send this header on your requests:\n";
echo "   Authorization: Bearer " . substr($accessToken, 0, 24) . "...\n";
echo "\nOk\n";

/**
 * Minimal authenticated GET — shows how to attach the Bearer token.
 * In a real integration use your HTTP client of choice.
 *
 * @return array{status:int, body:string}
 */
function authenticatedGet(string $url, string $accessToken): array
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer {$accessToken}",
        'Accept: application/json',
    ]);
    $body = (string) curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

    return ['status' => $status, 'body' => $body];
}

/**
 * @param array{status:int, body:string} $response
 */
function handleResponse(array $response): void
{
    echo "   HTTP {$response['status']}\n";
    echo "   {$response['body']}\n";
}
