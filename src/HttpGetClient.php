<?php

declare(strict_types=1);

namespace Blerify\Auth;

/**
 * Transport abstraction for authenticated JSON GET requests.
 *
 * Keeping the HTTP call behind an interface lets {@see ServiceAccountRolesClient}
 * be unit-tested without a network, and lets callers plug in their own HTTP
 * stack if needed (mirrors {@see TokenEndpointClient} for the token POST).
 */
interface HttpGetClient
{
    /**
     * GET a JSON resource and return the decoded response.
     *
     * Implementations MUST throw {@see \Blerify\Auth\Exception\AuthException} on
     * a transport error or a non-200 response.
     *
     * @param array<string,string> $headers header name => value
     *
     * @return array<int|string,mixed>
     */
    public function getJson(string $url, array $headers): array;
}
