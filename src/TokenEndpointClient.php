<?php

declare(strict_types=1);

namespace Blerify\Auth;

/**
 * Transport abstraction for the token-endpoint POST.
 *
 * Keeping the HTTP call behind an interface lets the assertion-signing and
 * caching logic in {@see ServiceAccountTokenProvider} be unit-tested without a
 * network, and lets callers plug in their own HTTP stack if needed.
 */
interface TokenEndpointClient
{
    /**
     * POST an `application/x-www-form-urlencoded` body to the token endpoint and
     * return the decoded JSON response.
     *
     * Implementations MUST throw {@see \Blerify\Auth\Exception\AuthException} on
     * a transport error or a non-200 response.
     *
     * @param array<string,string> $form
     *
     * @return array<string,mixed>
     */
    public function postForm(string $tokenUri, array $form): array;
}
