<?php

declare(strict_types=1);

namespace Blerify\Auth\Tests\Support;

use Blerify\Auth\HttpGetClient;

/**
 * In-memory {@see HttpGetClient} that records what it was called with and
 * returns a canned response. Lets the roles client be exercised without a
 * network.
 */
final class FakeHttpGetClient implements HttpGetClient
{
    public int $calls = 0;
    public ?string $lastUrl = null;

    /** @var array<string,string>|null */
    public ?array $lastHeaders = null;

    /** @param array<int|string,mixed> $response */
    public function __construct(private readonly array $response)
    {
    }

    public function getJson(string $url, array $headers): array
    {
        $this->calls++;
        $this->lastUrl = $url;
        $this->lastHeaders = $headers;

        return $this->response;
    }
}
