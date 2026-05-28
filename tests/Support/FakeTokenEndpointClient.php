<?php

declare(strict_types=1);

namespace Blerify\Auth\Tests\Support;

use Blerify\Auth\TokenEndpointClient;

/**
 * In-memory {@see TokenEndpointClient} that records what it was called with and
 * returns a canned response. Lets the provider be exercised without a network.
 */
final class FakeTokenEndpointClient implements TokenEndpointClient
{
    public int $calls = 0;
    public ?string $lastTokenUri = null;

    /** @var array<string,string>|null */
    public ?array $lastForm = null;

    /** @param array<string,mixed> $response */
    public function __construct(private readonly array $response)
    {
    }

    public function postForm(string $tokenUri, array $form): array
    {
        $this->calls++;
        $this->lastTokenUri = $tokenUri;
        $this->lastForm = $form;

        return $this->response;
    }
}
