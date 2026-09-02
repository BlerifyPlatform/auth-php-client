<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Ramsey\Uuid\Uuid;

/**
 * Reads the roles of the authenticated service account from the Blerify IAM
 * self-service endpoint:
 *
 *   GET /api/v1/iam/serviceAccounts/me/roles
 *
 * The caller's identity is derived server-side from the access token, so no
 * parameters are sent: a service account can only ever read its own roles.
 */
final class ServiceAccountRolesClient
{
    private const ROLES_PATH = '/api/v1/iam/serviceAccounts/me/roles';

    /**
     * @param string $baseUrl Blerify API base URL (e.g. https://api.demo.blerify.com)
     */
    public function __construct(
        private readonly string $baseUrl,
        private readonly ServiceAccountTokenProvider $tokens,
        private readonly HttpGetClient $http = new CurlHttpGetClient(),
    ) {
    }

    /**
     * Return the API roles granted to this service account.
     *
     * @param string|null $correlationId request-tracing id; a UUID is generated when omitted
     *
     * @return list<ServiceAccountRole>
     */
    public function getOwnRoles(?string $correlationId = null): array
    {
        $accessToken = $this->tokens->getAccessToken();
        $url = rtrim($this->baseUrl, '/') . self::ROLES_PATH;

        $response = $this->http->getJson($url, [
            'Authorization' => "Bearer {$accessToken}",
            'correlation-id' => $correlationId ?? Uuid::uuid4()->toString(),
        ]);

        $roles = [];
        foreach ($response as $item) {
            if (is_array($item)) {
                $roles[] = ServiceAccountRole::fromArray($item);
            }
        }

        return $roles;
    }
}
