<?php

declare(strict_types=1);

namespace Blerify\Auth;

use Blerify\Auth\Exception\AuthException;

/**
 * One API role granted to a service account.
 *
 * `projectId`/`projectName` are set for project-scoped roles (e.g.
 * `credentials.api`) and null for organization-level roles (e.g.
 * `notifications.api`). `projectName` can also be null when the project has
 * since been deleted.
 */
final class ServiceAccountRole
{
    public function __construct(
        public readonly string $name,
        public readonly ?string $projectId = null,
        public readonly ?string $projectName = null,
    ) {
    }

    /**
     * Build a role from one decoded item of the roles endpoint response.
     *
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['name']) || !is_string($data['name']) || $data['name'] === '') {
            throw new AuthException('Role item is missing the name field');
        }

        return new self(
            name: $data['name'],
            projectId: isset($data['projectId']) && is_string($data['projectId']) ? $data['projectId'] : null,
            projectName: isset($data['projectName']) && is_string($data['projectName']) ? $data['projectName'] : null,
        );
    }
}
