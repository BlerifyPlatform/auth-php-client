<?php

declare(strict_types=1);

namespace Blerify\Auth\Exception;

use RuntimeException;

/**
 * Raised for any failure while obtaining a Blerify service-account access token:
 * malformed credentials, transport errors, or a non-success response from the
 * token endpoint.
 */
class AuthException extends RuntimeException
{
}
