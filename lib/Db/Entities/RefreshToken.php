<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Db\Entities;

use OCP\AppFramework\Db\Entity;

/**
 * @method string getUserId()
 * @method void   setUserId(string $userId)
 * @method string getToken()
 * @method void   setToken(string $token)
 */
class RefreshToken extends Entity
{
    /** @var string */
    public $token;

    /** @var string */
    public $userId;
}
