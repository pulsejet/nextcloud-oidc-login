<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Events;

use OCP\EventDispatcher\Event;

/**
 * Class AccessTokenUpdatedEvent.
 */
class AccessTokenUpdatedEvent extends Event
{
    /** @var string */
    private $accessToken;

    /**
     * AccessTokenUpdatedEvent constructor.
     */
    public function __construct(
        string $accessToken
    ) {
        parent::__construct();
        $this->accessToken = $accessToken;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }
}
