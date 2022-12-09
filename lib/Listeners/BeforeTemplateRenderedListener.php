<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Listeners;

use OCA\OIDCLogin\Service\TokenService;
use OCP\AppFramework\Http\Events\BeforeTemplateRenderedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\ISession;
use OCP\IUserSession;

class BeforeTemplateRenderedListener implements IEventListener
{
    /** @var string */
    private $appName;

    /** @var IUserSession */
    private $userSession;

    /** @var TokenService */
    private $tokenService;

    /** @var ISession */
    private $session;

    public function __construct($appName, IUserSession $userSession, TokenService $tokenService, ISession $session)
    {
        $this->appName = $appName;
        $this->userSession = $userSession;
        $this->tokenService = $tokenService;
        $this->session = $session;
    }

    public function handle(Event $event): void
    {
        // If user not logged in or not an oidc session, nothing to do
        if (!($event instanceof BeforeTemplateRenderedEvent) || !$this->userSession->isLoggedIn() || !$this->session->exists('is_oidc')) {
            return;
        }

        if (!$this->tokenService->refreshTokens()) {
            $this->userSession->logout();
        }
    }
}
