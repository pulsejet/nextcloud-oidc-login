<?php

namespace OCA\OIDCLogin\Service;

use Exception;
use OCP\ISession;
use OCP\IURLGenerator;

class TokenService
{
    public const USER_AGENT = 'NextcloudOIDCLogin';

    /** @var ISession */
    private $session;

    private $loginService;

    public function __construct(
        $appName,
        ISession $session,
        LoginService $loginService,
        IURLGenerator $urlGenerator,
    ) {
        $this->appName = $appName;
        $this->session = $session;
        $this->loginService = $loginService;
        $this->urlGenerator = $urlGenerator;
    }

    public function refreshTokens(): bool
    {
        $accessTokenExpiresIn = $this->session->get('oidc_access_token_expires_in');
        $now = time();
        if ($now < $accessTokenExpiresIn) {
            return true;
        }

        $refreshTokenExpiresIn = $this->session->get('oidc_refresh_token_expires_in');
        $refreshToken = $this->session->get('oidc_refresh_token');
        if (!$refreshToken || ($refreshTokenExpiresIn && $now > $refreshTokenExpiresIn)) {
            return false;
        }

        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        try {
            $oidc = $this->loginService->createOIDCClient($callbackUrl);
            $tokenResponse = $oidc->refreshToken($refreshToken);
        } catch (Exception $e) {
            return false;
        }

        $this->loginService->storeTokens($tokenResponse);

        return true;
    }
}
