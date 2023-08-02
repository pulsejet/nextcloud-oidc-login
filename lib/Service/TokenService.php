<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Service;

use Exception;
use OCA\OIDCLogin\Events\AccessTokenUpdatedEvent;
use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\ILogger;
use OCP\ISession;
use OCP\IURLGenerator;

class TokenService
{
    /** @var string */
    private $appName;

    /** @var ISession */
    private $session;

    /** @var IConfig */
    private $config;

    /** @var IURLGenerator */
    private $urlGenerator;

    private ILogger $logger;

    private IEventDispatcher $dispatcher;

    public function __construct(
        $appName,
        ISession $session,
        IConfig $config,
        IURLGenerator $urlGenerator,
        ILogger $logger,
        IEventDispatcher $dispatcher
    ) {
        $this->appName = $appName;
        $this->session = $session;
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
    }

    /**
     * @param string $callbackUrl
     *
     * @return OpenIDConnectClient Configured instance of OpendIDConnectClient
     */
    public function createOIDCClient($callbackUrl = '')
    {
        $oidc = new OpenIDConnectClient(
            $this->session,
            $this->config,
            $this->appName,
        );
        $oidc->setRedirectURL($callbackUrl);

        // set TLS development mode
        $oidc->setVerifyHost($this->config->getSystemValue('oidc_login_tls_verify', true));
        $oidc->setVerifyPeer($this->config->getSystemValue('oidc_login_tls_verify', true));

        // Set OpenID Connect Scope
        $scope = $this->config->getSystemValue('oidc_login_scope', 'openid');
        $oidc->addScope($scope);

        return $oidc;
    }

    /**
     * @return bool Whether or not valid access token
     */
    public function refreshTokens(): bool
    {
        $accessTokenExpiresAt = $this->session->get('oidc_access_token_expires_at');
        $now = time();
        // If access token hasn't expired yet
        $this->logger->debug('checking if token should be refreshed', ['expires' => $accessTokenExpiresAt]);

        if (!empty($accessTokenExpiresAt) && $now < $accessTokenExpiresAt) {
            $this->logger->debug('no token expiration or not yet expired');

            return true;
        }

        $refreshToken = $this->session->get('oidc_refresh_token');
        // If refresh token doesn't exist or refresh token has expired
        if (empty($refreshToken)) {
            $this->logger->debug('refresh token not found');

            return false;
        }

        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        // Refresh the tokens, return false on failure
        $this->logger->debug('refreshing token');

        try {
            $oidc = $this->createOIDCClient($callbackUrl);
            $tokenResponse = $oidc->refreshToken($refreshToken);
            $this->storeTokens($tokenResponse);
            $this->logger->debug('token refreshed');

            $this->prepareLogout($oidc);

            return true;
        } catch (Exception $e) {
            $this->logger->error('token refresh failed', ['exception' => $e]);

            return false;
        }
    }

    public function storeTokens(object $tokenResponse): void
    {
        $oldAccessToken = $this->session->get('oidc_access_token');
        $this->logger->debug('old access token: '.$oldAccessToken);
        $this->logger->debug('new access token: '.$tokenResponse->access_token);

        $this->session->set('oidc_access_token', $tokenResponse->access_token);
        $this->session->set('oidc_refresh_token', $tokenResponse->refresh_token);

        $now = time();
        $accessTokenExpiresAt = $tokenResponse->expires_in + $now;

        $this->session->set('oidc_access_token_expires_at', $accessTokenExpiresAt);
        $this->dispatcher->dispatchTyped(new AccessTokenUpdatedEvent($tokenResponse->access_token));
    }

    public function prepareLogout(OpenIDConnectClient $oidc)
    {
        if ($oidc_login_logout_url = $this->config->getSystemValue('oidc_login_logout_url', false)) {
            if ($this->config->getSystemValue('oidc_login_end_session_redirect', false)) {
                $signout_url = $oidc->getEndSessionUrl($oidc_login_logout_url);
                $this->session->set('oidc_logout_url', $signout_url);
            } else {
                $this->session->set('oidc_logout_url', $oidc_login_logout_url);
            }
        } else {
            $this->session->set('oidc_logout_url', false);
        }
    }
}
