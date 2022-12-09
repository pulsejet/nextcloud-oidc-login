<?php

namespace OCA\OIDCLogin\Service;

use Exception;
use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OCP\IConfig;
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

    public function __construct(
        $appName,
        ISession $session,
        IConfig $config,
        IURLGenerator $urlGenerator,
    ) {
        $this->appName = $appName;
        $this->session = $session;
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
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
        $accessTokenExpiresIn = $this->session->get('oidc_access_token_expires_in');
        $now = time();
        // If access token hasn't expired yet
        if (!empty($accessTokenExpiresIn) && $now < $accessTokenExpiresIn) {
            return true;
        }

        $refreshTokenExpiresIn = $this->session->get('oidc_refresh_token_expires_in');
        $refreshToken = $this->session->get('oidc_refresh_token');
        // If refresh token doesn't exist or refresh token has expired
        if (!$refreshToken || (!empty($refreshTokenExpiresIn) && $now > $refreshTokenExpiresIn)) {
            return false;
        }

        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        // Refresh the tokens, return false on failure
        try {
            $oidc = $this->createOIDCClient($callbackUrl);
            $tokenResponse = $oidc->refreshToken($refreshToken);
            $this->storeTokens($tokenResponse);

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public function storeTokens(object $tokenResponse): void
    {
        $this->session->set('oidc_access_token', $tokenResponse->access_token);
        $this->session->set('oidc_refresh_token', $tokenResponse->refresh_token);

        $now = time();
        $accessTokenExpiresIn = $tokenResponse->expires_in + $now;
        $refreshTokenExpiresIn = $now + $tokenResponse->refresh_expires_in - 5;

        $this->session->set('oidc_access_token_expires_in', $accessTokenExpiresIn);
        $this->session->set('oidc_refresh_token_expires_in', $refreshTokenExpiresIn);
    }
}
