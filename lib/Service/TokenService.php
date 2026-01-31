<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Service;

use OCA\OIDCLogin\Db\Entities\RefreshToken;
use OCA\OIDCLogin\Db\Mappers\RefreshTokenMapper;
use OCA\OIDCLogin\Events\AccessTokenUpdatedEvent;
use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OCP\AppFramework\Db\DoesNotExistException;
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

    private RefreshTokenMapper $refreshTokenMapper;

    private IUserSession $userSession;

    private LoginService $loginService;

    /** @var ICrypto */
    private $crypto;

    public function __construct(
        $appName,
        ISession $session,
        IConfig $config,
        IURLGenerator $urlGenerator,
        LoggerInterface $logger,
        IEventDispatcher $dispatcher,
        RefreshTokenMapper $refreshTokenMapper,
        IUserSession $userSession,
        LoginService $loginService,
        ICrypto $crypto

    ) {
        $this->appName = $appName;
        $this->session = $session;
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
        $this->refreshTokenMapper = $refreshTokenMapper;
        $this->loginService = $loginService;
        $this->userSession = $userSession;
        $this->crypto = $crypto;

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
            $oidc = $this->loginService->createOIDCClient($callbackUrl);

            // To check if refresh tokens are enabled or not
            $refreshTokensEnabled = false;
            $refreshTokensDisabledExplicitly = $this->config->getSystemValue('oidc_refresh_tokens_disabled', false);

            $tokenResponse = $oidc->getTokenResponse();
            if (!$refreshTokensDisabledExplicitly) {
                $scopes = $oidc->getScopes();

                // Check if 'offline_access' scope is present
                foreach ($scopes as $scope) {
                    if (str_contains($scope, 'offline_access')) {
                        $refreshTokensEnabled = true;

                        break;
                    }
                }

                // Check if the refresh token itself is present and not empty
                if (isset($tokenResponse->refresh_token) && !empty($tokenResponse->refresh_token)) {
                    $refreshTokensEnabled = true;
                }
            }

            if ($refreshTokensEnabled) {
                $this->session->set('oidc_refresh_tokens_enabled', 1);
                $this->updateTokens($user, $tokenResponse);
            } else {
                return false;
            }

            $tokenResponse = $oidc->refreshToken($refreshToken);
            $this->storeTokens($tokenResponse);
            $this->logger->debug('token refreshed');

            $this->prepareLogout($oidc);

            return true;
        } catch (\Exception $e) {
            $this->logger->error('token refresh failed', ['exception' => $e]);

            return false;
        }
    }

    public function storeTokens(object $tokenResponse): void
    {
        $oldAccessToken = $this->session->get('oidc_access_token');
       
        $this->session->set('oidc_access_token', $tokenResponse->access_token);
        $this->session->set('oidc_refresh_token', $tokenResponse->refresh_token);

        $this->refreshTokenMapper->deleteTokenForUser($user);
        $userId = (string) $user->getUID();
        $refreshToken = $tokenResponse->refresh_token;
        $refreshToken = $this->crypto->encrypt($refreshToken);
        $newRefreshToken = new RefreshToken();
        $newRefreshToken->setUserId($user->getUID());
        $newRefreshToken->setToken($refreshToken);
        $this->refreshTokenMapper->insert($newRefreshToken);

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
