<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Service;

use OCA\OIDCLogin\AppInfo\Application;
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
use OCP\IUser;
use OCP\IUserSession;
use OCP\Security\ICrypto;

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
        ILogger $logger,
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
     * @return bool Whether or not valid access token
     */
    public function refreshTokens(): bool
    {
        $user = $this->userSession->getUser();

        if (!$user instanceof IUser) {
            return false;
        }
        $userId = (string) $user->getUID();
        $accessTokenExpiresAt = $this->session->get('oidc_access_token_expires_at');
        $now = time();
        // If access token hasn't expired yet
        $this->logger->debug('checking if token should be refreshed', ['expires' => $accessTokenExpiresAt]);

        // Give 10 seconds buffer just in case
        if (!empty($accessTokenExpiresAt) && $now < $accessTokenExpiresAt - 10) {
            $this->logger->debug('no token expiration or not yet expired');

            return true;
        }

        // To check if refresh tokens are enabled or not
        $refreshTokensDisabledExplicitly = $this->config->getSystemValue('oidc_login_refresh_tokens_disabled', false);
        if ($refreshTokensDisabledExplicitly) {
            return false;
        }

        try {
            $encryptedrefreshToken = $this->refreshTokenMapper->getTokenByUser($user)->getToken();
            $refreshToken = $this->crypto->decrypt($encryptedrefreshToken);
        } catch (DoesNotExistException) {
            // If refresh token doesn't
            $this->logger->debug('refresh token not found');

            return false;
        }

        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        // Refresh the tokens, return false on failure
        $this->logger->debug('refreshing token');

        try {
            // retrieve the refreshed tokens from OIDC provider
            $oidc = $this->loginService->createOIDCClient($callbackUrl);
            $tokenResponse = $oidc->refreshToken($refreshToken);
            if (isset($tokenResponse->error)) {
                $this->logger->error('Error refreshing token for user '.$user->getUID(), ['exception' => $tokenResponse->error]);

                return false;
            }

            $refreshTokensEnabled = false;

            // Check if 'offline_access' scope is present
            $scopes = $oidc->getScopes();
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

            if (!$refreshTokensEnabled) {
                return false;
            }

            $this->session->set('oidc_refresh_tokens_enabled', 1);
            $this->updateTokens($user, $tokenResponse);
            $this->logger->debug('token refreshed');

            $this->prepareLogout($oidc);

            return true;
        } catch (\Exception $e) {
            $this->logger->error('token refresh failed', ['exception' => $e]);

            return false;
        }
    }

    public function updateTokens(IUser $user, object $tokenResponse): void
    {
        $oldAccessToken = $this->session->get('oidc_access_token');
        $this->logger->debug('old access token: '.$oldAccessToken);
        $this->logger->debug('new access token: '.$tokenResponse->access_token);

        $this->session->set('oidc_access_token', $tokenResponse->access_token);

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

    public function persistOIDCProviderUID(IUser $user, OpenIDConnectClient $oidc) {
        $userId = (string) $user->getUID();
        $savedOIDCUid = $this->config->getUserValue($userId, Application::APP_ID, Application::OIDC_PROVIDER_UID_KEY);
        if ($savedOIDCUid !== null && trim($savedOIDCUid) !== '') {
            return;
        }

        $oidcUid = $oidc->getUserId();
        if ($oidcUid === null || trim($oidcUid) === '') {
            return;
        }

        $this->config->setUserValue($userId, Application::APP_ID, Application::OIDC_PROVIDER_UID_KEY, $oidcUid);
    }
}
