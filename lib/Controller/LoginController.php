<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Controller;

use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OCA\OIDCLogin\Service\LoginService;
use OCA\OIDCLogin\Service\TokenService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use OCP\IL10N;

class LoginController extends Controller
{

    /** @var IUserManager */
    private $userManager;

    /** @var IGroupManager */
    private $groupManager;

    /** @var TokenService */
    private $tokenService;

    /** @var IL10N */
    private $l;

   
    private IConfig $config;
    private IURLGenerator $urlGenerator;
    private IUserSession $userSession;
    private ISession $session;
    private LoginService $loginService;

    public function __construct(
        string $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserSession $userSession,
        ISession $session,
        IL10N $l,
        LoginService $loginService,
        TokenService $tokenService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->loginService = $loginService;
        $this->tokenService = $tokenService;
    }

    /**
     * @PublicPage
     *
     * @NoCSRFRequired
     *
     * @UseSession
     */
    public function oidc(): RedirectResponse
    {
        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        try {
            // Construct new client
            $oidc = $this->loginService->createOIDCClient($callbackUrl);

            // Authenticate
            $oidc->authenticate();
            $user = null;
            if ($this->config->getSystemValue('oidc_login_use_id_token', false)) {
                // Get user information from ID Token
                $user = $oidc->getIdTokenPayload();
            } else {
                // Get user information from OIDC
                $user = $oidc->requestUserInfo();
            }

            $this->tokenService->prepareLogout($oidc);

            // Convert to PHP array and process
            return $this->authSuccess(json_decode(json_encode($user), true), $oidc);

            // Get user info
            $profile = $oidc->getProfile();

            // Store logout URLs in session
            $this->prepareLogout($oidc);

            // Continue with login
            return $this->login($profile);
        } catch (\Exception $e) {
            // Go to noredir page if fallback enabled
            if ($this->config->getSystemValue('oidc_login_redir_fallback', false)) {
                $noRedirLoginUrl = $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm').'?noredir=1';
                header('Location: '.$noRedirLoginUrl);

                exit;
            }

            // Show error page
            \OC_Template::printErrorPage($e->getMessage());
        }
    }

    private function authSuccess($profile, $oidc)
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        return $this->login($profile, $oidc);
    }

    private function prepareLogout(OpenIDConnectClient $oidc): void
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

    private function login($profile, $oidc): RedirectResponse
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        /** @var \OCP\IUser $user */
        [$user, $password] = $this->loginService->login($profile);

        $refreshTokensEnabled = false;
        $refreshTokensDisabledExplicitly = $this->config->getSystemValue('oidc_refresh_tokens_disabled', false);

        $tokenResponse = $oidc->getTokenResponse();
        if (!$refreshTokensDisabledExplicitly) {
            $scopes = $oidc->getScopes();
            $refreshTokensEnabled = $this->shouldEnableRefreshTokens($scopes, $tokenResponse);
        }

        if ($refreshTokensEnabled) {
            $this->session->set('oidc_refresh_tokens_enabled', 1);
            $this->tokenService->updateTokens($user, $tokenResponse);
        }

        // Workaround to create user files folder. Remove it later.
        \OC::$server->get(\OCP\Files\IRootFolder::class)->getUserFolder($user->getUID());

        // Prevent being asked to change password
        $this->session->set('last-password-confirm', \OC::$server->get(ITimeFactory::class)->getTime());

        // Go to redirection URI
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            return new RedirectResponse($redirectUrl);
        }

        // Fallback redirection URI
        $redir = '/';
        if ($login_redir = $this->session->get('oidc_redir')) {
            $redir = $login_redir;
        }

        return new RedirectResponse($this->urlGenerator->getAbsoluteURL($redir));
    }

    private function shouldEnableRefreshTokens(array $scopes, object $tokenResponse): bool
    {
        foreach ($scopes as $scope) {
            if (str_contains($scope, 'offline_access')) {
                return true;
            }
        }

        if (isset($tokenResponse->refresh_token) && !empty($tokenResponse->refresh_token)) {
            return true;
        }

        return false;
    }
}
