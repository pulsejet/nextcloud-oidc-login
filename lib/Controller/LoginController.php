<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\Controller;

use OCA\OIDCLogin\Service\LoginService;
use OCA\OIDCLogin\Service\TokenService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;

class LoginController extends Controller
{
    /** @var IConfig */
    private $config;

    /** @var IURLGenerator */
    private $urlGenerator;

    /** @var IUserManager */
    private $userManager;

    /** @var IUserSession */
    private $userSession;

    /** @var IGroupManager */
    private $groupManager;

    /** @var ISession */
    private $session;

    /** @var LoginService */
    private $loginService;

    /** @var TokenService */
    private $tokenService;

    /** @var IL10N */
    private $l;

    /** @var \OCA\Files_External\Service\GlobalStoragesService */
    private $storagesService;

    public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserManager $userManager,
        IUserSession $userSession,
        IGroupManager $groupManager,
        ISession $session,
        IL10N $l,
        LoginService $loginService,
        TokenService $tokenService,
        $storagesService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->l = $l;
        $this->loginService = $loginService;
        $this->tokenService = $tokenService;
        $this->storagesService = $storagesService;
    }

    /**
     * @PublicPage
     *
     * @NoCSRFRequired
     *
     * @UseSession
     */
    public function oidc()
    {
        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        try {
            // Construct new client
            $oidc = $this->tokenService->createOIDCClient($callbackUrl);

            // Authenticate
            $oidc->authenticate();

            $tokenResponse = $oidc->getTokenResponse();

            $refreshTokensEnabled = false;
            $refreshTokensDisabledExplicitly = $this->config->getSystemValue('oidc_refresh_tokens_disabled', false);

            if (!$refreshTokensDisabledExplicitly) {
                $scopes = $oidc->getScopes();
                $refreshTokensEnabled = $this->shouldEnableRefreshTokens($scopes, $tokenResponse);
            }

            if ($refreshTokensEnabled) {
                $this->session->set('oidc_refresh_tokens_enabled', 1);
                $this->tokenService->storeTokens($tokenResponse);
            }

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
            return $this->authSuccess(json_decode(json_encode($user), true));
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

    private function authSuccess($profile)
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        return $this->login($profile);
    }

    private function login($profile)
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        list($user, $userPassword) = $this->loginService->login($profile, $this->userSession, $this->request);

        // Workaround to create user files folder. Remove it later.
        \OC::$server->query(\OCP\Files\IRootFolder::class)->getUserFolder($user->getUID());

        // Prevent being asked to change password
        $this->session->set('last-password-confirm', \OC::$server->query(ITimeFactory::class)->getTime());

        // Go to redirection URI
        if ($redirectUrl = $this->session->get('login_redirect_url')) {
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
