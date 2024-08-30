<?php

namespace OCA\OIDCLogin\Controller;

use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OCA\OIDCLogin\Service\LoginService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;

class LoginController extends Controller
{
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
        LoginService $loginService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->loginService = $loginService;
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

    private function prepareLogout(OpenIDConnectClient $oidc): void
    {
        $this->session->set('oidc_sid', $oidc->getVerifiedClaims('sid'));
        
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

    private function login(array $profile): RedirectResponse
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        /** @var IUser $user */
        [$user, $password] = $this->loginService->login($profile);

        // Workaround to create user files folder. Remove it later.
        \OC::$server->get(IRootFolder::class)->getUserFolder($user->getUID());

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

    /**
     * @PublicPage
     *
     * @NoCSRFRequired
     *
     * @UseSession
     */
    public function frontChannelLogout($sid, $iss)
    {
        if (!isset($sid) || !isset($iss)) {
            return $this->getFrontChannelLogoutErrorResponse(
                "invalid request",
                "Missing 'sid' and 'iss' parameters"
            );
        }
        
        $issuer = $this->config->getSystemValue('oidc_login_provider_url');
        if ($iss !== $issuer) {
            return $this->getFrontChannelLogoutErrorResponse(
                "invalid iss",
                "Issuer not recognized"
            );
        }
        
        if (!$this->userSession->isLoggedIn()) {
            return $this->getFrontChannelLogoutErrorResponse(
                "user not logged",
                "The user is not logged in Nextcloud"
            );
        }

        if ($this->session->get('oidc_sid') !== $sid) {
            return $this->getFrontChannelLogoutErrorResponse(
                "invalid sid",
                "The sid of the logout token was not found."
            );
        }
        
        $this->userSession->logout();
        return new JSONResponse([], Http::STATUS_OK);
    }

    private function getFrontChannelLogoutErrorResponse($error, $description) {
        $response = new JSONResponse(
            [
                'error' => $error,
                'error_description' => $description,
            ],
            Http::STATUS_BAD_REQUEST,
        );
                
        return $response;
    }
}
