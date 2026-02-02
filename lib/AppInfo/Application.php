<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\AppInfo;

use OC\AppFramework\Utility\ControllerMethodReflector;
use OCA\OIDCLogin\OIDCLoginOption;
use OCA\OIDCLogin\Service\LoginService;
use OCA\OIDCLogin\Service\TokenService;
use OCA\OIDCLogin\WebDAV\BasicAuthBackend;
use OCA\OIDCLogin\WebDAV\BearerAuthBackend;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use OCP\Util;

class Application extends App implements IBootstrap
{
    public const APP_ID = 'oidc_login';
    public const OIDC_PROVIDER_UID_KEY = 'oidc_uid';

    protected IURLGenerator $url;
    protected IL10N $l;
    protected IConfig $config;

    private const TOKEN_LOGIN_KEY = 'is_oidc_token_login';

    /** @var TokenService */
    private $tokenService;

    /** @var LoginService */
    private $loginService;

    public function __construct()
    {
        parent::__construct(self::APP_ID);
    }

    public function register(IRegistrationContext $context): void
    {
        $context->registerEventListener(
            'OCA\DAV\Connector\Sabre::authInit',
            BearerAuthBackend::class
        );

        $context->registerEventListener(
            'OCA\DAV\Connector\Sabre::addPlugin',
            BearerAuthBackend::class
        );

        $context->registerEventListener(
            'OCA\DAV\Connector\Sabre::authInit',
            BasicAuthBackend::class
        );

        $context->registerEventListener(
            'OCA\DAV\Connector\Sabre::addPlugin',
            BasicAuthBackend::class
        );
    }

    public function boot(IBootContext $context): void
    {
        $container = $context->getAppContainer();
        $this->l = $container->query(IL10N::class);
        $this->url = $container->query(IURLGenerator::class);
        $this->config = $container->query(IConfig::class);
        $this->tokenService = $container->query(TokenService::class);
        $this->loginService = $container->query(LoginService::class);
        $request = $container->query(IRequest::class);

        // Check if automatic redirection is enabled
        $useLoginRedirect = $this->config->getSystemValue('oidc_login_auto_redirect', false);

        // Check if alternative login page is enabled
        $altLoginPage = $this->config->getSystemValue('oidc_login_alt_login_page', false);

        // URL for login without redirecting forcefully, false if we are not doing that
        $noRedirLoginUrl = $useLoginRedirect ? $this->url->linkToRouteAbsolute('core.login.showLoginForm').'?noredir=1' : false;

        // Get logged in user's session
        $userSession = $container->get(IUserSession::class);
        $session = $container->get(ISession::class);
        $logger = $container->get(ILogger::class);
        // If it is an OCS request, try to authenticate with bearer token if not logged in
        $isBearerAuth = str_starts_with($request->getHeader('Authorization'), 'Bearer ');
        if (!$userSession->isLoggedIn()
            && ('true' === $request->getHeader('OCS-APIREQUEST'))
            && $isBearerAuth) {
            $bearerAuthBackend = $container->get(BearerAuthBackend::class);
            $this->loginWithBearerToken($request, $bearerAuthBackend, $session, $logger);
        }

        // For non-OCS routes, perform validation even if logged in via session
        if ($isBearerAuth && 'true' === $request->getHeader('OIDC-LOGIN-WITH-TOKEN')) {
            // Invalidate existing session's oidc login
            $session->remove(self::TOKEN_LOGIN_KEY);
            $bearerAuthBackend = $container->get(BearerAuthBackend::class);
            $this->loginWithBearerToken($request, $bearerAuthBackend, $session, $logger);
        }

        // Check if the user is logged in
        if ($userSession->isLoggedIn()) {
            // when the cookie is set but session is not, it means
            // new session didn't initialize oidc parameters
            // so we do logout, which will re-trigger login (by button or auto-redirect)
            if (!$session->exists('is_oidc') && isset($_COOKIE[LoginService::OIDC_USER_COOKIE_NAME])) {
                $this->loginService->unsetOidcRememberMeCookie();
                $userSession->logout();

                return;
            }

            // Halt processing if not logged in with OIDC
            if (!$session->exists('is_oidc')) {
                return;
            }

            // Disable password confirmation for user
            $session->set('last-password-confirm', $container->get(ITimeFactory::class)->getTime());

            $refreshTokensEnabled = $session->exists('oidc_refresh_tokens_enabled');
            /* Redirect to logout URL on completing logout
               If do not have logout URL, go to noredir on logout */
            if ($logoutUrl = $session->get('oidc_logout_url', $noRedirLoginUrl)) {
                $userSession->listen('\OC\User', 'logout', function () use (&$logoutUrl, $refreshTokensEnabled, $session) {
                    if ($refreshTokensEnabled) {
                        // Refresh tokens before logout
                        $this->tokenService->refreshTokens();
                        $logoutUrl = $session->get('oidc_logout_url');
                    }
                });

                $userSession->listen('\OC\User', 'postLogout', function () use ($logoutUrl, $session) {
                    // Do nothing if this is a CORS request
                    if ($this->getContainer()->get(ControllerMethodReflector::class)->hasAnnotation('CORS')) {
                        return;
                    }

                    // Properly close the session and clear the browsers storage data before
                    // redirecting to the logout url.
                    $this->loginService->unsetOidcRememberMeCookie();

                    $session->set('clearingExecutionContexts', '1');
                    $session->close();
                    if (!$this->isApiRequest()) {
                        header('Clear-Site-Data: "cache", "storage"');
                        header('Location: '.$logoutUrl);

                        exit;
                    }
                });
            }

            if ($refreshTokensEnabled && !$this->tokenService->refreshTokens()) {
                $userSession->logout();
            }

            // Hide password change form
            if ($this->config->getSystemValue('oidc_login_hide_password_form', false)) {
                Util::addStyle(self::APP_ID, 'oidc.hidepasswordform');
            }

            return;
        }

        // Redirect automatically or show alt login page
        if (\array_key_exists('REQUEST_METHOD', $_SERVER)
            && 'GET' === $_SERVER['REQUEST_METHOD']
            && '/login' === $request->getPathInfo()
            && null === $request->getParam('noredir')
            && null === $request->getParam('user')
        ) {
            // Set redirection URL
            $redir = $request->getParam('redirect_url');
            if (null !== $redir && !empty($redir)) {
                $session->set('oidc_redir', $redir);
            } else {
                $session->set('oidc_redir', '/');
            }

            // Get URLs
            $loginLink = OIDCLoginOption::getLoginLink($request, $this->url);

            // Force redirect
            if ($useLoginRedirect) {
                header('Location: '.$loginLink);

                exit;
            }

            // Alt login page
            if ($altLoginPage) {
                $OIDC_LOGIN_URL = $loginLink; // available in alt login page
                header_remove('content-security-policy');

                require $altLoginPage;

                exit;
            }
        }
    }

    public function isApiRequest()
    {
        // Check if the request includes an 'Accept' header with value 'application/json'
        return isset($_SERVER['HTTP_ACCEPT']) && false !== strpos($_SERVER['HTTP_ACCEPT'], 'application/json');
    }

    private function loginWithBearerToken(IRequest $request, BearerAuthBackend $bearerAuthBackend, ISession $session, ILogger $logger)
    {
        $authHeader = $request->getHeader('Authorization');
        $bearerToken = substr($authHeader, 7);
        if (empty($bearerToken)) {
            return;
        }

        try {
            $bearerAuthBackend->login($bearerToken);
            $session->set(self::TOKEN_LOGIN_KEY, 1);
        } catch (\Exception $e) {
            $logger->debug("OIDC Bearer token validation failed with: {$e->getMessage()}", ['app' => self::APP_ID]);
        }
    }
}
