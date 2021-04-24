<?php

declare(strict_types=1);

namespace OCA\OIDCLogin\AppInfo;

use OC\AppFramework\Utility\ControllerMethodReflector;
use OCP\AppFramework\App;
use OCP\IURLGenerator;
use OCP\IConfig;
use OCP\IUserSession;
use OCP\IRequest;
use OCP\ISession;
use OCP\IL10N;
use OCP\Util;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\OIDCLogin\OIDCLoginOption;

class Application extends App implements IBootstrap
{
    private $appName = 'oidc_login';

	/** @var IURLGenerator */
	protected $url;
	/** @var IL10N */
	protected $l;
	/** @var Config */
	protected $config;

    public function __construct()
    {
        parent::__construct($this->appName);
    }

    public function register(IRegistrationContext $context): void
    {
        $context->registerAlternativeLogin(OIDCLoginOption::class);

        // Try to get Files_External storage service
        $context->registerService('storagesService', function($container) {
            $storagesService = null;
            try {
                $storagesService = class_exists('\OCA\Files_External\Service\GlobalStoragesService') ?
                    $container->query(\OCA\Files_External\Service\GlobalStoragesService::class) : null;
            } catch (Exception $e) {}
            return $storagesService;
        });

        $context->registerEventListener(
            'OCA\DAV\Connector\Sabre::authInit',
            '\OCA\OIDCLogin\WebDAV\BearerAuthBackend'
        );
    }

    public function boot(IBootContext $context): void
    {
        $container = $context->getAppContainer();
        $this->l = $container->query(IL10N::class);
        $this->url = $container->query(IURLGenerator::class);
        $this->config = $container->query(IConfig::class);
        $request = $container->query(IRequest::class);

        // Check if automatic redirection is enabled
        $useLoginRedirect = $this->config->getSystemValue('oidc_login_auto_redirect', false);

        // Check if alternative login page is enabled
        $altLoginPage = $this->config->getSystemValue('oidc_login_alt_login_page', false);

        // URL for login without redirecting forcefully, false if we are not doing that
        $noRedirLoginUrl = $useLoginRedirect ? $this->url->linkToRouteAbsolute('core.login.showLoginForm') . '?noredir=1' : false;

        // Get logged in user's session
        $userSession = $container->query(IUserSession::class);
        $session = $container->query(ISession::class);

        // Check if the user is logged in
        if ($userSession->isLoggedIn()) {
            // Halt processing if not logged in with OIDC
            if (!$session->exists('is_oidc')) {
                return;
            }

            // Disable password confirmation for user
            $session->set('last-password-confirm', $container->query(ITimeFactory::class)->getTime());

            /* Redirect to logout URL on completing logout
               If do not have logout URL, go to noredir on logout */
            if ($logoutUrl = $this->config->getSystemValue('oidc_login_logout_url', $noRedirLoginUrl)) {
                $userSession->listen('\OC\User', 'postLogout', function () use ($logoutUrl) {
                    // Do nothing if this is a CORS request
                    if ($this->getContainer()->query(ControllerMethodReflector::class)->hasAnnotation('CORS')) {
                        return;
                    }

                    header('Location: ' . $logoutUrl);
                    exit();
                });
            }

            // Hide password change form
            if ($hidePasswordForm = $this->config->getSystemValue('oidc_login_hide_password_form', false)) {
                Util::addStyle($this->appName, 'oidc');
            }

            return;
        }

        // Redirect automatically or show alt login page
        if (array_key_exists('REQUEST_METHOD', $_SERVER) &&
            $_SERVER['REQUEST_METHOD'] === 'GET' &&
            $request->getPathInfo() === '/login' &&
            $request->getParam('noredir') == null &&
            $request->getParam('user') == null
        ) {
            // Set redirection URL
            $redir = $request->getParam('redirect_url');
            if ($redir != null && !empty($redir)) {
                $session->set('oidc_redir', $redir);
            } else {
                $session->set('oidc_redir', '/');
            }

            // Get URLs
            $loginLink = OIDCLoginOption::getLoginLink($request, $this->url);

            // Force redirect
            if ($useLoginRedirect) {
                header('Location: ' . $loginLink);
                exit();
            }

            // Alt login page
            if ($altLoginPage) {
                $OIDC_LOGIN_URL = $loginLink;
                header_remove('content-security-policy');
                require $altLoginPage;
                exit();
            }
        }
	}
}
