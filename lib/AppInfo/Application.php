<?php

namespace OCA\OIDCLogin\AppInfo;

use OC\AppFramework\Utility\ControllerMethodReflector;
use OCP\AppFramework\App;
use OCP\IURLGenerator;
use OCP\IConfig;
use OCP\IUserSession;
use OCP\IRequest;
use OCP\ISession;
use OCP\IL10N;

class Application extends App
{
    private $appName = 'oidc_login';

    private $providerUrl;

    private $redirectUrl;
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;

    public function __construct()
    {
        parent::__construct($this->appName);
    }

    public function register()
    {
        $l = $this->query(IL10N::class);
        $this->urlGenerator = $this->query(IURLGenerator::class);

        $this->config = $this->query(IConfig::class);

        // Check if automatic redirection is enabled
        $useLoginRedirect = $this->config->getSystemValue('oidc_login_auto_redirect', false);

        // Check if alternative login page is enabled
        $altLoginPage = $this->config->getSystemValue('oidc_login_alt_login_page', false);

        // URL for login without redirecting forcefully, false if we are not doing that
        $noRedirLoginUrl = $useLoginRedirect ? $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm') . '?noredir=1' : false;

        // Get logged in user's session
        $userSession = $this->query(IUserSession::class);
        $session = $this->query(ISession::class);

        // Check if the user is logged in
        if ($userSession->isLoggedIn()) {
            // Get the session of the user
            $uid = $userSession->getUser()->getUID();

            // Disable password confirmation for user
            if ($this->config->getUserValue($uid, $this->appName, 'disable_password_confirmation')) {
                $session->set('last-password-confirm', time());
            }

            /* Redirect to logout URL on completing logout
               If do not have logout URL, go to noredir on logout */
            if ($logoutUrl = $this->config->getSystemValue('oidc_login_logout_url', $noRedirLoginUrl)) {
                $userSession->listen('\OC\User', 'postLogout', function () use ($logoutUrl) {
                    // Do nothing if this is a CORS request
                    if ($this->query(ControllerMethodReflector::class)->hasAnnotation('CORS')) {
                        return;
                    }

                    header('Location: ' . $logoutUrl);
                    exit();
                });
            }
            return;
        }

        // Get the container to pass special parameters
        $container = $this->getContainer();

        // Get Files_External storage service
        $storagesService = class_exists('\OCA\Files_External\Service\GlobalStoragesService') ?
            $this->query(\OCA\Files_External\Service\GlobalStoragesService::class) : null;
        $container->registerParameter('storagesService', $storagesService);

        // Get URLs
        $request = $this->query(IRequest::class);
        $this->redirectUrl = $request->getParam('redirect_url');
        $this->providerUrl = $this->urlGenerator->linkToRoute($this->appName.'.login.oidc', [
            'login_redirect_url' => $this->redirectUrl
        ]);

        // Add login button
        $this->addAltLogin();

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

            // Force redirect
            if ($useLoginRedirect) {
                header('Location: ' . $this->providerUrl);
                exit();
            }

            // Alt login page
            if ($altLoginPage) {
                $OIDC_LOGIN_URL = $this->providerUrl;
                header_remove('content-security-policy');
                include $altLoginPage;
                exit();
            }
        }
    }

    private function addAltLogin()
    {
        $l = $this->query(IL10N::class);
        \OC_App::registerLogIn([
            'name' => $l->t($this->config->getSystemValue('oidc_login_button_text', 'OpenID Connect')),
            'href' => $this->providerUrl
        ]);
    }

    private function query($className)
    {
        return $this->getContainer()->query($className);
    }
}
