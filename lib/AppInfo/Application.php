<?php

namespace OCA\OIDCLogin\AppInfo;

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

        // URL for login without redirecting forcefully, false if we are not doing that
        $noRedirLoginUrl = $useLoginRedirect ? $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm') . '?noredir=1' : false;

        // Get logged in user's session
        $userSession = $this->query(IUserSession::class);

        // Check if the user is logged in
        if ($userSession->isLoggedIn()) {
            // Get the session of the user
            $uid = $userSession->getUser()->getUID();
            $session = $this->query(ISession::class);

            // Disable password confirmation for user
            if ($this->config->getUserValue($uid, $this->appName, 'disable_password_confirmation')) {
                $session->set('last-password-confirm', time());
            }

            /* Redirect to logout URL on completing logout
               If do not have logout URL, go to noredir on logout */
            if ($logoutUrl = $this->config->getSystemValue('oidc_login_logout_url', $noRedirLoginUrl)) {
                $userSession->listen('\OC\User', 'postLogout', function () use ($logoutUrl) {
                    header('Location: ' . $logoutUrl);
                    exit();
                });
            }
            return;
        }

        // Get URLs
        $request = $this->query(IRequest::class);
        $this->redirectUrl = $request->getParam('redirect_url');
        $this->providerUrl = $this->urlGenerator->linkToRoute($this->appName.'.login.oidc', [
            'login_redirect_url' => $this->redirectUrl
        ]);

        // Add login button
        $this->addAltLogin();

        // Redirect automatically
        if ($useLoginRedirect && $request->getPathInfo() === '/login' && $request->getParam('noredir') == null) {
            header('Location: ' . $this->providerUrl);
            exit();
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
