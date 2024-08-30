<?php

namespace OCA\OIDCLogin\WebDAV;

use OCA\DAV\Events\SabrePluginAuthInitEvent;
use OCA\OIDCLogin\Service\LoginService;
use OCP\Defaults;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IConfig;
use OCP\ISession;
use OCP\IUserSession;
use OCP\SabrePluginEvent;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Backend\AbstractBasic;
use Sabre\DAV\Auth\Plugin;

class BasicAuthBackend extends AbstractBasic implements IEventListener
{
    private string $appName;
    private IUserSession $userSession;
    private ISession $session;
    private IConfig $config;
    private LoggerInterface $logger;
    private LoginService $loginService;

    /**
     * @param string $principalPrefix
     */
    public function __construct(
        string $appName,
        IUserSession $userSession,
        ISession $session,
        IConfig $config,
        LoggerInterface $logger,
        LoginService $loginService,
        $principalPrefix = 'principals/users/'
    ) {
        $this->appName = $appName;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->config = $config;
        $this->logger = $logger;
        $this->loginService = $loginService;
        $this->principalPrefix = $principalPrefix;

        // setup realm
        $defaults = new Defaults();
        $this->realm = $defaults->getName();
    }

    public function validateUserPass($username, $password)
    {
        \OC_Util::setupFS(); // login hooks may need early access to the filesystem

        if (!$this->userSession->isLoggedIn()) {
            try {
                $this->login($username, $password);
            } catch (\Exception $e) {
                $this->logger->debug("WebDAV basic token validation failed with: {$e->getMessage()}", ['app' => $this->appName]);

                return false;
            }
        }

        if ($this->userSession->isLoggedIn()) {
            return $this->setupUserFs($this->userSession->getUser()->getUID());
        }

        return false;
    }

    /**
     * Implements IEventListener::handle.
     * Registers this class as an authentication backend with Sabre WebDav.
     */
    public function handle(Event $event): void
    {
        if (!$event instanceof SabrePluginAuthInitEvent
            && !$event instanceof SabrePluginEvent) {
            return;
        }

        $authPlugin = $event->getServer()->getPlugin('auth');
        if ($authPlugin instanceof Plugin) {
            $webdav_enabled = $this->config->getSystemValue('oidc_login_webdav_enabled', false);
            $password_auth_enabled = $this->config->getSystemValue('oidc_login_password_authentication', false);

            if ($webdav_enabled && $password_auth_enabled) {
                $authPlugin->addBackend($this);
            }
        }
    }

    private function setupUserFs($userId)
    {
        \OC_Util::setupFS($userId);

        /* On the v1 route /remote.php/webdav, a default nextcloud backend
         * tries and fails to authenticate users, then close the session.
         * This is why this check is needed.
         * https://github.com/nextcloud/server/issues/31091
         */
        if (PHP_SESSION_ACTIVE === session_status()) {
            $this->session->close();
        }

        return $this->principalPrefix.$userId;
    }

    private function login(string $username, string $password)
    {
        $client = $this->loginService->createOIDCClient();
        if (null === $client) {
            throw new \Exception("Couldn't create OIDC client!");
        }

        $client->addAuthParam([
            'username' => $username,
            'password' => $password,
        ]);

        $token = $client->requestResourceOwnerToken(true);

        if (null === $token) {
            throw new \Exception("Couldn't get a resource owner token");
        }

        if (isset($token->error)) {
            if (isset($token->error_description)) {
                throw new \Exception("Resource owner token error: {$token->error} {$token->error_description}");
            }

            throw new \Exception("Resource owner token error: {$token->error}");
        }

        $profile = $client->getTokenProfile($token->access_token);

        $this->loginService->login($profile);
    }
}
