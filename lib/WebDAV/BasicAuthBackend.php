<?php

namespace OCA\OIDCLogin\WebDAV;

use OCA\OIDCLogin\Service\LoginService;
use OCA\OIDCLogin\Service\TokenService;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Backend\AbstractBasic;

class BasicAuthBackend extends AbstractBasic implements IEventListener
{
    /** @var string */
    private $appName;

    /** @var IRequest */
    private $request;

    /** @var IUserSession */
    private $userSession;

    /** @var ISession */
    private $session;

    /** @var IConfig */
    private $config;

    /** @var LoggerInterface */
    private $logger;

    /** @var LoginService */
    private $loginService;

    /** @var TokenService */
    private $tokenService;

    /**
     * @param string $principalPrefix
     */
    public function __construct(
        string $appName,
        IRequest $request,
        IUserSession $userSession,
        ISession $session,
        IConfig $config,
        LoggerInterface $logger,
        LoginService $loginService,
        TokenService $tokenService,
        $principalPrefix = 'principals/users/'
    ) {
        $this->appName = $appName;
        $this->request = $request;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->config = $config;
        $this->logger = $logger;
        $this->loginService = $loginService;
        $this->tokenService = $tokenService;
        $this->principalPrefix = $principalPrefix;
        $this->context = ['app' => $appName];

        // setup realm
        $defaults = new \OCP\Defaults();
        $this->realm = $defaults->getName();
    }

    public function validateUserPass($username, $password)
    {
        \OC_Util::setupFS(); // login hooks may need early access to the filesystem

        if (!$this->userSession->isLoggedIn()) {
            try {
                $this->login($username, $password);
            } catch (\Exception $e) {
                $this->logger->debug("WebDAV basic token validation failed with: {$e->getMessage()}", $this->context);

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
        $plugin = $event->getServer()->getPlugin('auth');
        $webdav_enabled = $this->config->getSystemValue('oidc_login_webdav_enabled', false);
        $password_auth_enabled = $this->config->getSystemValue('oidc_login_password_authentication', false);

        if (null !== $plugin && $webdav_enabled && $password_auth_enabled) {
            $plugin->addBackend($this);
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
        $client = $this->tokenService->createOIDCClient();
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

        $this->loginService->login($profile, $this->userSession, $this->request);
    }
}
