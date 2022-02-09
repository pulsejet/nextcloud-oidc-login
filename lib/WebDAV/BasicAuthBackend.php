<?php

namespace OCA\OIDCLogin\WebDAV;

use OC\Authentication\Token\DefaultTokenProvider;
use OCA\OIDCLogin\Service\LoginService;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;
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

    /** @var ILogger */
    private $logger;

    /** @var LoginService */
    private $loginService;

    /**
     * @param string $principalPrefix
     */
    public function __construct(
        string $appName,
        IRequest $request,
        IUserSession $userSession,
        ISession $session,
        IConfig $config,
        ILogger $logger,
        LoginService $loginService,
        $principalPrefix = 'principals/users/'
    ) {
        $this->appName = $appName;
        $this->request = $request;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->config = $config;
        $this->logger = $logger;
        $this->loginService = $loginService;
        $this->principalPrefix = $principalPrefix;
        $this->context = ['app' => $appName];

        // setup realm
        $defaults = new \OCP\Defaults();
        $this->realm = $defaults->getName();
    }

    /**
     * {@inheritdoc}
     */
    public function validateUserPass($username, $password)
    {
        \OC_Util::setupFS(); //login hooks may need early access to the filesystem

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
        $this->session->close();

        return $this->principalPrefix.$userId;
    }

    /**
     * {@inheritdoc}
     */
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

        $profile = $client->getTokenProfile($token->access_token);

        list($user, $userPassword) = $this->loginService->login($profile);

        $this->userSession->getSession()->regenerateId();
        $tokenProvider = \OC::$server->query(DefaultTokenProvider::class);
        $this->userSession->setTokenProvider($tokenProvider);
        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
        $token = $tokenProvider->getToken($this->userSession->getSession()->getId());

        $this->userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $userPassword,
            'token' => empty($userPassword) ? $token : null,
        ], false);
    }
}
