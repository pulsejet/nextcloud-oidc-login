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
use Sabre\DAV\Auth\Backend\AbstractBearer;

class BearerAuthBackend extends AbstractBearer implements IEventListener
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

    /** @var string */
    private $principalPrefix;

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

    /**
     * {@inheritdoc}
     */
    public function validateBearerToken($bearerToken)
    {
        \OC_Util::setupFS(); // login hooks may need early access to the filesystem

        if (!$this->userSession->isLoggedIn()) {
            try {
                $this->login($bearerToken);
            } catch (\Exception $e) {
                $this->logger->debug("WebDAV bearer token validation failed with: {$e->getMessage()}", $this->context);

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

        if (null !== $plugin && $webdav_enabled) {
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
     * Tries to log in a user based on the given $bearerToken.
     *
     * @param string $bearerToken an OIDC JWT bearer token
     */
    private function login(string $bearerToken)
    {
        $client = $this->tokenService->createOIDCClient();
        if (null === $client) {
            throw new \Exception("Couldn't create OIDC client!");
        }

        $client->validateBearerToken($bearerToken);

        $profile = $client->getTokenProfile($bearerToken);

        $this->loginService->login($profile, $this->userSession, $this->request);
    }
}
