<?php

namespace OCA\OIDCLogin\WebDAV;

use OCA\OIDCLogin\Service\LoginService;

use OCP\ISession;
use OCP\IUserSession;
use OCP\ILogger;
use OCP\IConfig;

use OCP\EventDispatcher\IEventListener;
use OCP\EventDispatcher\Event;

use Sabre\DAV\Auth\Backend\AbstractBearer;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

class BearerAuthBackend extends AbstractBearer implements IEventListener {
    /** @var string */
    private $appName;
    /** @var IUserSession */
    private $userSession;
    /** @var ISession */
    private $session;
    /** @var IConfig */
    private $config;
    /** @var string */
    private $principalPrefix;
    /** @var ILogger */
    private $logger;
    /** @var LoginService */
    private $loginService;

    /**
     * @param IUserSession $userSession
     * @param ISession $session
     * @param string $principalPrefix
     */
    public function __construct(
        string $appName,
        IUserSession $userSession,
        ISession $session,
        IConfig $config,
        ILogger $logger,
        LoginService $loginService,
        $principalPrefix = 'principals/users/')
    {
        $this->appName = $appName;
        $this->userSession = $userSession;
        $this->session = $session;
        $this->config = $config;
        $this->logger = $logger;
        $this->loginService = $loginService;
        $this->principalPrefix = $principalPrefix;
        $this->context = ["app" => $appName];

        // setup realm
        $defaults = new \OCP\Defaults();
        $this->realm = $defaults->getName();
    }

    private function setupUserFs($userId) {
        \OC_Util::setupFS($userId);
        $this->session->close();
        return $this->principalPrefix . $userId;
    }

    /**
     * {@inheritdoc}
     */
    public function validateBearerToken($bearerToken) {
        \OC_Util::setupFS(); //login hooks may need early access to the filesystem

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
     * \Sabre\DAV\Auth\Backend\AbstractBearer::challenge sets an WWW-Authenticate
     * header which some DAV clients can't handle. Thus we override this function
     * and make it simply return a 401.
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     */
    public function challenge(RequestInterface $request, ResponseInterface $response) {
        $response->setStatus(401);
    }

    /**
     * Tries to log in a user based on the given $bearerToken.
     * @param string $bearerToken An OIDC JWT bearer token.
     */
    private function login(string $bearerToken) {
        $client = $this->loginService->createOIDCClient();
        if(is_null($client)) {
            throw new \Exception("Couldn't create OIDC client!");
        }
        
        $client->validateBearerToken($bearerToken);

        $profile = $client->getTokenPayload($bearerToken);

        list($user, $userPassword) = $this->loginService->login($profile);

        $this->userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $userPassword
        ]);
    }

    /**
     * Implements IEventListener::handle.
     * Registers this class as an authentication backend with Sabre WebDav.
     */
    public function handle(Event $event): void {
        $plugin = $event->getServer()->getPlugin('auth');
        $webdav_enabled = $this->config->getSystemValue('oidc_login_webdav_enabled', false);
        
        if($plugin != null && $webdav_enabled) {
            $plugin->addBackend($this);
        }
    }
}

