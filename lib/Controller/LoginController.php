<?php

namespace OCA\OIDCLogin\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IConfig;
use OCP\IUserSession;
use OCP\IUserManager;
use OCP\IURLGenerator;
use OCP\IGroupManager;
use OCP\ISession;
use OC\User\LoginException;
use Jumbojett\OpenIDConnectClient;

class LoginController extends Controller
{
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
    /** @var IUserManager */
    private $userManager;
    /** @var IUserSession */
    private $userSession;
    /** @var IGroupManager */
    private $groupManager;
    /** @var ISession */
    private $session;
    /** @var IL10N */
    private $l;


    public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserManager $userManager,
        IUserSession $userSession,
        IGroupManager $groupManager,
        ISession $session,
        IL10N $l
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->l = $l;
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function oidc()
    {
        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        $config = [
            'default_group' => ''
        ];

        try {
            $oidc = new OpenIDConnectClient(
                $this->config->getSystemValue('oidc_login_provider_url'),
                $this->config->getSystemValue('oidc_login_client_id'),
                $this->config->getSystemValue('oidc_login_client_secret'));
            $oidc->setRedirectURL($callbackUrl);
            $oidc->authenticate();
            $user = $oidc->requestUserInfo();
        } catch (\Exception $e) {
            throw new LoginException($e->getMessage());
        }

        return $this->authSuccess(json_decode(json_encode($user), true), $config);
    }

    private function authSuccess($profile, array $config)
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }
        
        $profile['default_group'] = $config['default_group'];

        return $this->login($profile);
    }

    private function login($profile)
    {
        // Get attributes
        $confattr = $this->config->getSystemValue('oidc_login_attributes', array());
        $defattr = array(
            'id' => 'sub',
            'name' => 'name',
            'uid' => 'sub',
            'mail' => 'mail',
        );
        $attr = array_merge($defattr, $confattr);

        $uid = preg_replace('#.*/#', '', rtrim($profile[$attr['id']], '/'));
        if (empty($uid)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }

        // Check max length of uid
        if (strlen($uid) > 64) {
            $uid = md5($profileId);
        }

        // Get user with fallback
        $user = $this->userManager->get($uid);
        if (null === $user && $profile->email) {
            $user = $this->userManager->getByEmail($profile->email)[0];
        }        

        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        // Create user if not existing
        if (null === $user) {
            if ($this->config->getAppValue($this->appName, 'disable_registration')) {
                throw new LoginException($this->l->t('Auto creating new users is disabled'));
            }
            
            $password = substr(base64_encode(random_bytes(64)), 0, 30);
            $user = $this->userManager->createUser($uid, $password);

            $this->config->setUserValue($uid, $this->appName, 'disable_password_confirmation', 1);
        }

        // Update user profile 
        $user->setDisplayName($profile[$attr['name']] ?: $profile[$attr['id']]);
        $user->setEMailAddress((string)$profile[$attr['mail']]);

        $defaultGroup = $profile['default_group'];
        if ($defaultGroup && $group = $this->groupManager->get($defaultGroup)) {
            $group->addUser($user);
        }

        // Complete login
        $this->userSession->completeLogin($user, ['loginName' => $user->getUID(), 'password' => '']);
        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());

        // Go to redirection URI
        if ($redirectUrl = $this->session->get('login_redirect_url')) {
            return new RedirectResponse($redirectUrl);
        }

        // Prevent being asked to change password
        $this->session->set('last-password-confirm', time());

        return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
    }
}
