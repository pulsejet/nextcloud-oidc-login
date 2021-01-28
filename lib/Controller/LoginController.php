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
use OCA\OIDCLogin\Provider\OpenIDConnectClient;

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
    /** @var \OCA\Files_External\Service\GlobalStoragesService */
    private $storagesService;


    public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserManager $userManager,
        IUserSession $userSession,
        IGroupManager $groupManager,
        ISession $session,
        IL10N $l,
        $storagesService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->l = $l;
        $this->storagesService = $storagesService;
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function oidc()
    {
        $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oidc');

        try {
            // Construct new client
            $oidc = new OpenIDConnectClient(
                $this->session,
                $this->config->getSystemValue('oidc_login_provider_url'),
                $this->config->getSystemValue('oidc_login_client_id'),
                $this->config->getSystemValue('oidc_login_client_secret'));
            $oidc->setRedirectURL($callbackUrl);

            // set TLS development mode
            $oidc->setVerifyHost($this->config->getSystemValue('oidc_login_tls_verify', true));
            $oidc->setVerifyPeer($this->config->getSystemValue('oidc_login_tls_verify', true));

            // Set OpenID Connect Scope
            $scope = $this->config->getSystemValue('oidc_login_scope', 'openid');
            $oidc->addScope($scope);

            // Authenticate
            $oidc->authenticate();

            // Get user information from OIDC
            $user = $oidc->requestUserInfo();

            // Convert to PHP array and process
            return $this->authSuccess(json_decode(json_encode($user), true));

        } catch (\Exception $e) {
            // Go to noredir page if fallback enabled
            if ($this->config->getSystemValue('oidc_login_redir_fallback', false)) {
                $noRedirLoginUrl = $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm') . '?noredir=1';
                header('Location: ' . $noRedirLoginUrl);
                exit();
            }

            // Show error page
            \OC_Template::printErrorPage($e->getMessage());
        }
    }

    private function authSuccess($profile)
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        return $this->login($profile);
    }

    private function login($profile)
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        // Get attributes
        $confattr = $this->config->getSystemValue('oidc_login_attributes', array());
        $defattr = array(
            'id' => 'sub',
            'name' => 'name',
            'mail' => 'email',
            'quota' => 'ownCloudQuota',
            'home' => 'homeDirectory',
            'ldap_uid' => 'uid',
            'groups' => 'ownCloudGroups',
        );
        $attr = array_merge($defattr, $confattr);

        // Flatten the profile array excluding attributes
        $profile = $this->flatten($profile, $attr);

        // Ensure the LDAP user exists if we are proxying for LDAP
        if ($this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            // Get LDAP uid
            $ldapUid = $profile[$attr['ldap_uid']];
            if (empty($ldapUid)) {
                throw new LoginException($this->l->t('No LDAP UID found in OpenID response'));
            }

            // Get the LDAP user backend
            $ldap = NULL;
            foreach ($this->userManager->getBackends() as $backend) {
                if ($backend->getBackendName() == $this->config->getSystemValue('oidc_login_ldap_backend', "LDAP")) {
                    $ldap = $backend;
                }
            }

            // Check if backend found
            if ($ldap == NULL) {
                throw new LoginException($this->l->t('No LDAP user backend found!'));
            }

            // Get LDAP Access object
            $access = $ldap->getLDAPAccess($ldapUid);

            // Get the DN
            $dns = $access->fetchUsersByLoginName($ldapUid);
            if (empty($dns)) {
                throw new LoginException($this->l->t('Error getting DN for LDAP user'));
            }
            $dn = $dns[0];

            // Store the user
            $ldapUser = $access->userManager->get($dn);
            if ($ldapUser == NULL) {
                throw new LoginException($this->l->t('Error getting user from LDAP'));
            }

            // Method no longer exists on NC 20+
            if (method_exists($ldapUser, 'update')) {
                $ldapUser->update();
            }
        }

        // Get UID
        $uid = $profile[$attr['id']];
        if (empty($uid)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }

        // Check max length of uid
        if (strlen($uid) > 64) {
            $uid = md5($uid);
        }

        // Get user with fallback
        $user = $this->userManager->get($uid);

        // Create user if not existing
        if (null === $user) {
            if ($this->config->getSystemValue('oidc_login_disable_registration', true)) {
                throw new LoginException($this->l->t('Auto creating new users is disabled'));
            }

            $password = substr(base64_encode(random_bytes(64)), 0, 30);
            $user = $this->userManager->createUser($uid, $password);

            $this->config->setUserValue($uid, $this->appName, 'disable_password_confirmation', 1);
        }

        // Get base data directory
        $datadir = $this->config->getSystemValue('datadirectory');

        // Set home directory unless proxying for LDAP
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false) &&
             array_key_exists($attr['home'], $profile)) {

            // Get intended home directory
            $home = $profile[$attr['home']];

            if($this->config->getSystemValue('oidc_login_use_external_storage', false)) {
                // Check if the files external app is enabled and injected
                if ($this->storagesService === null) {
                    throw new LoginException($this->l->t('files_external app must be enabled to use oidc_login_use_external_storage'));
                }

                // Check if the user already has matching storage on their root
                $storages = array_filter($this->storagesService->getStorages(), function ($storage) use ($uid) {
                    return in_array($uid, $storage->getApplicableUsers()) && // User must own the storage
                        $storage->getMountPoint() == "/" && // It must be mounted as root
                        $storage->getBackend()->getIdentifier() == 'local' && // It must be type local
                        count($storage->getApplicableUsers() == 1); // It can't be shared with other users
                });

                if(!empty($storages)) {
                    // User had storage on their / so make sure it's the correct folder
                    $storage = array_values($storages)[0];
                    $options = $storage->getBackendOptions();
                    
                    if($options['datadir'] != $home) {
                        $options['datadir'] = $home;
                        $storage->setBackendOptions($options);
                        $this->storagesService->updateStorage($storage);
                    }
                } else {
                    // User didnt have any matching storage on their root, so make one
                    $storage = $this->storagesService->createStorage('/', 'local', 'null::null', array(
                        'datadir' => $home
                    ), array(
                        'enable_sharing' => true
                    ));
                    $storage->setApplicableUsers([$uid]);
                    $this->storagesService->addStorage($storage);
                }
            } else {
                // Make home directory if does not exist
                mkdir($home, 0777, true);

                // Home directory (intended) of the user
                $nhome = "$datadir/$uid";

                // Check if correct link or home directory exists
                if (!file_exists($nhome) || is_link($nhome)) {
                    // Unlink if invalid link
                    if (is_link($nhome) && readlink($nhome) != $home) {
                        unlink($nhome);
                    }

                    // Create symlink to directory
                    if (!is_link($nhome) && !symlink($home, $nhome)) {
                        throw new LoginException("Failed to create symlink to home directory");
                    }
                }
            }
        }

        // Update user profile
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            if ($attr['name'] !== null) {
                $user->setDisplayName($profile[$attr['name']] ?: $profile[$attr['id']]);
            }

            if ($attr['mail'] !== null) {
                $user->setEMailAddress((string)$profile[$attr['mail']]);
            }

            // Set optional params
            if (array_key_exists($attr['quota'], $profile)) {
                $user->setQuota((string) $profile[$attr['quota']]);
            } else {
                if ($defaultQuota = $this->config->getSystemValue('oidc_login_default_quota')) {
                    $user->setQuota((string) $defaultQuota);
                };
            }

            // Add/remove user to/from groups
            if (array_key_exists($attr['groups'], $profile)) {
                // Get group names from profile
                $groupNames = $profile[$attr['groups']];

                // Explode by space if string
                if (is_string($groupNames)) {
                    $groupNames = explode(' ', $groupNames);
                }

                // Make sure group names is an array
                if (!is_array($groupNames)) {
                    throw new LoginException($attr['groups'] . ' must be an array');
                }

                // Remove user from groups not present
                $currentUserGroups = $this->groupManager->getUserGroups($user);
                foreach ($currentUserGroups as $currentUserGroup) {
                    if (!in_array($currentUserGroup->getDisplayName(), $groupNames)) {
                        $currentUserGroup->removeUser($user);
                    }
                }

                // Add user to group
                foreach ($groupNames as $group) {
                    if ($systemgroup = $this->groupManager->get($group)) {
                        $systemgroup->addUser($user);
                    }
                }
            }

            // Manage administrator role
            if ($adminAttribute = $this->config->getSystemValue('oidc_login_admin_attribute')) {
                $systemgroup = $this->groupManager->get('admin');
                if (array_key_exists($adminAttribute, $profile) && $profile[$adminAttribute]) {
                    $systemgroup->addUser($user);
                } else {
                    $systemgroup->removeUser($user);
                }
            }

            // Add default group if present
            if ($defaultGroup = $this->config->getSystemValue('oidc_login_default_group')) {
                if ($systemgroup = $this->groupManager->get($defaultGroup)) {
                    $systemgroup->addUser($user);
                }
            }
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

        // Get redirection url
        $redir = '/';
        if ($login_redir = $this->session->get('oidc_redir')) {
            $redir = $login_redir;
        }

        return new RedirectResponse($this->urlGenerator->getAbsoluteURL($redir));
    }

    private function flatten($array, $exclude, $prefix = '') {
        $result = array();
        foreach($array as $key => $value) {
            if (is_array($value) && !in_array($key, $exclude)) {
                $result = $result + $this->flatten($value, $exclude, $prefix . $key . '_');
            } else {
                $result[$prefix . $key] = $value;
            }
        }
        return $result;
    }
}
