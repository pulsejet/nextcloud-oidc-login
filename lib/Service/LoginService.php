<?php

namespace OCA\OIDCLogin\Service;

use OC\Authentication\Token\IProvider;
use OCA\OIDCLogin\Provider\OpenIDConnectClient;
use OC\User\LoginException;
use OCP\IAvatarManager;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

class LoginService
{
    public const USER_AGENT = 'NextcloudOIDCLogin';

    private IAvatarManager $avatarManager;
    private IConfig $config;
    private IRequest $request;
    private IUserManager $userManager;
    private IGroupManager $groupManager;
    private IL10N $l;
    private IProvider $tokenProvider;
    private LoggerInterface $logger;
    private AttributeMap $attr;

    public function __construct(
        IConfig $config,
        IRequest $request,
        IUserManager $userManager,
        IAvatarManager $avatarManager,
        IGroupManager $groupManager,
        IL10N $l,
        IProvider $tokenProvider,
        LoggerInterface $logger,
        AttributeMap $attr
    ) {
        $this->config = $config;
        $this->request = $request;
        $this->userManager = $userManager;
        $this->avatarManager = $avatarManager;
        $this->groupManager = $groupManager;
        $this->l = $l;
        $this->tokenProvider = $tokenProvider;
        $this->logger = $logger;
        $this->attr = $attr;

        // get external storage service if available
        $this->storagesService = class_exists('\OCA\Files_External\Service\GlobalStoragesService') ?
            \OC::$server->get(\OCA\Files_External\Service\GlobalStoragesService::class) : null;
    }

    public function createOIDCClient(string $callbackUrl = ''): OpenIDConnectClient
    {
        $oidc = \OC::$server->get(OpenIDConnectClient::class);
        $oidc->setRedirectURL($callbackUrl);

        // set TLS development mode
        $oidc->setVerifyHost($this->config->getSystemValue('oidc_login_tls_verify', true));
        $oidc->setVerifyPeer($this->config->getSystemValue('oidc_login_tls_verify', true));

        // Set OpenID Connect Scope
        $scope = $this->config->getSystemValue('oidc_login_scope', 'openid');
        $oidc->addScope($scope);

        return $oidc;
    }

    /**
     * Log in the user using the provided profile.
     *
     * @return array [\OCP\IUser user, string password]
     */
    public function login(array $profile): array
    {
        // Flatten the profile array
        $profile = $this->flatten($profile);

        // Get UID
        $uid = $this->attr->id($profile);

        // Ensure the LDAP user exists if we are proxying for LDAP
        if ($this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            $ldapUid = $this->attr->ldapUid($profile);
            $uid = $this->getLDAPUserUid($ldapUid) ?: $uid;
        }

        // Check UID
        if (empty($uid)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }

        // Check max length of uid
        if (\strlen($uid) > 64) {
            $uid = md5($uid);
        }

        // DEPRECATED: This code can be removed once the 'oidc_login_allowed_groups' feature is removed
        // Check if user is in allowed groups
        if ($allowedGroups = $this->config->getSystemValue('oidc_login_allowed_groups', null)) {
            $groupNames = $this->getGroupNames($profile);
            if (empty(array_intersect($allowedGroups, $groupNames))) {
                throw new LoginException($this->l->t('Access to this service is not allowed because you are not member of the allowed groups. If you think this is an error, contact your administrator.'));
            }
        }

        // Check if user has an allowed login filter value
        if ($allowedLoginFilterValues = $this->config->getSystemValue('oidc_login_filter_allowed_values', null)) {
            $loginFilterValues = $this->getLoginFilterValues($profile);
            if (empty(array_intersect($allowedLoginFilterValues, $loginFilterValues))) {
                throw new LoginException($this->l->t('Access to this service is not allowed because you do not have one of the allowed login filter values. If you think this is an error, contact your administrator.'));
            }
        }

        // Get user with fallback
        $user = $this->userManager->get($uid);

        // Password can be empty unless first login.
        // On first login, we cannot use a token to authenticate the user
        // as this does not trigger creation of the user's skeleton files
        $password = '';

        // Create user if not existing
        if (null === $user) {
            // Generate random password of 30 characters
            $password = substr(base64_encode(random_bytes(64)), 0, 30);

            // Create user. This will throw if creation is not permitted.
            $user = $this->createUser($uid, $password);
        }

        // Set home directory unless proxying for LDAP
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false) && ($home = $this->attr->home($profile))) {
            $this->createHomeDirectory($home, $uid);
        }

        // Update user profile
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            // Update basic profile attributes
            $this->updateBasicProfile($user, $profile);

            // Get group names
            $groupNames = $this->getGroupNames($profile);

            // Update groups
            $this->updateUserGroups($user, $groupNames, $profile);
        }

        $this->completeLogin($user, $password);

        return [$user, $password];
    }

    /**
     * Log in the user to the session using the provided credentials.
     *
     * @param $user     User object (should be non-null)
     * @param $password (empty unless first login)
     */
    public function completeLogin(IUser $user, string $password): void
    {
        /** @var Session */
        $userSession = \OC::$server->get(IUserSession::class);
//
        /* On the v1 route /remote.php/webdav, a default nextcloud backend
         * tries and fails to authenticate users, then close the session.
         * This is why this check is needed.
         * https://github.com/nextcloud/server/issues/31091
         */
        if (PHP_SESSION_ACTIVE === session_status()) {
            $userSession->getSession()->regenerateId();
        }

        $userSession->setTokenProvider($this->tokenProvider);
        $userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
        $token = $this->tokenProvider->getToken($userSession->getSession()->getId());

        // Log the user in. This will throw if login fails.
        $userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $password,
            'token' => empty($password) ? $token : null,
        ], false);

        // Last login timestamp isn't updated when logging in with a token
        // This will return true for first login.
        // If the user was newly created then completeLogin will already trigger
        // prepareUserLogin. Fortunately, the subsequent updateLastLoginTimestamp call
        // we make here will return false then.
        if ($user->updateLastLoginTimestamp()) { // true if first login
            // warning: calling protected method
            $method = (new \ReflectionClass($userSession))->getMethod('prepareUserLogin');
            $method->setAccessible(true);
            $method->invoke($userSession, true, false);
        }
    }

    /**
     * If the LDAP backend interface is enabled, make user the
     * user actually exists in LDAP and return the uid.
     *
     * @return null|string LDAP user uid or null if not found
     *
     * @throws LoginException if LDAP backend is not enabled or user is not found
     *
     * @return null|string LDAP user uid or null if not found
     */
    private function getLDAPUserUid(?string $ldapUid): ?string
    {
        // Make sure we have the LDAP UID
        if (empty($ldapUid)) {
            throw new LoginException($this->l->t('No LDAP UID found in OpenID response'));
        }

        // Get the LDAP user backend
        $ldap = null;
        foreach ($this->userManager->getBackends() as $backend) {
            /** @var \OCP\IUserBackend $backend */
            if ($backend->getBackendName() === $this->config->getSystemValue('oidc_login_ldap_backend', 'LDAP')) {
                $ldap = $backend;
            }
        }

        // Check if backend found
        if (null === $ldap) {
            throw new LoginException($this->l->t('No LDAP user backend found!'));
        }

        /** @var \OCA\User_LDAP\IUserLDAP $ldap */

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
        if (null === $ldapUser) {
            throw new LoginException($this->l->t('Error getting user from LDAP'));
        }

        // Update the email address (#84)
        if (method_exists($ldapUser, 'updateEmail')) {
            $ldapUser->updateEmail();
        }

        // Force a UID for existing users with a different
        // user ID in nextcloud than in LDAP
        return $ldap->dn2UserName($dn);
    }

    /**
     * Create a user if we are allowed to do that.
     *
     * @return IUser Created user object
     *
     * @throws LoginException If oidc_login_disable_registration is true
     *
     * @return false|\OCP\IUser User object if created
     */
    private function createUser(string $uid, string $password): IUser
    {
        if ($this->config->getSystemValue('oidc_login_disable_registration', true)) {
            throw new LoginException($this->l->t('Auto creating new users is disabled'));
        }

        $user = $this->userManager->createUser($uid, $password);
        if (false === $user) {
            throw new LoginException($this->l->t('Error creating user'));
        }

        return $user;
    }

    /**
     * Create the user's home directory at the given path.
     *
     * @param string $home Path to the home directory
     * @param string $uid  User ID
     *
     * @throws LoginException If home directory could not be created
     */
    private function createHomeDirectory(string $home, string $uid): void
    {
        if ($this->config->getSystemValue('oidc_login_use_external_storage', false)) {
            // Check if the files external app is enabled and injected
            if (null === $this->storagesService) {
                throw new LoginException($this->l->t('files_external app must be enabled to use oidc_login_use_external_storage'));
            }

            // Check if the user already has matching storage on their root
            $storages = array_filter($this->storagesService->getStorages(), static function ($storage) use ($uid) {
                return \in_array($uid, $storage->getApplicableUsers(), true) // User must own the storage
                    && '/' === $storage->getMountPoint() // It must be mounted as root
                    && 'local' === $storage->getBackend()->getIdentifier() // It must be type local
                    && 1 === \count($storage->getApplicableUsers()); // It can't be shared with other users
            });

            if (!empty($storages)) {
                // User had storage on their / so make sure it's the correct folder
                $storage = array_values($storages)[0];
                $options = $storage->getBackendOptions();

                if ($options['datadir'] !== $home) {
                    $options['datadir'] = $home;
                    $storage->setBackendOptions($options);
                    $this->storagesService->updateStorage($storage);
                }
            } else {
                // User didnt have any matching storage on their root, so make one
                $storage = $this->storagesService->createStorage('/', 'local', 'null::null', [
                    'datadir' => $home,
                ], [
                    'enable_sharing' => true,
                ]);
                $storage->setApplicableUsers([$uid]);
                $this->storagesService->addStorage($storage);
            }
        } else {
            // Make home directory if does not exist
            mkdir($home, 0777, true);

            // Get base data directory
            $datadir = $this->config->getSystemValue('datadirectory');

            // Home directory (intended) of the user
            $nhome = "{$datadir}/{$uid}";

            // Check if correct link or home directory exists
            if (!file_exists($nhome) || is_link($nhome)) {
                // Unlink if invalid link
                if (is_link($nhome) && readlink($nhome) !== $home) {
                    unlink($nhome);
                }

                // Create symlink to directory
                if (!is_link($nhome) && !symlink($home, $nhome)) {
                    throw new LoginException('Failed to create symlink to home directory');
                }
            }
        }
    }

    /**
     * Update basic profile attributes such as name and email.
     */
    private function updateBasicProfile(IUser $user, array $profile): void
    {
        if (null !== ($name = $this->attr->name($profile))) {
            $user->setDisplayName($name ?: $this->attr->id($profile));
        }

        if (null !== ($mail = $this->attr->mail($profile))) {
            if ($user->getSystemEMailAddress() !== $mail) {
                $user->setSystemEMailAddress((string) $mail);
            }
        }

        // Set quota
        if (null !== ($quota = $this->attr->quota($profile))) {
            $user->setQuota((string) $quota);
        } else {
            if ($defaultQuota = $this->config->getSystemValue('oidc_login_default_quota')) {
                $user->setQuota((string) $defaultQuota);
            }
        }

        if ($this->config->getSystemValue('oidc_login_update_avatar', false)
            && ($photoURL = $this->attr->photoURL($profile))) {
            try {
                $curl = curl_init($photoURL);
                curl_setopt($curl, CURLOPT_HEADER, false);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($curl, CURLOPT_USERAGENT, self::USER_AGENT);
                $raw = curl_exec($curl);
                curl_close($curl);

                $image = new \OC_Image();
                $image->loadFromData($raw);

                $avatar = $this->avatarManager->getAvatar($user->getUid());
                if ($avatar) {
                    $last_modified = $avatar->getFile(64)->getMTime();
                    $formatted_date = date('D, d M Y H:i:s \G\M\T', $last_modified);
                    curl_setopt($curl, CURLOPT_HTTPHEADER, ["If-Modified-Since: {$formatted_date}"]);
                }
                $raw = curl_exec($curl);

                if (200 === curl_getinfo($curl, CURLINFO_HTTP_CODE)) {
                    $image = new \OC_Image();
                    $image->loadFromData($raw);
                    $image->centerCrop();

                    $avatar->set($image);
                }
                curl_close($curl);
            } catch (\Exception $e) {
                $this->logger->debug("Could not load image for {$user->getUid()} :  {$e->getMessage()}");
            }
        }
    }

    /**
     * Get list of login filter values of user from OIDC response.
     *
     * @return string[] List of login filter values
     */
    private function getLoginFilterValues(array $profile): array
    {
        $loginFilterValues = [];
        // Add user's login filter values from profile
        if ($this->attr->hasLoginFilter($profile)) {
            // Get login filter values
            $profileLoginFilterValues = $this->attr->login_filter($profile);

            // Make sure login filter allowed values names is an array
            if (!\is_array($profileLoginFilterValues)) {
                throw new LoginException('Login filter values field must be an array, '.\gettype($profileLoginFilterValues).' given');
            }

            // Add to all login filter values
            $loginFilterValues = array_merge($loginFilterValues, $profileLoginFilterValues);
        }

        // Remove duplicate login filter values
        return array_unique($loginFilterValues);
    }

    /**
     * Get list of groups of user from OIDC response.
     *
     * @return string[] List of groups
     */
    private function getGroupNames(array $profile)
    {
        // Groups to add user in
        $groupNames = [];

        // Add administrator group from attribute
        if ($this->attr->managesAdmin()) {
            if ($this->attr->isAdmin($profile)) {
                $groupNames[] = 'admin';
            }
        }

        // Add default group if present
        if ($defaultGroup = $this->config->getSystemValue('oidc_login_default_group')) {
            $groupNames[] = $defaultGroup;
        }

        // Add user's groups from profile
        if ($this->attr->hasGroups($profile)) {
            // Get group names
            $profileGroups = $this->attr->groups($profile);

            // Make sure group names is an array
            if (!\is_array($profileGroups)) {
                throw new LoginException('Groups field must be an array, '.\gettype($profileGroups).' given');
            }

            // Add to all groups
            $groupNames = array_merge($groupNames, $profileGroups);
        }

        // Remove duplicate groups
        return array_unique($groupNames);
    }

    /**
     * Update groups of a user to a given list of groups.
     *
     * @param string[] $groupNames
     */
    private function updateUserGroups(IUser $user, array $groupNames, array $profile): void
    {
        // Remove user from groups not present
        $currentUserGroups = $this->groupManager->getUserGroups($user);
        foreach ($currentUserGroups as $currentUserGroup) {
            if (($key = array_search($currentUserGroup->getGID(), $groupNames, true)) !== false) {
                // User is already in group - don't process further
                unset($groupNames[$key]);
            } else {
                // User is not supposed to be in this group
                // Remove the user ONLY if we're using profile groups
                // or the group is the `admin` group and we manage admin role
                if ($this->attr->hasGroups($profile)
                    || ($this->attr->managesAdmin() && 'admin' === $currentUserGroup->getGID())) {
                    $currentUserGroup->removeUser($user);
                }
            }
        }

        // Add user to group
        foreach ($groupNames as $group) {
            // Get existing group
            $systemgroup = $this->groupManager->get($group);

            // Create group if does not exist
            if (!$systemgroup && $this->config->getSystemValue('oidc_create_groups', false)) {
                $systemgroup = $this->groupManager->createGroup($group);
            }

            // Add user to group
            if ($systemgroup) {
                $systemgroup->addUser($user);
            }
        }
    }

    /**
     * Flatten an array.
     */
    private function flatten(array $array, string $prefix = ''): array
    {
        $result = [];
        foreach ($array as $key => $value) {
            $result[$prefix.$key] = $value;
            if (\is_array($value)) {
                $result += $this->flatten($value, $prefix.$key.'_');
            }
            if (\is_int($key) && \is_string($value)) {
                $result[$prefix.$value] = $value;
            }
        }

        return $result;
    }
}
