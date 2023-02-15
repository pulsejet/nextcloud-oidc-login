<?php

namespace OCA\OIDCLogin\Service;

use OCP\IConfig;

class AttributeMap
{
    /** @var string Unique identifier for username */
    private $_id;

    /** @var string Full display name of user */
    private $_name;

    /** @var string Email address (no overwrite if null) */
    private $_mail;

    /** @var string Usage quota for user */
    private $_quota;

    /** @var string Absolute path to home directory */
    private $_home;

    /** @var string LDAP uid to search for when running in proxy mode */
    private $_ldapUid;

    /** @var string Array or space separated string of NC groups for the user */
    private $_groups;

    /** @var string Array or space separated string of roles for the user */
    private $_roles;

    /** @var string The URL of the user avatar. */
    private $_photoUrl;

    /** @var null|string If this value is truthy, the user is added to the admin group (optional) */
    private $_isAdmin;

    public function __construct(IConfig $config)
    {
        $confattr = $config->getSystemValue('oidc_login_attributes', []);
        $defattr = [
            'id' => 'sub',
            'name' => 'name',
            'mail' => 'email',
            'quota' => 'ownCloudQuota',
            'home' => 'homeDirectory',
            'ldap_uid' => 'uid',
            'groups' => 'ownCloudGroups',
            'roles' => 'roles',
            'photoURL' => 'picture',
        ];
        $attr = array_merge($defattr, $confattr);

        $this->_id = $attr['id'];
        $this->_name = $attr['name'];
        $this->_mail = $attr['mail'];
        $this->_quota = $attr['quota'];
        $this->_home = $attr['home'];
        $this->_ldapUid = $attr['ldap_uid'];
        $this->_groups = $attr['groups'];
        $this->_roles = $attr['roles'];
        $this->_photoUrl = $attr['photoURL'];

        // Optional attributes
        if (\array_key_exists('is_admin', $attr)) {
            $this->_isAdmin = $attr['is_admin'];
        }
    }

    /**
     * Get ID from profile.
     *
     * @param mixed $profile
     *
     * @return string
     */
    public function id(&$profile)
    {
        return self::get($this->_id, $profile);
    }

    /**
     * Get display name from profile.
     *
     * @param mixed $profile
     *
     * @return string
     */
    public function name(&$profile)
    {
        return self::get($this->_name, $profile);
    }

    /**
     * Get email address from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function mail(&$profile)
    {
        return self::get($this->_mail, $profile);
    }

    /**
     * Get quota from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function quota(&$profile)
    {
        return self::get($this->_quota, $profile);
    }

    /**
     * Get home directory from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function home(&$profile)
    {
        return self::get($this->_home, $profile);
    }

    /**
     * Get LDAP uid from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function ldapUid(&$profile)
    {
        return self::get($this->_ldapUid, $profile);
    }

    /**
     * Get groups from profile.
     *
     * @param mixed $profile
     *
     * @return null|array
     */
    public function groups(&$profile)
    {
        $groups = self::get($this->_groups, $profile);

        // Explode by space if string
        if (\is_string($groups)) {
            $groups = array_filter(explode(' ', $groups));
        }

        return $groups;
    }

    /**
     * Get roles from profile.
     *
     * @param mixed $profile
     *
     * @return null|array
     */
    public function roles(&$profile)
    {
        $roles = self::get($this->_roles, $profile);

        // Explode by space if string
        if (\is_string($roles)) {
            $roles = array_filter(explode(' ', $roles));
        }

        return $roles;
    }

    /**
     * Get photo URL from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function photoUrl(&$profile)
    {
        return self::get($this->_photoUrl, $profile);
    }

    /**
     * Get admin status from profile.
     *
     * @param mixed $profile
     *
     * @return null|string
     */
    public function isAdmin(&$profile)
    {
        return self::get($this->_isAdmin, $profile);
    }

    /**
     * Returns whether the OIDC response has the groups field in it.
     *
     * @param array $profile
     */
    public function hasGroups(&$profile)
    {
        return \array_key_exists($this->_groups, $profile);
    }

    /**
     * Returns whether the OIDC response has the roles field in it.
     *
     * @param array $profile
     */
    public function hasRoles(&$profile)
    {
        return \array_key_exists($this->_roles, $profile);
    }

    /**
     * Returns whether OIDC should manage the admin role with `is_admin` attribute.
     */
    public function managesAdmin()
    {
        return null !== $this->_isAdmin;
    }

    private static function get($attr, &$profile)
    {
        if (null !== $attr && \array_key_exists($attr, $profile)) {
            return $profile[$attr];
        }

        return null;
    }
}
