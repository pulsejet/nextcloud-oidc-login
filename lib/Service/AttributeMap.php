<?php

namespace OCA\OIDCLogin\Service;

use OCP\IConfig;

class AttributeMap
{
    /** Unique identifier for username */
    private string $_id;

    /** Full display name of user */
    private string $_name;

    /** Email address (no overwrite if null) */
    private string $_mail;

    /** Usage quota for user */
    private string $_quota;

    /** Absolute path to home directory */
    private string $_home;

    /** LDAP uid to search for when running in proxy mode */
    private string $_ldapUid;

    /** Array or space separated string of NC groups for the user */
    private string $_groups;

    /** Array or space separated string of login filter values for the user */
    private string $_login_filter;

    /** The URL of the user avatar. */
    private string $_photoUrl;

    /** If this value is truthy, the user is added to the admin group (optional) */
    private ?string $_isAdmin = null;

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
            'login_filter' => 'roles',
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
        $this->_login_filter = $attr['login_filter'];
        $this->_photoUrl = $attr['photoURL'];

        // Optional attributes
        if (\array_key_exists('is_admin', $attr)) {
            $this->_isAdmin = $attr['is_admin'];
        }
    }

    /**
     * Get ID from profile.
     */
    public function id(array $profile): ?string
    {
        return self::get($this->_id, $profile);
    }

    /**
     * Get display name from profile.
     */
    public function name(array $profile): ?string
    {
        return self::get($this->_name, $profile);
    }

    /**
     * Get email address from profile.
     */
    public function mail(array $profile): ?string
    {
        return self::get($this->_mail, $profile);
    }

    /**
     * Get quota from profile.
     */
    public function quota(array $profile): ?string
    {
        return self::get($this->_quota, $profile);
    }

    /**
     * Get home directory from profile.
     */
    public function home(array $profile): ?string
    {
        return self::get($this->_home, $profile);
    }

    /**
     * Get LDAP uid from profile.
     */
    public function ldapUid(array $profile): ?string
    {
        return self::get($this->_ldapUid, $profile);
    }

    /**
     * Get groups from profile.
     */
    public function groups(array $profile): ?array
    {
        $groups = self::get($this->_groups, $profile);

        // Explode by space if string
        if (\is_string($groups)) {
            $groups = array_filter(explode(' ', $groups));
        }

        return $groups;
    }

    /**
     * Get login_filter from profile.
     */
    public function login_filter(array $profile): ?array
    {
        $login_filter = self::get($this->_login_filter, $profile);

        // Explode by space if string
        if (\is_string($login_filter)) {
            $login_filter = array_filter(explode(' ', $login_filter));
        }

        return $login_filter;
    }

    /**
     * Get photo URL from profile.
     */
    public function photoUrl(array $profile): ?string
    {
        return self::get($this->_photoUrl, $profile);
    }

    /**
     * Get admin status from profile.
     */
    public function isAdmin(array $profile): ?string
    {
        return self::get($this->_isAdmin, $profile);
    }

    /**
     * Returns whether the OIDC response has the groups field in it.
     */
    public function hasGroups(array $profile)
    {
        return \array_key_exists($this->_groups, $profile);
    }

    /**
     * Returns whether the OIDC response has the login_filter field in it.
     */
    public function hasLoginFilter(array $profile)
    {
        return \array_key_exists($this->_login_filter, $profile);
    }

    /**
     * Returns whether OIDC should manage the admin role with `is_admin` attribute.
     */
    public function managesAdmin(): bool
    {
        return null !== $this->_isAdmin;
    }

    private static function get(string $attr, array $profile)
    {
        if (null !== $attr && \array_key_exists($attr, $profile)) {
            return $profile[$attr];
        }

        return null;
    }
}
