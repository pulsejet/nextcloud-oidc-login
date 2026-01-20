# Nextcloud OIDC Login

Provides user creation and login via one single OpenID Connect provider. Even though this is a fork of [nextcloud-social-login](https://github.com/zorn-v/nextcloud-social-login), it fundamentally differs in two ways - aims for simplistic, single provider login (and hence is very minimalistic), and it supports having LDAP as the primary user backend. This way, you can use OpenID Connect to login to Nextcloud while maintaining an LDAP backend with attributes with the LDAP plugin.

### Features

- Automatic [Identity provider endpoints discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- User creation at first login
- User profile update at login (name, email, avatar, groups etc.)
- Group creation
- Automatic redirection from the nextcloud login page to the Identity Provider login page
- WebDAV endpoints `Bearer` and `Basic` authentication

## Config

All configuration for the app is directly picked up from Nextcloud's system configuration file (`config.php`). The following properties (with their descriptions) are valid configuration entries.

```php
$CONFIG = array (
    // Some Nextcloud options that might make sense here
    'allow_user_to_change_display_name' => false,
    'lost_password_link' => 'disabled',

    // URL of provider. All other URLs are auto-discovered from .well-known
    'oidc_login_provider_url' => 'https://openid.example.com',

    // Client ID and secret registered with the provider
    'oidc_login_client_id' => 'application',
    'oidc_login_client_secret' => 'secret',

    // Automatically redirect the login page to the provider
    'oidc_login_auto_redirect' => false,

    // Redirect to this page after logging out the user
    'oidc_login_logout_url' => 'https://openid.example.com/thankyou',

    // If set to true the user will be redirected to the
    // logout endpoint of the OIDC provider after logout
    // in Nextcloud. After successfull logout the OIDC
    // provider will redirect back to 'oidc_login_logout_url' (MUST be set).
    'oidc_login_end_session_redirect' => false,

    // Quota to assign if no quota is specified in the OIDC response (bytes)
    //
    // NOTE: If you want to allow NextCloud to manage quotas, omit this option. Do not set it to
    // zero or -1 or ''.
    'oidc_login_default_quota' => '1000000000',

    // Login button text
    'oidc_login_button_text' => 'Log in with OpenID',

    // Hide the NextCloud password change form.
    'oidc_login_hide_password_form' => false,

    // Use ID Token instead of UserInfo
    'oidc_login_use_id_token' => false,

    // Attribute map for OIDC response. Available keys are:
    //   * id:           Unique identifier for username
    //   * name:         Full name
    //                      If set to null, existing display name won't be overwritten
    //   * mail:         Email address
    //                      If set to null, existing email address won't be overwritten
    //   * quota:        Nextcloud storage quota
    //   * home:         Home directory location. A symlink or external storage to this location is used
    //   * ldap_uid:     LDAP uid to search for when running in proxy mode
    //   * groups:       Array or space separated string of Nextcloud groups for the user.
    //                   Note that the name here corresponds to the GID of the group and not the display name
    //                   In the admin panel, the GID may be obtained from the URL when editing a group
    //   * login_filter: Array or space separated string. If 'oidc_login_filter_allowed_values' is
    //                      set, it is checked against these values.
    //   * photoURL:     The URL of the user avatar. The nextcloud server will download the picture
    //                      at user login. This may lead to security issues. Use with care.
    //                      This will only be effective if oidc_login_update_avatar is enabled.
    //   * is_admin:     If this value is truthy, the user is added to the admin group (optional)
    //
    // The attributes in the OIDC response are flattened by adding the nested
    // array key as the prefix and an underscore. Thus,
    //
    //     $profile = [
    //         'id' => 1234,
    //         'attributes' => [
    //             'uid' => 'myuid',
    //             'abc' => 'xyz'
    //         ],
    //         'list' => ['one', 'two']
    //     ];
    //
    // would become,
    //
    //     $profile = [
    //         'id' => 1234,
    //         'attributes' => [
    //             'uid' => 'myuid',
    //             'abc' => 'xyz'
    //         ],
    //         'attributes_uid' => 'myuid',
    //         'attributes_abc' => 'xyz',
    //         'list' => ['one', 'two'],
    //         'list_0' => 'one',
    //         'list_1' => 'two',
    //         'list_one' => 'one',
    //         'list_two' => 'two',
    //     ]
    //
    // https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    //
    // note: on Keycloak, OIDC name claim = "${given_name} ${family_name}" or one of them if any is missing
    //
    'oidc_login_attributes' => array (
        'id' => 'sub',
        'name' => 'name',
        'mail' => 'email',
        'quota' => 'ownCloudQuota',
        'home' => 'homeDirectory',
        'ldap_uid' => 'uid',
        'groups' => 'ownCloudGroups',
        'login_filter' => 'realm_access_roles',
        'photoURL' => 'picture',
        'is_admin' => 'ownCloudAdmin',
    ),

    // Default group to add users to (optional, defaults to nothing)
    'oidc_login_default_group' => 'oidc',

    // DEPRECATED: This option will be removed in a future release. Use
    // 'login_filter' and 'oidc_login_filter_allowed_values' instead.
    //
    // Allow only users in configured group(s) to access Nextcloud. In case the user
    // is not assigned to this group (read from oidc_login_attributes) the login
    // will not be allowed for this user.
    //
    // Must be specified as an array of groups that are allowed to access Nextcloud.
    // e.g. 'oidc_login_allowed_groups' => array('group1', 'group2')
    'oidc_login_allowed_groups' => null,

    // Allow only users in configured value(s) to access Nextcloud. In case the user
    // is not assigned to this value (read from oidc_login_attributes) the login
    // will not be allowed for this user.
    //
    // Must be specified as an array of values (e.g. roles) that are allowed to
    // access Nextcloud. e.g. 'oidc_login_filter_allowed_values' => array('role1', 'role2')
    'oidc_login_filter_allowed_values' => null,

    // Use external storage instead of a symlink to the home directory
    // Requires the files_external app to be enabled
    'oidc_login_use_external_storage' => false,

    // Set OpenID Connect scope
    'oidc_login_scope' => 'openid profile',

    // Run in LDAP proxy mode
    // In this mode, instead of creating users of its own, OIDC login
    // will get the existing user from an LDAP database and only
    // perform authentication with OIDC. All user data will be derived
    // from the LDAP database instead of the OIDC user response
    //
    // The `id` attribute in `oidc_login_attributes` must return the
    // "Internal Username" (see expert settings in LDAP integration)
    'oidc_login_proxy_ldap' => false,

    // Disable creation of users new to Nextcloud from OIDC login.
    // A user may be known to the IdP but not (yet) known to Nextcloud.
    // This setting controls what to do in this case.
    // - 'true' (default): if the user authenticates to the IdP but is not known to Nextcloud,
    //     then they will be returned to the login screen and not allowed entry;
    // - 'false': if the user authenticates but is not yet known to Nextcloud,
    //     then the user will be automatically created; note that with this setting,
    //     you will be allowing (or relying on) a third-party (the IdP) to create new users
    'oidc_login_disable_registration' => true,

    // Fallback to direct login if login from OIDC fails
    // Note that no error message will be displayed if enabled
    'oidc_login_redir_fallback' => false,

    // Use an alternative login page
    // This page will be php-included instead of a redirect if specified
    // For example, setting it to `assets/login.php` will use that file
    // in the nextcloud base directory
    // Note: the PHP variable $OIDC_LOGIN_URL is available for redirect URI
    // Note: you may want to try setting `oidc_login_logout_url` to your
    // base URL if you face issues regarding re-login after logout
    'oidc_login_alt_login_page' => false,

    // For development, you may disable TLS verification. Default value is `true`
    // which should be kept in production
    'oidc_login_tls_verify' => true,

    // If you get your groups from the oidc_login_attributes, you might want
    // to create them if they are not already existing, Default is `false`.
    'oidc_create_groups' => false,

    // Enable use of WebDAV via OIDC bearer token.
    'oidc_login_webdav_enabled' => false,

    // Enable authentication with user/password for DAV clients that do not
    // support token authentication (e.g. DAVx⁵)
    'oidc_login_password_authentication' => false,

    // The time in seconds used to cache public keys from provider.
    // The default value is 1 day.
    'oidc_login_public_key_caching_time' => 86400,

    // The minimum time in seconds to wait between requests to the jwks_uri endpoint.
    // Avoids that the provider will be DoSed when someone requests with unknown kids.
    // The default is 10 seconds.
    'oidc_login_min_time_between_jwks_requests' => 10,

    // The time in seconds used to cache the OIDC well-known configuration from the provider.
    // The default value is 1 day.
    'oidc_login_well_known_caching_time' => 86400,

    // If true, nextcloud will download user avatars on login.
    // This may lead to security issues as the server does not control
    // which URLs will be requested. Use with care.
    'oidc_login_update_avatar' => false,

    // If true, the default Nextcloud proxy won't be used to make internals OIDC call.
    // The default is false.
    'oidc_login_skip_proxy' => false,

    // Code challenge method for PKCE flow.
    // Possible values are:
    //	- 'S256'
    //	- 'plain'
    // The default value is empty, which won't apply the PKCE flow.
    'oidc_login_code_challenge_method' => '',
);
```
### Usage with [Keycloak](https://www.keycloak.org/)
1. Create a new Client for Nextcloud in a Keycloak Realm of your choosing.
    1. Set a `Client ID` and save.
    2. Set `Access type` to `confidential`
	3. Add a `Valid Redirect URI` e.g. `https://cloud.example.com/*`.
	4. Open the `Fine Grain OpenID Connect Configuration` dropdown and set `ID Token Signature Algorithm` to `RS256` and save.

2. Open your created Client and go to `Mappers`. (optional)
    1. Click `create` and set `Mapper Type` to `User Attribute`.
    2. Set `Name`, `User Attribute`, and `Token Claim Name` to `ownCloudQuota`.
    3. Set `Claim JSON Type` as `String`.
    4. Click `create` and set `Mapper Type` to `User Client Role`.
    5. Set `Name` and `Token Claim Name` to `ownCloudGroups` and select your Client ID.
    6. Set `Claim JSON Type` as `String`.
    7. Add or edit a User and go to `Attributes`.
    8. Add an `Attribute` by setting `Key` as `ownCloudQuota` and `Value` to your preferred limit (in bytes).
    9. Disable admin-level and user-level notifications of user group membership changes ("Settings > Administration > Activity" and "Settings > Personal > Activity", respectively). Repeat the user-level setting for all existing usersin your NextCloud instance, or invite them to do so on their own (e.g. via a NextCloud Announcement). Failure to complete this step may cause a "Token is invalid" exception on the login attempt following a group membership change. 
3. Necessary `config.php` settings (differing from above)
```php
'oidc_login_client_id' => 'nextcloud', // Client ID: Step 1
'oidc_login_client_secret' => 'secret', // Client Secret: Got to Clients -> Client -> Credentials
'oidc_login_provider_url' => 'https://keycloak.example.com/auth/realms/YOUR_REALM',
'oidc_login_end_session_redirect' => true, // Keycloak 18+
'oidc_login_logout_url' => 'https://cloud.example.com/apps/oidc_login/oidc', // Keycloak 18+
// 'oidc_login_logout_url' => 'https://keycloak.example.com/auth/realms/MY_REALM/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fcloud.example.com%2F', // Keycloak <18
'oidc_login_auto_redirect' => true,
'oidc_login_redir_fallback' => true,
'oidc_login_attributes' => array(
	'id' => 'preferred_username',
	'mail' => 'email',
),
// If you are running Nextcloud behind a reverse proxy, make sure this is set
'overwriteprotocol' => 'https',
```
4. (optional) Enable the [PKCE flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce) by setting the value `Clients` &rarr; `Your NC client` &rarr; `Advanced` &rarr; `Proof Key for Code Exchange Code Challenge Method` to `S256`. Please also set the appropriate configuration value accordingly:
```php
'oidc_login_code_challenge_method' => 'S256',
```

**Note:**
- If necessary, restart Nextcloud to clear the APCu cache for the config file.
- You can use the above `Mapper` method to map any arbitrary user attribute in Keycloak to output with standard userdata, allowing use of arbitrary fields for `id`, etc.

#### Configuration for WebDAV access

The underlying OIDC library ensures, that the `aud` property of the JWT token contains the configured Nextcloud client ID (config option `oidc_login_client_id`).
However, when obtaining an access token for a user with a client other than the Nextcloud client (e.g. using rclone), the `aud` property does not contain Nextclouds client ID.
Thus, the login would fail. The following steps ensure, that access tokens obtained with your client always contain your Nextcloud client in the `aud` property.

1. Go to `Client Scopes`
1. Add new client scope, call it `nextcloud`.
1. Under `Mappers` create a new mapper of type `Audience` and ensure that `Included Client Audience` contains your Nextcloud client. Click Save.
1. Finally, go to `Client > your-client-to-obtain-access-token > Client Scopes` and add the new `nextcloud` scope.

### Login Filter

The login filter feature allows to allow/deny access to nextcloud to users based on roles or similar claims. Use the `login_filter` in `oidc_login_attributes` to define, which claim holds the roles/permissions. For Keycloak this could be for example:

```
'login_filter' => 'realm_access_roles'
```

 Use `oidc_login_filter_allowed_values` to set, which roles/groups/whatever have access, eg.:

```
'oidc_login_filter_allowed_values' => array('nextcloudRole')
```

The login filter feature will replace the deprecated `oidc_login_allowed_groups`, as this was limited to using groups for access control. If you want to use a group as login filter you can still achieve the same by setting `login_filter` to your groups claim and setting a corresponding `oidc_login_filter_allowed_values`.


