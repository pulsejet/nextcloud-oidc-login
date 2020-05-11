# NextCloud OIDC Login

Make possible create users and login via one single OpenID Connect provider. Even though a fork of [nextcloud-social-login](https://github.com/zorn-v/nextcloud-social-login), it fundamentally differs in two ways - aims for simplistic, single provider login (and hence is very minimalastic), and it supports having LDAP as the primary user backend. This way, you can use OpenID Connect to login to Nextcloud while maintaining an LDAP backend with attributes with the LDAP plugin. Supports automatic discovery of endpoints through the OpenID Connect spec, with a single provider configuration attribute.

## Config

All configuration for the app is directly picked up from NextCloud's system configuration file (`config.php`). The following properties (with their descriptions) are valid configuration entries.

```php
$CONFIG = array (
    // Some NextCloud options that might make sense here
    'allow_user_to_change_display_name' => false,
    'lost_password_link' => 'disabled',

    // URL of provider. All other URLs are auto-discovered from .well-known
    'oidc_login_provider_url' => 'https://openid.example.com',

    // Client ID and secret registered with the providr
    'oidc_login_client_id' => 'application',
    'oidc_login_client_secret' => 'secret',

    // Automatically redirect the login page to the provider
    'oidc_login_auto_redirect' => false,

    // Redirect to this page after logging out the user
    'oidc_login_logout_url' => 'https://openid.example.com/thankyou',

    // Quota to assign if no quota is specified in the OIDC response
    'oidc_login_default_quota' => '1000000',

    // Login button text
    'oidc_login_button_text' => 'Log in with OpenID',

    // Attribute map for OIDC response. Available keys are:
    //   i)   id:       Unique identifier for username
    //   ii)  name:     Full name
    //   iii) mail:     Email address
    //   iv)  quota:    NextCloud storage quota
    //   v)   home:     Home directory location. A symlink or external storage to this location is used
    //   vi)  ldap_uid: LDAP uid to search for when running in proxy mode
    //
    // The attributes in the OIDC response are flattened by adding the nested
    // array key as the prefix and an underscore. Thus,
    //
    //     $profile = [
    //         'id' => 1234,
    //         'attributes' => [
    //             'uid' => 'myuid'
    //         ]
    //     ];
    //
    // would become,
    //
    //     $profile = [
    //         'id' => 1234,
    //         'attributes_uid' => 'myuid'
    //     ]
    //
    'oidc_login_attributes' => array (
        'id' => 'sub',
        'name' => 'name',
        'mail' => 'email',
        'quota' => 'ownCloudQuota',
        'home' => 'homeDirectory',
    ),

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
    'oidc_login_proxy_ldap' => false,

    // Disable creation of new users from OIDC login
    'oidc_login_disable_registration' => true,

    // Fallback to direct login if login from OIDC fails
    // Note that no error message will be displayed if enabled
    'oidc_login_redir_fallback' => false,

    // Use an alternative login page
    // This page will be php-included instead of an redirect if specified
    // In the example below, the PHP file `login.php` in `assets`
    // in nextcloud base directory will be included
    // Note: the PHP variable $OIDC_LOGIN_URL is available for redirect URI
    // Note: you may want to try setting `oidc_login_logout_url` to your
    // base URL if you face issues regarding re-login after logout
    'oidc_login_alt_login_page' => 'assets/login.php',
    
    // For development, you may disable TLS verification. Default value is `true`
    // which should be kept in production
    'oidc_login_tls_verify' => true,
);
```
### Usage with [Keycloak](https://www.keycloak.org/)
1. Create the NextCloud Client in a Keycloak Realm of your choosing.
	1. Set `Access type` to `confidential`  
	Note: The `Client Secret` will be in the newly created `Credentials` tab after saving.
	2. Add a `Valid Redirect uri` of `https://cloud.example.com/*`
	3. Add a `Mapper` to the Nextcloud OIDC Client 
		1. Set `Mapper Type` to `user attribute`
		2. Set `Name`, `User Attribute`, and `Token Claim Name` to `ownCloudQuota`
		3. Set `Claim JSON Type` as `string`.
2. Add a User `Attribute` to necessary user accounts in Keycloak.
	1. Set `Key` as `ownCloudQuota` and `Value` to your preferred limit.
3. Necessary `config.php` settings (differing from above)
```php
'oidc_login_provider_url' => 'https://keycloak.example.com/auth/realms/YOUR_REALM',
'oidc_login_auto_redirect' => true,
'oidc_login_redir_fallback' => true,
'oidc_login_logout_url' => 'https://keycloak.example.com/auth/realms/MY_REALM/protocol/openid-connect/logout?redirect_uri=https%3A%2F%2Fcloud.example.com%2F',
'oidc_login_attributes' => array(
	'id' => 'preferred_username',
	'mail' => 'email',
),
// If you are running Nextcloud behind a reverse proxy, make sure this is set
'overwriteprotocol' => 'https',
```

**Note:** If necessary, restart Nextcloud to clear the APCu cache for the config file.

**Note:** You can use the above `Mapper` method to map any arbitrary user attribute in Keycloak to output with standard userdata, allowing use of arbitrary fields for `id`, etc.
