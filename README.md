# NextCloud OIDC Login

Make possible create users and login via one single OpenID Connect provider. Even though a fork of [nextcloud-social-login](https://github.com/zorn-v/nextcloud-social-login), it fundamentally differs in two ways - aims for simplistic, single provider login (and hence is very minimalastic), and it supports having LDAP as the primary user backend. This way, you can use OpenID Connect to login to Nextcloud while maintaining an LDAP backend with attributes with the LDAP plugin. Supports automatic discovery of endpoints through the OpenID Connect spec, with a single provider configuration attribute.

## Config

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
    //   v)   home:     Home directory location. A symlink to this location is used
    //   vi)  ldap_uid: LDAP uid to search for when running in proxy mode
    'oidc_login_attributes' => array (
        'id' => 'sub',
        'name' => 'name',
        'mail' => 'mail',
        'quota' => 'ownCloudQuota',
        'home' => 'homeDirectory',
    ),

    // Run in LDAP proxy mode
    // In this mode, instead of creating users of its own, OIDC login
    // will get the existing user from an LDAP database and only
    // perform authentication with OIDC. All user data will be derived
    // from the LDAP database instead of the OIDC user response
    'oidc_login_proxy_ldap' => false,

    // Disable creation of new users from OIDC login
    'oidc_login_disable_registration' => true,
);
```
