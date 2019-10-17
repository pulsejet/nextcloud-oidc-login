# NextCloud Single OpenID Connect

Make possible create users and login via one single OpenID Connect provider. Even though a fork of [nextcloud-social-login](https://github.com/zorn-v/nextcloud-social-login), it fundamentally differs in two ways - aims for simplistic, single provider login (and hence is very minimalastic), and it supports having LDAP as the primary user backend. This way, you can use OpenID Connect to login to Nextcloud while maintaining an LDAP backend with attributes with the LDAP plugin. Supports automatic discovery of endpoints through the OpenID Connect spec, with a single provider configuration attribute.

## Config

```php
$CONFIG = array (
    'allow_user_to_change_display_name' => false,
    'lost_password_link' => 'disabled',

    'oidc_login_provider_url' => 'https://openid.example.com',
    'oidc_login_client_id' => 'application',
    'oidc_login_client_secret' => 'secret',
    'oidc_login_auto_redirect' => false,
    'oidc_login_logout_url' => 'https://openid.example.com/thankyou',
    'oidc_login_default_quota' => '1000000',
    'oidc_login_button_text' => 'Log in with OpenID',
    'oidc_login_attributes' => array (
        'id' => 'sub',
        'name' => 'name',
        'uid' => 'sub',
        'mail' => 'mail',
        'quota' => 'ownCloudQuota',
        'home' => 'homeDirectory',
    ),
    'oidc_login_proxy_ldap' => false,
    'oidc_login_disable_registration' => true,
);
```
