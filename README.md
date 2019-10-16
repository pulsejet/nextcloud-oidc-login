# NextCloud Single OpenID Connect

Make possible create users and login via one single OpenID Connect provider. Fork of https://github.com/zorn-v/nextcloud-social-login

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
    'oidc_login_attributes' => array (
        'id' => 'sub',
        'name' => 'name',
        'uid' => 'sub',
        'mail' => 'mail',
        'quota' => 'ownCloudQuota',
        'home' => 'homeDirectory',
    ),
);
```

### About Callback(Reply) Url
You can copy link from specific login button on login page and paste it on provider's website as callback url!
Some users may get strange reply(Callback) url error from provider even if you pasted the right url, that's because your nextcloud server may generate http urls when you are actually using https.
Please set 'overwriteprotocol' => 'https', in your config.php file.
