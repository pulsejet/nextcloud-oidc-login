# OpenID Connect Basic

Make possible create users and login via OpenID Connect

## Config

```php
$CONFIG = array (
    'oidc_login_provider_url' => 'https://openid.example.com',
    'oidc_login_client_id' => 'application',
    'oidc_login_client_secret' => 'secret',
    'oidc_login_auto_redirect' => false,
    'oidc_login_logout_url' => 'https://openid.example.com/thankyou',
);
```

### About Callback(Reply) Url
You can copy link from specific login button on login page and paste it on provider's website as callback url!
Some users may get strange reply(Callback) url error from provider even if you pasted the right url, that's because your nextcloud server may generate http urls when you are actually using https.
Please set 'overwriteprotocol' => 'https', in your config.php file.
