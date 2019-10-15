# OpenID Connect Basic

Make possible create users and login via OpenID Connect

## Config

You can use `'social_login_auto_redirect' => true` setting in `config.php` for auto redirect unauthorized users to social login if only one provider is configured.

### About Callback(Reply) Url
You can copy link from specific login button on login page and paste it on provider's website as callback url!
Some users may get strange reply(Callback) url error from provider even if you pasted the right url, that's because your nextcloud server may generate http urls when you are actually using https.
Please set 'overwriteprotocol' => 'https', in your config.php file.
