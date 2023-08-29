# Development

This file contains some useful tips for developers of this app.

## Lint

```bash
composer install
composer lint
```

## Dummy OIDC Provider

Since the app uses OIDC, you may need a dummy provider to work with.
One way to do this is to use [this](https://github.com/pulsejet/stub-oidc-provider)
stub OIDC provider, which is a simple Node.js app that can be run locally.
The easiest way is to use Docker compose. You can find a sample `docker-compose.yml` below.

```yaml
app:
  image: nextcloud:latest
  restart: always
  ports:
    - 8025:80
  volumes:
    - nextcloud:/var/www/html

oidc:
  image: ghcr.io/pulsejet/stub-oidc-provider:master
  container_name: oidc
  environment:
    - PORT=9000
    - ISSUER=https://localhost:9000
    - STUB_CLIENT_ID=nextcloud
    - STUB_CLIENT_SECRET=secrethardtokeep
    - CALLBACK_URL=http://localhost:8025/apps/oidc_login/oidc
  ports:
    - 9000:9000
```

In your `config.php`, you need:

```php
'oidc_login_provider_url' => 'http://oidc:9000/',
'oidc_login_client_id' => 'nextcloud',
'oidc_login_client_secret' => 'secrethardtokeep',
'oidc_login_well_known_caching_time' => 0, // prevent unexpected surprises
'oidc_login_attributes' => array (
  'id' => 'pid',
  'name' => 'pid',
),
'oidc_login_disable_registration' => false,  // allows creation of new users
'oidc_login_tls_verify' => false,           // allows self-signed certificates
```

Finally, update `/etc/hosts` to point `oidc` to `localhost`:

```bash
echo "127.0.0.1 oidc" | sudo tee -a /etc/hosts
```

You should be able to use the test provider to login now.
