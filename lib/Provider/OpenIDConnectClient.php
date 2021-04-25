<?php

namespace OCA\OIDCLogin\Provider;

require_once __DIR__ . '/../../3rdparty/autoload.php';

use OCP\ISession;
use OCP\IConfig;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    /** @var ISession */
    private $session;
    /** @var IConfig */
    private $config;
    /** @var string */
    private $appName;

    // Keycloak uses a default of 86400 seconds (1 day) as caching time for public keys
    // https://www.keycloak.org/docs/latest/securing_apps/index.html#_java_adapter_config
    private const DEFAULT_PUBLIC_KEY_CACHING_TIME = 86400;
    /** @var int */
    private $publicKeyCachingTime;

    // Avoid DoSing provider by issuing too many requests triggered by an attacker with bad kids
    // Keycloak uses a default of 10 seconds as a minimum time between JWKS requests
    // https://www.keycloak.org/docs/latest/securing_apps/index.html#_java_adapter_config
    private const DEFAULT_MIN_TIME_BETWEEN_JWKS_REQUESTS = 10;
    /** @var int */
    private $minTimeBetweenJwksRequests;

    // .well-known/openid-configuration shouldn't change much, so we default to 1 day.
    private const DEFAULT_WELL_KNOWN_CACHING_TIME = 86400;
    /** @var int */
    private $wellKnownCachingTime;

    public function __construct(
        ISession $session,
        IConfig $config,
        string $appName,
        $issuer = null)
    {
        $this->config = $config;
        parent::__construct(
            $this->config->getSystemValue('oidc_login_provider_url'),
            $this->config->getSystemValue('oidc_login_client_id'),
            $this->config->getSystemValue('oidc_login_client_secret'),
            $issuer
        );
        $this->session = $session;
        $this->appName = $appName;
        $this->publicKeyCachingTime = $this->config->getSystemValue('oidc_login_public_key_caching_time', self::DEFAULT_PUBLIC_KEY_CACHING_TIME);
        $this->minTimeBetweenJwksRequests = $this->config->getSystemValue('oidc_login_min_time_between_jwks_requests', self::DEFAULT_MIN_TIME_BETWEEN_JWKS_REQUESTS);
        $this->wellKnownCachingTime = $this->config->getSystemValue('oidc_login_well_known_caching_time', self::DEFAULT_WELL_KNOWN_CACHING_TIME);
    }
    /**
    * {@inheritdoc}
    */
    protected function getSessionKey($key)
    {
        return $this->session->get($key);
    }
    /**
    * {@inheritdoc}
    */
    protected function setSessionKey($key, $value)
    {
        $this->session->set($key, $value);
    }
    /**
    * {@inheritdoc}
    */
    protected function unsetSessionKey($key)
    {
        $this->session->remove($key);
    }
    /**
    * {@inheritdoc}
    */
    protected function startSession() {
        $this->session->set('is_oidc', 1);
    }
    /**
    * {@inheritdoc}
    */
    protected function commitSession() {
        $this->startSession();
    }

    /**
    * {@inheritdoc}
    */
    protected function fetchURL($url, $post_body = null, $headers = array()) {
        if(strpos($url, "/.well-known/openid-configuration") !== false) {
            // Cache .well-known
            return $this->getWellKnown($url);
        }
        if($url === $this->getProviderConfigValue("jwks_uri")) {
            // Cache jwks 
            return $this->getJWKs();
        }
        return parent::fetchURL($url, $post_body, $headers);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyJWTsignature($jwt) {
        try {
            return parent::verifyJWTsignature($jwt);
        } catch(\Exception $e) {
            // As we are caching the JWKs, we might not know the newest ones.
            // Thus we try verifying the signature first, but if that didn't work because the
            // key couldn't be found, we fetch new ones and try again.
            \OC::$server->getLogger()->debug("Error when verifying jwt {$e->getMessage()}");
            if(strpos($e->getMessage(), "Unable to find a key") !== false) {
                $this->getJWKs(true);
                return parent::verifyJWTsignature($jwt);
            }
            // Otherwise, rethrow error
            throw $e;
        }
    }

    /**
     * Fetches the well-known OIDC discovery endpoint and caches the result
     * for the configured amount of time. This reduces the requests required
     * to the provider. The openid-configuration shouldn't change much anyway.
     */
    private function getWellKnown(string $url) {
        $lastFetched = $this->config->getAppValue($this->appName, 'last_updated_well_known', 0);
        $age = time() - $lastFetched;
        
        if($age < $this->wellKnownCachingTime) {
            return $this->config->getAppValue($this->appName, 'well-known');
        }

        $resp = parent::fetchURL($url);

        $this->config->setAppValue($this->appName, 'well-known', $resp);
        $this->config->setAppValue($this->appName, 'last_updated_well_known', time());

        return $resp;
    }

    /**
     * Fetches new signing keys and stores them for the configured amount of time.
     * This reduces the requests required to the provider and increases the response time,
     * especially when using WebDAV.
     * 
     * @throws \Jumbojett\OpenIDConnectClientException
     */
    private function getJWKs($ignore_cache = false) {
        $lastFetched = $this->config->getAppValue($this->appName, 'last_updated_jwks', 0);

        $keyAge = time() - $lastFetched;

        // Use cache
        if(!$ignore_cache && $keyAge < $this->publicKeyCachingTime) {
            return $this->config->getAppValue($this->appName, 'jwks');
        }

        // Avoid DoSing the provider
        if(time() - $lastFetched < $this->minTimeBetweenJwksRequests) {
            \OC::$server->getLogger()->warning("Too many update signing key requests", ["app" => $this->appName]);
            throw new \Jumbojett\OpenIDConnectClientException("Too many update signing key requests");
        }

        // Avoid recursion
        $resp = parent::fetchURL($this->getProviderConfigValue('jwks_uri'));

        $this->config->setAppValue($this->appName, 'jwks', $resp);
        $this->config->setAppValue($this->appName, 'last_updated_jwks', time());

        return $resp;
    }

    /**
     * Validates the given bearer token by checking the validity of the tokens signature and claims.
     * 
     * @throws \Jumbojett\OpenIDConnectClientException
     */
    public function validateBearerToken($token) {
        $claims = $this->decodeJWT($token, 1);
        // There is no nonce when validating bearer token
        $claims->nonce = $this->getNonce();
        if(!$this->verifyJWTsignature($token)) {
            throw new \Jumbojett\OpenIDConnectClientException('Unable to verify signature');
        }
        if(!$this->verifyJWTclaims($claims)) {
            throw new \Jumbojett\OpenIDConnectClientException('Unable to verify claims');
        }
    }

    public function getTokenPayload($token) {
        return $this->decodeJWT($token, 1);
    }
}
