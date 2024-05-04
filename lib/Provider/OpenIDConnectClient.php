<?php

namespace OCA\OIDCLogin\Provider;

require_once __DIR__.'/../../3rdparty/autoload.php';

use OCP\IConfig;
use OCP\ISession;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    // Keycloak uses a default of 86400 seconds (1 day) as caching time for public keys
    // https://www.keycloak.org/docs/latest/securing_apps/index.html#_java_adapter_config
    private const DEFAULT_PUBLIC_KEY_CACHING_TIME = 86400;

    // Avoid DoSing provider by issuing too many requests triggered by an attacker with bad kids
    // Keycloak uses a default of 10 seconds as a minimum time between JWKS requests
    // https://www.keycloak.org/docs/latest/securing_apps/index.html#_java_adapter_config
    private const DEFAULT_MIN_TIME_BETWEEN_JWKS_REQUESTS = 10;

    private const WELL_KNOWN_CONFIGURATION = '/.well-known/openid-configuration';
    // .well-known/openid-configuration shouldn't change much, so we default to 1 day.
    private const DEFAULT_WELL_KNOWN_CACHING_TIME = 86400;

    // Don't skip Nextcloud HTTP proxy by default
    private const DEFAULT_SKIP_PROXY = false;

    private ISession $session;
    private IConfig $config;
    private string $appName;

    private int $publicKeyCachingTime;
    private int $minTimeBetweenJwksRequests;
    private int $wellKnownCachingTime;
    private ?bool $accessTokenIsJWT = null;

    public function __construct(
        string $appName,
        ISession $session,
        IConfig $config
    ) {
        $this->appName = $appName;
        $this->session = $session;
        $this->config = $config;

        parent::__construct(
            $this->config->getSystemValue('oidc_login_provider_url'),
            $this->config->getSystemValue('oidc_login_client_id'),
            $this->config->getSystemValue('oidc_login_client_secret'),
            null, // issuer
        );

        $codeChallengeMethod = $this->config->getSystemValue('oidc_login_code_challenge_method');
        if (!empty($codeChallengeMethod)) {
            $this->setCodeChallengeMethod($codeChallengeMethod);
        }

        // Get Nextcloud proxy from system value
        $proxy = $this->config->getSystemValue('proxy');

        // Enable proxy only if set in configuration and not skipped
        if (!empty($proxy) && !$this->config->getSystemValue('oidc_login_skip_proxy', self::DEFAULT_SKIP_PROXY)) {
            $this->setHttpProxy($proxy);
        }

        $this->publicKeyCachingTime = $this->config->getSystemValue('oidc_login_public_key_caching_time', self::DEFAULT_PUBLIC_KEY_CACHING_TIME);
        $this->minTimeBetweenJwksRequests = $this->config->getSystemValue('oidc_login_min_time_between_jwks_requests', self::DEFAULT_MIN_TIME_BETWEEN_JWKS_REQUESTS);
        $this->wellKnownCachingTime = $this->config->getSystemValue('oidc_login_well_known_caching_time', self::DEFAULT_WELL_KNOWN_CACHING_TIME);
    }

    /**
     * Verifies the signature of the given JWT string.
     *
     * @param string $jwt
     *
     * @return bool
     *
     * @throws \Jumbojett\OpenIDConnectClientException
     */
    public function verifyJWTsignature($jwt)
    {
        try {
            return parent::verifyJWTsignature($jwt);
        } catch (\Exception $e) {
            // As we are caching the JWKs, we might not know the newest ones.
            // Thus we try verifying the signature first, but if that didn't work because the
            // key couldn't be found, we fetch new ones and try again.
            \OC::$server->getLogger()->debug("Error when verifying jwt {$e->getMessage()}");
            if (false !== strpos($e->getMessage(), 'Unable to find a key')) {
                $this->getJWKs(true);

                return parent::verifyJWTsignature($jwt);
            }

            // Otherwise, rethrow error
            throw $e;
        }
    }

    /**
     * Validates the given bearer token by checking the validity of the tokens signature and claims.
     *
     * @throws \Jumbojett\OpenIDConnectClientException
     */
    public function validateBearerToken(string $token): void
    {
        if ($this->isJWT($token)) {
            $claims = $this->decodeJWT($token, 1);
        } else {
            $claims = $this->introspectToken($token);
        }

        // There is no nonce when validating bearer token
        $claims->nonce = $this->getNonce();
        if ($this->isJWT($token) && !$this->verifyJWTsignature($token)) {
            throw new \Jumbojett\OpenIDConnectClientException('Unable to verify signature');
        }
        if (!$this->verifyJWTclaims($claims)) {
            throw new \Jumbojett\OpenIDConnectClientException('Unable to verify claims');
        }
    }

    public function getProfile(): array
    {
        /** @var array $profile */
        $profile = null;

        if ($this->config->getSystemValue('oidc_login_use_id_token', false)) {
            // Get user information from ID Token
            $profile = $this->getIdTokenPayload();
        } else {
            // Get user information from OIDC
            $profile = $this->requestUserInfo();
        }

        return json_decode(json_encode($profile), true);
    }

    public function getTokenProfile(string $token): array
    {
        if ($this->isJWT($token)) {
            $jwt = $this->decodeJWT($token, 1);

            // Convert stdClass to array recursively
            return json_decode(json_encode($jwt), true);
        }

        $this->accessToken = $token;

        return $this->getProfile();
    }

    public function isJWT(string $token): bool
    {
        if (null === $this->accessTokenIsJWT) {
            try {
                if (substr_count($token, '.') < 2) {
                    $this->accessTokenIsJWT = false;

                    return false;
                }

                $parts = explode('.', $token);

                $joseHeader = json_decode(\Jumbojett\base64url_decode($parts[0]));
                if (null === $joseHeader || !property_exists($joseHeader, 'alg')) {
                    $this->accessTokenIsJWT = false;

                    return false;
                }

                if (null === json_decode(\Jumbojett\base64url_decode($parts[1]))) {
                    $this->accessTokenIsJWT = false;

                    return false;
                }

                $this->accessTokenIsJWT = true;
            } catch (\Exception $e) {
                $this->accessTokenIsJWT = false;
            }
        }

        return $this->accessTokenIsJWT;
    }

    /**
     * Gets the OIDC end session URL that will logout the user and redirect back to $post_logout_redirect_uri.
     *
     * @return string the OIDC logout URL
     */
    public function getEndSessionUrl(string $post_logout_redirect_uri): string
    {
        $id_token_hint = $this->getIdToken();
        $end_session_endpoint = null;

        try {
            $end_session_endpoint = $this->getProviderConfigValue('end_session_endpoint');
        } catch (\Exception $e) {
            throw new \Exception("end_session_endpoint could not be fetched.\n".
                                 "Your OIDC provider probably does not support logout.\n".
                                 'Set "oidc_login_end_session_redirect" => false in Nextcloud config.');
        }

        $signout_params = [
            'id_token_hint' => $id_token_hint,
            'post_logout_redirect_uri' => $post_logout_redirect_uri, ];
        $end_session_endpoint .= (false === strpos($end_session_endpoint, '?') ? '?' : '&').http_build_query($signout_params);

        return $end_session_endpoint;
    }

    protected function getSessionKey($key)
    {
        return $this->session->get($key);
    }

    protected function setSessionKey($key, $value)
    {
        $this->session->set($key, $value);
    }

    protected function unsetSessionKey($key)
    {
        $this->session->remove($key);
    }

    protected function startSession()
    {
        $this->session->set('is_oidc', 1);
    }

    protected function commitSession()
    {
        $this->startSession();
    }

    protected function fetchURL($url, $post_body = null, $headers = [])
    {
        // this must be an exact match as for IdentityServer the JWKS uri is a path below .well-knowm
        if (0 === substr_compare($url, self::WELL_KNOWN_CONFIGURATION, -\strlen(self::WELL_KNOWN_CONFIGURATION))) {
            // Cache .well-known
            return $this->getWellKnown($url);
        }
        if ($url === $this->getProviderConfigValue('jwks_uri')) {
            // Cache jwks
            return $this->getJWKs();
        }

        return parent::fetchURL($url, $post_body, $headers);
    }

    /**
     * Fetches the well-known OIDC discovery endpoint and caches the result
     * for the configured amount of time. This reduces the requests required
     * to the provider. The openid-configuration shouldn't change much anyway.
     */
    private function getWellKnown(string $url)
    {
        $lastFetched = $this->config->getAppValue($this->appName, 'last_updated_well_known', 0);
        $age = time() - $lastFetched;

        if ($age < $this->wellKnownCachingTime) {
            return $this->config->getAppValue($this->appName, 'well-known');
        }

        $resp = parent::fetchURL($url);

        // A successful response must use the 200 OK status code, so don't cache non-200 responses
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
        if (200 !== $this->getResponseCode()) {
            \OC::$server->getLogger()->warning('Got non-200 response code when querying well-known', ['app' => $this->appName]);

            return $resp;
        }

        $this->config->setAppValue($this->appName, 'well-known', $resp);
        $this->config->setAppValue($this->appName, 'last_updated_well_known', time());

        return $resp;
    }

    /**
     * Fetches new signing keys and stores them for the configured amount of time.
     * This reduces the requests required to the provider and increases the response time,
     * especially when using WebDAV.
     *
     * @param mixed $ignore_cache
     *
     * @throws \Jumbojett\OpenIDConnectClientException
     */
    private function getJWKs($ignore_cache = false)
    {
        $lastFetched = $this->config->getAppValue($this->appName, 'last_updated_jwks', 0);

        $keyAge = time() - $lastFetched;

        // Use cache
        if (!$ignore_cache && $keyAge < $this->publicKeyCachingTime) {
            return $this->config->getAppValue($this->appName, 'jwks');
        }

        // Avoid DoSing the provider
        if (time() - $lastFetched < $this->minTimeBetweenJwksRequests) {
            \OC::$server->getLogger()->warning('Too many update signing key requests', ['app' => $this->appName]);

            throw new \Jumbojett\OpenIDConnectClientException('Too many update signing key requests');
        }

        // Avoid recursion
        $resp = parent::fetchURL($this->getProviderConfigValue('jwks_uri'));

        // Don't cache non-200 responses.
        // As we didn't find any specification in the standard, what 200 code it should exactly be,
        // we accept the complete range.
        if ($this->getResponseCode() < 200 || $this->getResponseCode() >= 300) {
            \OC::$server->getLogger()->warning('Got non-200 response code when querying JWKs', ['app' => $this->appName]);

            return $resp;
        }

        $this->config->setAppValue($this->appName, 'jwks', $resp);
        $this->config->setAppValue($this->appName, 'last_updated_jwks', time());

        return $resp;
    }
}
