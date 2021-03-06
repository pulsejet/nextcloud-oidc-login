<?php

namespace OCA\OIDCLogin\Provider;

require_once __DIR__ . '/../../3rdparty/autoload.php';

use OCP\ISession;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    /** @var ISession */
    private $session;
    public function __construct(
        ISession $session,
        $provider_url = null,
        $client_id = null,
        $client_secret = null,
        $issuer = null)
    {
        parent::__construct($provider_url, $client_id, $client_secret, $issuer);
        $this->session = $session;
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
}
