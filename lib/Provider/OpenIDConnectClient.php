<?php

namespace OCA\OIDCLogin\Provider;

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
        // Do nothing
    }
    /**
    * {@inheritdoc}
    */
    protected function commitSession() {
        $this->startSession();
        // Do nothing
    }
}
