<?php

namespace OCA\OIDCLogin;

use OCA\Registration\AppInfo\Application;
use OCP\Authentication\IAlternativeLogin;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IRequest;
use OCP\IConfig;
use OCP\Util;

class OIDCLoginOption implements IAlternativeLogin {

	/** @var IURLGenerator */
	protected $url;
	/** @var IL10N */
	protected $l;
	/** @var Config */
	protected $config;
	/** @var IRequest */
	protected $request;

	public function __construct(IURLGenerator $url,
								IL10N $l,
								IConfig $config,
								IRequest $request) {
		$this->url = $url;
		$this->l = $l;
		$this->config = $config;
		$this->request = $request;
	}

	public function getLabel(): string
	{
		return $this->l->t($this->config->getSystemValue('oidc_login_button_text', 'OpenID Connect'));
	}

	public function getLink(): string
	{
		$redirectUrl = $this->request->getParam('redirect_url');
		$providerUrl = $this->url->linkToRoute('oidc_login.login.oidc', [
			'login_redirect_url' => $redirectUrl
		]);
		return $providerUrl;
	}

	public function getClass(): string
	{
		return 'oidc-button';
	}

	public function load(): void
	{
	}
}
