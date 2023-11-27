<?php

namespace OCA\OIDCLogin;

use OCP\Authentication\IAlternativeLogin;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;

class OIDCLoginOption implements IAlternativeLogin
{
    protected IURLGenerator $url;
    protected IL10N $l;
    protected IConfig $config;
    protected IRequest $request;

    public function __construct(
        IURLGenerator $url,
        IL10N $l,
        IConfig $config,
        IRequest $request
    ) {
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
        return $this->getLoginLink($this->request, $this->url);
    }

    public static function getLoginLink(IRequest $request, IURLGenerator $url): string
    {
        return $url->linkToRoute('oidc_login.login.oidc', [
            'login_redirect_url' => $request->getParam('redirect_url'),
        ]);
    }

    public function getClass(): string
    {
        return 'oidc-button';
    }

    public function load(): void {}
}
