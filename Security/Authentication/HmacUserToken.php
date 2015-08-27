<?php

namespace Ibrows\HmacBundle\Security\Authentication;


use Acquia\Hmac\Request\RequestInterface;
use Acquia\Hmac\Request\Symfony;
use Acquia\Hmac\SignatureInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Class HmacUserToken
 * @package Ibrows\HmacBundle\Security\Authentication
 */
class HmacUserToken extends AbstractToken
{
    /**
     * @var SignatureInterface
     */
    private $passedSignature;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var string
     */
    private $authenticationProviderKey;

    /**
     * @return string
     */
    public function getAuthenticationProviderKey()
    {
        return $this->authenticationProviderKey;
    }

    /**
     * @param string $authenticationProviderKey
     */
    public function setAuthenticationProviderKey($authenticationProviderKey)
    {
        $this->authenticationProviderKey = $authenticationProviderKey;
    }


    /**
     * @return SignatureInterface
     */
    public function getPassedSignature()
    {
        return $this->passedSignature;
    }

    /**
     * @param SignatureInterface $passedSignature
     */
    public function setPassedSignature($passedSignature)
    {
        $this->passedSignature = $passedSignature;
    }


    /**
     * @param Request $request
     * @return $this
     */
    public function setRequest($request)
    {
        $this->request = $request;
    }

    /**
     * @return Request
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @return RequestInterface
     */
    public function getRequestWrapper()
    {
        return new Symfony($this->request);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->getPassedSignature();
    }

}
