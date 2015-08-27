<?php

namespace Ibrows\HmacBundle\Security\Authentication;

use Acquia\Hmac\Exception\MalformedRequestException;
use Acquia\Hmac\Request\Symfony;
use Acquia\Hmac\RequestSigner;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class HmacAuthenticationListener implements ListenerInterface
{
    /**
     * @var TokenStorageInterface
     */
    private $securityContext;
    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;
    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var AuthenticationEntryPointInterface
     */
    private $authenticationEntryPoint;
    /**
     * @var string
     */
    private $authenticationProviderKey;
    /**
     * @var LoggerInterface
     */
    private $logger;


    /**
     * @var string The request header name containing the service label, id an signature
     */
    private $authenticationHeaderName;

    /**
     * @param TokenStorageInterface             $securityContext
     * @param AuthenticationManagerInterface    $authenticationManager
     * @param                                   $providerKey
     * @param                                   $authenticationProviderKey
     * @param AuthenticationEntryPointInterface $authenticationEntryPoint
     * @param LoggerInterface                   $logger
     */
    public function __construct(TokenStorageInterface $securityContext, AuthenticationManagerInterface $authenticationManager, $providerKey, $authenticationProviderKey, AuthenticationEntryPointInterface $authenticationEntryPoint = null, LoggerInterface $logger = null)
    {
        if (empty($providerKey)) {
            throw new \InvalidArgumentException('providerKey must not be empty.');
        }

        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->logger = $logger;
        $this->authenticationProviderKey = $authenticationProviderKey;
    }


    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $requestWrapper = new Symfony($request);
        $requestSigner = new RequestSigner();
        $requestSigner->setProvider($this->authenticationProviderKey);


        try {
            $passedSignature = $requestSigner->getSignature($requestWrapper);
            $token = new HmacUserToken();
            $token->setPassedSignature($passedSignature);
            $token->setRequest($request);
            $token->setAuthenticationProviderKey($this->providerKey);
            $authenticatedToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authenticatedToken);
        } catch (MalformedRequestException $exception) {
            $body = "\nMessage: " . $exception->getMessage();
            $body .= "\n\nUri: " . $request->getUri();
            $body .= "\n\nHeaders:\n" . $request->headers;
            $event->setResponse(new Response($body, 401));
        } catch (AuthenticationException $exception) {
            $body = "\nMessage: " . $exception->getMessage();
            $body .= "\n\nUri: " . $request->getUri();
            $body .= "\n\nHeaders:\n" . $request->headers;
            $event->setResponse(new Response($body, 401));
        }

    }


}
