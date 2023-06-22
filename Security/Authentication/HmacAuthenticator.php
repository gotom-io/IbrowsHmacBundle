<?php

namespace Ibrows\HmacBundle\Security\Authentication;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class HmacAuthenticator extends AbstractAuthenticator
{

    public function __construct(
        private UserProviderInterface $userProvider,
        private string $providerKey,
    ) {

    }

    protected function retrieveUser(string $identifier): UserInterface
    {
        return $this->userProvider->loadUserByIdentifier($identifier);
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization') && str_starts_with($request->headers->get('Authorization'), $this->providerKey);
    }


    public function authenticate(Request $request): Passport
    {
        $requestSigner = new RequestSigner($this->providerKey);
        try {
            $passedSignature = $requestSigner->getSignature($request);
        } catch (MalformedRequestException $exception) {
            throw new CustomUserMessageAuthenticationException($exception->getMessage(), [], 401, $exception);
        }

        $comparison = (int) $passedSignature->compareTimestamp('+30 minutes');
        if (-1 === $comparison) {
            throw new CustomUserMessageAuthenticationException('Request is too old');
        }
        if (1 === $comparison) {
            throw new CustomUserMessageAuthenticationException('Request is too far in the future');
        }

        $userId = $passedSignature->getId();
        if (!$userId) {
            throw new CustomUserMessageAuthenticationException('No user id', []);

        }

        $user = $this->retrieveUser($userId);

        $requestSigner = new RequestSigner($this->providerKey);
        $requestSigner->setProvider($this->providerKey);
        $requestSignature = $requestSigner->signRequest($request, $user->getPassword());
        if (!$passedSignature->matches($requestSignature)) {
            throw new CustomUserMessageAuthenticationException('Signature not valid', [(string) $passedSignature, $requestSignature], 401);

        }

        return new SelfValidatingPassport(new UserBadge($userId, fn($userId) => $this->retrieveUser($userId)));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $errorMessage = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new JsonResponse($errorMessage, 401);
    }
}
