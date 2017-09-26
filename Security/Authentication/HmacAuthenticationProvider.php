<?php

namespace Ibrows\HmacBundle\Security\Authentication;


use Acquia\Hmac\RequestSigner;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class HmacAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var bool
     */
    private $hideUserNotFoundExceptions;
    /**
     * @var UserCheckerInterface
     */
    private $userChecker;
    /**
     * @var string
     */
    private $providerKey;
    /**
     * @var
     */
    private $authenticationProviderKey;

    /**
     * Constructor.
     *
     * @param UserProviderInterface $userProvider An UserProviderInterface instance
     * @param UserCheckerInterface  $userChecker An UserCheckerInterface instance
     * @param string                $providerKey The provider key
     * @param bool                  $hideUserNotFoundExceptions Whether to hide user not found exception or not
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, $hideUserNotFoundExceptions = true, $authenticationProviderKey)
    {
        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->userChecker = $userChecker;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->userProvider = $userProvider;
        $this->authenticationProviderKey = $authenticationProviderKey;
    }


    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return;
        }
        /** @var $token HmacUserToken */
        $comparison = $token->getPassedSignature()->compareTimestamp('+30 minutes');
        if (-1 == $comparison) {
            throw new BadCredentialsException('Request is too old');
        } elseif (1 == $comparison) {
            throw new BadCredentialsException('Request is too far in the future');
        }
        $userId = $token->getPassedSignature()->getId();

        if (empty($userId)) {
            $userId = 'NONE_PROVIDED';
        }

        try {
            $user = $this->retrieveUser($userId, $token);
        } catch (UsernameNotFoundException $notFound) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $notFound);
            }
            $notFound->setUsername($userId);
            throw $notFound;
        }

        if (!$user instanceof UserInterface) {
            throw new AuthenticationServiceException('retrieveUser() must return a UserInterface.');
        }


        $this->userChecker->checkPreAuth($user);

        $requestSigner = new RequestSigner();
        $requestSigner->setProvider($this->authenticationProviderKey);
        $requestSignature = $requestSigner->signRequest($token->getRequestWrapper(), $user->getPassword());
        if (!$token->getPassedSignature()->matches($requestSignature)) {
            throw new BadCredentialsException('Signature not valid');
        }
        $this->userChecker->checkPostAuth($user);


        $authenticatedToken = new HmacUserToken($user->getRoles());
        $authenticatedToken->setRequest($token->getRequest());
        $authenticatedToken->setPassedSignature($token->getPassedSignature());
        $authenticatedToken->setAuthenticationProviderKey($token->getAuthenticationProviderKey());
        $authenticatedToken->setAttributes($token->getAttributes());

        return $authenticatedToken;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof HmacUserToken && $this->providerKey === $token->getAuthenticationProviderKey();
    }


    /**
     * {@inheritdoc}
     */
    protected function retrieveUser($username, HmacUserToken $token)
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);

            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
            }

            return $user;
        } catch (UsernameNotFoundException $notFound) {
            $notFound->setUsername($username);
            throw $notFound;
        } catch (\Exception $repositoryProblem) {
            $ex = new AuthenticationServiceException($repositoryProblem->getMessage(), 0, $repositoryProblem);
            $ex->setToken($token);
            throw $ex;
        }
    }


}
