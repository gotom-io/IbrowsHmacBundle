<?php

namespace Ibrows\HmacBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;


class HmacFactory implements AuthenticatorFactoryInterface
{

    public function getKey(): string
    {
        return 'ibrows_hmac';
    }

    public function addConfiguration(NodeDefinition $builder): void
    {
        $builder
            ->children()
            ->scalarNode('authentication_provider_key')->defaultValue('ibrows')->end()
            ->end();
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $providerBaseId = 'ibrows_hmac.security.authenticator';
        $providerId = $providerBaseId . '.' . $firewallName;
        $service = $container->setDefinition($providerId, new ChildDefinition($providerBaseId));
        $service->replaceArgument(0, new Reference($userProviderId));
        $service->replaceArgument(1, $config['authentication_provider_key']);

        return $providerId;
    }
}
