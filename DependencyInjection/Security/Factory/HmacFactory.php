<?php

namespace Ibrows\HmacBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class HmacFactory implements SecurityFactoryInterface
{

    /**
     * @param ContainerBuilder $container
     * @param string           $id
     * @param array            $config
     * @param string           $userProvider serviceId
     * @param  string          $defaultEntryPoint
     * @return array
     */
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerBaseId = 'ibrows_hmac.security.authentication.provider';
        $providerId = $providerBaseId . '.' . $id;
        $service = $container->setDefinition($providerId, new DefinitionDecorator($providerBaseId));
        $service->replaceArgument(0, new Reference($userProvider));
        $service->replaceArgument(2, $id);
        $service->replaceArgument(4, $config['authentication_provider_key']);

        $listenerBaseId = 'ibrows_hmac.security.authentication.listener';
        $listenerId = $listenerBaseId . '.' . $id;
        $service = $container->setDefinition($listenerId, new DefinitionDecorator($listenerBaseId));
        $service->replaceArgument(0, new Reference('security.context')); // need to avoid ServiceCircularReferenceException
        $service->replaceArgument(2, $id);
        $service->replaceArgument(3, $config['authentication_provider_key']);
        $service->replaceArgument(4, $defaultEntryPoint);

        return array($providerId, $listenerId, $defaultEntryPoint);
    }


    /**
     * @return string
     */
    public function getKey()
    {
        return 'ibrows_hmac';
    }


    /**
     * @return string
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

    /**
     * @param NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
            ->scalarNode('authentication_provider_key')->defaultValue('ibrows')->end()
            ->end();
    }

}
