<?php

namespace Ibrows\HmacBundle;

use Ibrows\HmacBundle\DependencyInjection\Security\Factory\HmacFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class IbrowsHmacBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new HmacFactory());
    }
}
