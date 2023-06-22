<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ibrows\HmacBundle\Tests\app;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Kernel;

/**
 * App Test Kernel for functional tests.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class AppKernel extends Kernel
{
    private string $rootConfig;


    public function __construct(string $rootConfig, string $environment, bool $debug)
    {
        $this->rootConfig = $rootConfig;
        $fs = new Filesystem();
        if (!$fs->isAbsolutePath($rootConfig) && !is_file($rootConfig = __DIR__.'/'.$rootConfig)) {
            throw new \InvalidArgumentException(sprintf('The root config "%s" does not exist.', $rootConfig));
        }

        parent::__construct($environment, $debug);
    }

    public function registerBundles(): iterable
    {
        return [
            new \Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
            new \Symfony\Bundle\SecurityBundle\SecurityBundle(),
            new \Ibrows\HmacBundle\IbrowsHmacBundle(),
        ];
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/'.Kernel::VERSION.'/cache/'.$this->environment;
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/'.Kernel::VERSION.'/logs';
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/' . $this->rootConfig);
    }
}
