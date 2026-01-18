<?php
/**
 * This file is part of the Astra Security Suite
 *
 *  Copyright (c) 2019 (https://www.getastra.com/)
 *
 *  For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 *
 */

/**
 *
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-03-10
 */

namespace GetAstra;

use \Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Interop\Container\ContainerInterface;

abstract class Plugin implements EventSubscriberInterface
{
    /**
     * @var \Interop\Container\ContainerInterface
     */
    protected $container;

    /**
     * Plugin Version
     * @var string
     */
    protected $version;

    /**
     * @return string
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * @param string $version
     */
    public function setVersion($version)
    {
        $this->version = $version;
    }

    /**
     * Plugin constructor
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->version = '0.0.0';
    }

    public static function getSubscribedEvents()
    {
        return array();
    }

}