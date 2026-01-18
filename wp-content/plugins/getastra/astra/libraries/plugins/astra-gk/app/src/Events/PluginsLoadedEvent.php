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
 * Event triggered when all plugins are loaded
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-03-10
 */

namespace GetAstra\Events;

use Symfony\Component\EventDispatcher\Event;

class PluginsLoadedEvent extends Event
{
    const NAME = 'plugins.loaded';

    protected $foo;

    public function __construct()
    {
        $this->foo = 'bar';
    }

    public function getFoo()
    {
        return $this->foo;
    }

}