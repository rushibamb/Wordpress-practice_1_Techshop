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

namespace GetAstra\Subscribers;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use GetAstra\Events\PluginsLoadedEvent;

class PluginsLoadedSubscriber implements EventSubscriberInterface
{

    public static function getSubscribedEvents()
    {
        return array(
            'plugin.MalwareScanner2.activated' => 'onPluginsLoadEvent',
        );
    }

    public function onPluginsLoadEvent(Event $event, $eventName)
    {
        //var_dump($eventName);
        // fetch event information here
        //echo "The value of the foo is :" . $event->getFoo() . "\n";
    }
}