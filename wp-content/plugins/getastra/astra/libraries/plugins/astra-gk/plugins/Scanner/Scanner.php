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
 * Malware Scanner Plugin
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-03-10
 */

namespace GetAstra\Plugins;

use Curl\MultiCurl;
use GetAstra\Plugin;
use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;
use GetAstra\Plugins\Scanner\Helpers\StatusHelper;
use GetAstra\Plugins\Scanner\Migrations\ScannerSchema;
use GetAstra\Plugins\Scanner\Services\ScanEngine;
use Interop\Container\ContainerInterface;
use Slim\Http\Request;

if (!defined('ASTRAROOT')) {
    exit;
}

class Scanner extends Plugin
{
    protected $container;
    protected $options;

    public static function getSubscribedEvents()
    {
        return array('plugin.loaded' => 'onPluginsLoadEvent');
    }

    function onPluginsLoadEvent($event)
    {
    }

    function __construct(ContainerInterface $container)
    {
        parent::__construct($container);

        $this->container = $container;
        $this->options = $container->get('options');

        $this->setVersion("7.0.1");
        $this->fixMemoryLimits();

        $schema = new ScannerSchema($container);

        if (!$schema->exists()) {
            $schema->runInstall();
        }

        //$this->startScanIfRequired();

    }

    /*
        protected function startScanIfRequired()
        {
            $remoteScanRequest = (int)ConfigHelper::get('scanRequireRemoteStart', 0);
            ConfigHelper::set('scanRequireRemoteStart', 0);

            $math = (time() - strtotime(date('m/d/Y H:i:s', $remoteScanRequest))) < 600; //Request lasts for 10 minutes
            if ($remoteScanRequest && $math) {

                //$engine = new ScanEngine();
                StatusHelper::add(10, 'info', "Starting the remote scan");
                //$engine->go();

                $request = $this->container->get('request');

                try {
                    $cronURL = $request->getUri();
                    ConfigHelper::set('scanStartAttemptscanStartAttempt', time());

                    $multiCurl = new MultiCurl();
                    $multiCurl->setOpt(CURLOPT_SSL_VERIFYHOST, false);
                    $multiCurl->setOpt(CURLOPT_SSL_VERIFYPEER, false);
                    //$multiCurl->setRetry(3);
                    $multiCurl->setHeader('Referer', false);

                    $multiCurl->setOpt(CURLOPT_TIMEOUT_MS, 10);
                    //$multiCurl->setTimeout(0.01);
                    //$multiCurl->setTimeout(1);

                    $multiCurl->addGet($cronURL);

                    //TODO Notify SF about Scan Start
                } catch (\Exception $e) {
                    ConfigHelper::set('lastScanCompleted', $e->getMessage());
                    ConfigHelper::set('lastScanFailureType', 'scanner.callbackfailed');
                    return false;
                }

            }

        }
    */
    
    protected function fixMemoryLimits()
    {
        $maxMemory = @ini_get('memory_limit');
        $last = strtolower(substr($maxMemory, -1));
        $maxMemory = (int)$maxMemory;

        if ($last == 'g') {
            $maxMemory = $maxMemory * 1024 * 1024 * 1024;
        } else if ($last == 'm') {
            $maxMemory = $maxMemory * 1024 * 1024;
        } else if ($last == 'k') {
            $maxMemory = $maxMemory * 1024;
        }

        if ($maxMemory < 134217728 /* 128 MB */ && $maxMemory > 0 /* Unlimited */) {
            if (strpos(ini_get('disable_functions'), 'ini_set') === false) {
                @ini_set('memory_limit', '128M');
            }
        }
    }


}