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
 * @date   2019-03-14
 */

namespace GetAstra\Plugins\Scanner\Helpers;

use GetAstra\Helpers\OptionsHelper as Options;
use GetAstra\Plugins\Scanner\Services\FileScanner as msScanner;

class ConfigHelper
{

    const AUTOLOAD = 'yes';
    const DONT_AUTOLOAD = 'no';

    const TYPE_BOOL = 'boolean';
    const TYPE_INT = 'integer';
    const TYPE_FLOAT = 'double';
    const TYPE_DOUBLE = 'double';
    const TYPE_STRING = 'string';
    const TYPE_ARRAY = 'array';
    const TYPE_JSON = 'json';

    private static $prefix = "ms_";
    private static $options;

    public static $defaultConfig = array(


    );

    public static function get($name, $default = null, $allowedCache = true)
    {
        $option = Options::get(self::$prefix . $name, $default, $allowedCache);

        if (empty($option)) {
            if(isset(self::$defaultConfig[$name])){
                $option = self::$defaultConfig[$name]['value'];
            }
        }

        return $option;
    }

    public static function set($name, $value, $autoload = "yes")
    {
        return Options::set(self::$prefix . $name, $value, $autoload, 'scanner');
    }

    public static function delete($name){
        return Options::delete(self::$prefix . $name);
    }

    public static function increment($name)
    {
        return Options::increment(self::$prefix . $name);
    }


    public static function getScanLock(){

        $scanRunning = (int) self::get('scanRunning');
        $scanTimeout = (int) self::get('scanTimeoutMinutes');


        $timeoutCrossed = (time() - strtotime(date('m/d/Y H:i:s', $scanRunning))) > ($scanTimeout * 60);

        if ($scanRunning && !$timeoutCrossed) {
            return FALSE;
        }

        self::set('scanRunning', time());
        return true;
    }

    public static function clearScanLock(){
        self::set('scanRunning', '');
        self::updateScanStillRunning(false);

        //TODO Update SF4 about status
    }

    public static function updateScanStillRunning($running = true) {
        $timestamp = time();
        if (!$running) {
            $timestamp = 0;
        }

        self::set('scanLastStatusTime', $timestamp);
    }

    /**
     * Returns false if the scan has not been detected as timed out. If it has, it returns the timestamp of the last status update.
     *
     * @return bool|int
     */
    public static function lastScanStatusUpdate() {
        if (self::get('scanLastStatusTime', 0) === 0) {
            return false;
        }

        $threshold = self::get('scanFailureThreshold', 300);
        return (time() > self::get('scanLastStatusTime', 0) + $threshold) ? self::get('scanLastStatusTime', 0) : false;
    }

}