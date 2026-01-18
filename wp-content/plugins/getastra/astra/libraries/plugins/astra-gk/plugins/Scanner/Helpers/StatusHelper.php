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

use GetAstra\Helpers\OptionsHelper;
use GetAstra\Plugins\Scanner\Models\ScanStatus;

class StatusHelper
{
    public static function add($level, $type, $msg)
    {

        $isDebugMode = OptionsHelper::get('debugMode', false);

        if ($level > 3 && $level < 10 && (!$isDebugMode)) {
            return false;
        }


        $status = new ScanStatus;
        $status->ctime = sprintf('%.6f', microtime(true));
        $status->level = $level;
        $status->type = $type;
        $status->msg = $msg;
        $status->save();
    }

    public static function makeDuration($secs, $createExact = false)
    {
        $components = array();

        $months = floor($secs / (86400 * 30));
        $secs -= $months * 86400 * 30;
        $days = floor($secs / 86400);
        $secs -= $days * 86400;
        $hours = floor($secs / 3600);
        $secs -= $hours * 3600;
        $minutes = floor($secs / 60);
        $secs -= $minutes * 60;

        if ($months) {
            $components[] = self::pluralize($months, 'month');
            if (!$createExact) {
                $hours = $minutes = $secs = 0;
            }
        }
        if ($days) {
            $components[] = self::pluralize($days, 'day');
            if (!$createExact) {
                $minutes = $secs = 0;
            }
        }
        if ($hours) {
            $components[] = self::pluralize($hours, 'hour');
            if (!$createExact) {
                $secs = 0;
            }
        }
        if ($minutes) {
            $components[] = self::pluralize($minutes, 'minute');
        }
        if ($secs) {
            $components[] = self::pluralize($secs, 'second');
        }

        if (empty($components)) {
            $components[] = 'less than 1 second';
        }

        return implode(' ', $components);
    }

    public static function pluralize($m1, $t1, $m2 = false, $t2 = false)
    {
        if ($m1 != 1) {
            $t1 = $t1 . 's';
        }
        if ($m2 != 1) {
            $t2 = $t2 . 's';
        }
        if ($m1 && $m2) {
            return "$m1 $t1 $m2 $t2";
        } else {
            return "$m1 $t1";
        }
    }
}