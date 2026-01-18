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
 * @date   2019-03-15
 */

namespace GetAstra\Plugins\Scanner\Helpers;

use GetAstra\Plugins\Scanner\Helpers\ConfigHelper;

class ServerHelper
{

    private static $lastErrorReporting = false;
    private static $lastDisplayErrors = false;

    public static function requestMaxMemory()
    {
        if (ConfigHelper::get('maxMem', false) && (int)ConfigHelper::get('maxMem') > 0) {
            $maxMem = (int)ConfigHelper::get('maxMem');
        } else {
            $maxMem = 256;
        }
        if (function_exists('memory_get_usage') && ((int)@ini_get('memory_limit') < $maxMem)) {
            self::iniSet('memory_limit', $maxMem . 'M');
        }
    }

    public static function iniSet($key, $val)
    {
        if (self::funcEnabled('ini_set')) {
            @ini_set($key, $val);
        }
    }

    public static function funcEnabled($func)
    {
        if (!function_exists($func)) {
            return false;
        }
        $disabled = explode(',', ini_get('disable_functions'));
        foreach ($disabled as $f) {
            if ($func == $f) {
                return false;
            }
        }
        return true;
    }

    public static function saveBaseUrlIfNotTest($url)
    {
        if (strpos($url, 'testAjax') === false) {
            ConfigHelper::set('baseUrl', $url, 'no');
        }

    }

    public static function formatBytes($bytes, $precision = 2)
    {
        $units = array('B', 'KB', 'MB', 'GB', 'TB');

        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);

        // Uncomment one of the following alternatives
        $bytes /= pow(1024, $pow);
        // $bytes /= (1 << (10 * $pow));

        return round($bytes, $precision) . ' ' . $units[$pow];
    }

    public static function errorsOff()
    {
        self::$lastErrorReporting = @ini_get('error_reporting');
        @error_reporting(0);
        self::$lastDisplayErrors = @ini_get('display_errors');
        self::iniSet('display_errors', 0);
    }

    public static function errorsOn()
    {
        @error_reporting(self::$lastErrorReporting);
        self::iniSet('display_errors', self::$lastDisplayErrors);
    }

    public static function fileTooBig($file)
    {
        self::errorsOff();
        $fh = @fopen($file, 'r');
        self::errorsOn();

        if (!$fh) {
            return false;
        }

        // Max size is 50 megs
        $offset = 52428800 + 1;
        $tooBig = false;
        try {
            if (@fseek($fh, $offset, SEEK_SET) === 0) {
                if (strlen(fread($fh, 1)) === 1) {
                    $tooBig = true;
                }
            } //Otherwise we couldn't seek there so it must be smaller
            fclose($fh);
            return $tooBig;
        } catch (\Exception $e) {
            return true;
        } //If we get an error don't scan this file, report it's too big.
    }

    public static function substr($string, $start, $length = null)
    {
        if ($length === null) {
            $length = self::strlen($string);
        }
        return self::callMBSafeStrFunction('substr', array(
            $string, $start, $length
        ));
    }

    public static function mbstring_binary_safe_encoding($reset = false)
    {
        static $encodings = array();
        static $overloaded = null;

        if (is_null($overloaded))
            $overloaded = function_exists('mb_internal_encoding') && (ini_get('mbstring.func_overload') & 2);

        if (false === $overloaded)
            return;

        if (!$reset) {
            $encoding = mb_internal_encoding();
            array_push($encodings, $encoding);
            mb_internal_encoding('ISO-8859-1');
        }

        if ($reset && $encodings) {
            $encoding = array_pop($encodings);
            mb_internal_encoding($encoding);
        }
    }

    public static function reset_mbstring_encoding()
    {
        self::mbstring_binary_safe_encoding(true);
    }

    public static function strlen($binary)
    {
        $args = func_get_args();
        return self::callMBSafeStrFunction('strlen', $args);
    }

    protected static function callMBSafeStrFunction($function, $args)
    {
        self::mbstring_binary_safe_encoding();
        $return = call_user_func_array($function, $args);
        self::reset_mbstring_encoding();
        return $return;
    }

    public static function potentialBinaryStringToHTML($string, $inline = false, $allowmb4 = false)
    {
        $output = '';

        if (!defined('ENT_SUBSTITUTE')) {
            define('ENT_SUBSTITUTE', 0);
        }

        $span = '<span class="hex-sequence">';
        if ($inline) {
            $span = '<span style="color:#587ECB">';
        }

        for ($i = 0; $i < self::strlen($string); $i++) {
            $c = $string[$i];
            $b = ord($c);
            if ($b < 0x20) {
                $output .= $span . '\x' . str_pad(dechex($b), 2, '0', STR_PAD_LEFT) . '</span>';
            } else if ($b < 0x80) {
                $output .= htmlspecialchars($c, ENT_QUOTES, 'ISO-8859-1');
            } else { //Assume multi-byte UTF-8
                $bytes = 0;
                $test = $b;

                while (($test & 0x80) > 0) {
                    $bytes++;
                    $test = (($test << 1) & 0xff);
                }

                $brokenUTF8 = ($i + $bytes > self::strlen($string) || $bytes == 1);
                if (!$brokenUTF8) { //Make sure we have all the bytes
                    for ($n = 1; $n < $bytes; $n++) {
                        $c2 = $string[$i + $n];
                        $b2 = ord($c2);
                        if (($b2 & 0xc0) != 0x80) {
                            $brokenUTF8 = true;
                            $bytes = $n;
                            break;
                        }
                    }
                }

                if (!$brokenUTF8) { //Ensure the byte sequences are within the accepted ranges: https://tools.ietf.org/html/rfc3629
                    /*
                     * UTF8-octets = *( UTF8-char )
                        * UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
                        * UTF8-1      = %x00-7F
                        * UTF8-2      = %xC2-DF UTF8-tail
                        * UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
                        *               %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
                        * UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
                        *               %xF4 %x80-8F 2( UTF8-tail )
                        * UTF8-tail   = %x80-BF
                     */

                    $testString = self::substr($string, $i, $bytes);
                    $regex = '/^(?:' .
                        '[\xc2-\xdf][\x80-\xbf]' . //UTF8-2
                        '|' . '\xe0[\xa0-\xbf][\x80-\xbf]' . //UTF8-3
                        '|' . '[\xe1-\xec][\x80-\xbf]{2}' .
                        '|' . '\xed[\x80-\x9f][\x80-\xbf]' .
                        '|' . '[\xee-\xef][\x80-\xbf]{2}';
                    if ($allowmb4) {
                        $regex .= '|' . '\xf0[\x90-\xbf][\x80-\xbf]{2}' . //UTF8-4
                            '|' . '[\xf1-\xf3][\x80-\xbf]{3}' .
                            '|' . '\xf4[\x80-\x8f][\x80-\xbf]{2}';
                    }
                    $regex .= ')$/';
                    if (!preg_match($regex, $testString)) {
                        $brokenUTF8 = true;
                    }
                }

                if ($brokenUTF8) {
                    $bytes = min($bytes, strlen($string) - $i);
                    for ($n = 0; $n < $bytes; $n++) {
                        $c2 = $string[$i + $n];
                        $b2 = ord($c2);
                        $output .= $span . '\x' . str_pad(dechex($b2), 2, '0', STR_PAD_LEFT) . '</span>';
                    }
                    $i += ($bytes - 1);
                } else {
                    $output .= htmlspecialchars(self::substr($string, $i, $bytes), ENT_QUOTES | ENT_SUBSTITUTE, 'ISO-8859-1');
                    $i += ($bytes - 1);
                }
            }
        }
        return $output;
    }

}