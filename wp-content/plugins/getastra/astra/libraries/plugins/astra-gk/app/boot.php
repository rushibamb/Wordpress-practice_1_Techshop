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

class AstraBoot
{
    private $settings;

    function __construct($settings)
    {
        $this->settings = $settings;
    }

    public function check()
    {
        return 'ss';
    }

    protected function testDatabase()
    {


    }

    protected function createDatabase()
    {

        if (!is_writeable(CZ_DB_PATH . 'db')) {
            echo_debug('DB Folder is writable');
        } else {
            echo_debug('DB Folder is not writable');
        }

    }
}

if(!function_exists('hash_equals'))
{
    function hash_equals($str1, $str2)
    {
        if(strlen($str1) != strlen($str2))
        {
            return false;
        }
        else
        {
            $res = $str1 ^ $str2;
            $ret = 0;
            for($i = strlen($res) - 1; $i >= 0; $i--)
            {
                $ret |= ord($res[$i]);
            }
            return !$ret;
        }
    }
}


$boot = new AstraBoot($settings);
return $boot->check();


