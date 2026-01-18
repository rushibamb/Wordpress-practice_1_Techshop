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
 * @date   2019-04-05
 */

namespace GetAstra\Helpers\Cms;

use GetAstra\Helpers\StringHelper;

class OpencartHelper
{

    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getName()
    {
        return "opencart";
    }

    public function getVersion()
    {

        $opencart_path = $this->path . 'index.php';

        if (!file_exists($opencart_path)) {
            return false;
        }

        $contents = file_get_contents($opencart_path);
        $version = StringHelper::getStringBetween($contents, "define('VERSION', '", "');");

        if (!empty($version)) {
            return $version;
        }

        return false;
    }

}