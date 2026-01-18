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

class Drupal7Helper implements CmsInterface
{

    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getName()
    {
        return "drupal";
    }

    public function getVersion()
    {

        $ps_path = $this->path . 'includes/bootstrap.inc';

        if (!file_exists($ps_path)) {
            return false;
        }

        $contents = file_get_contents($ps_path);

        $version = StringHelper::getStringBetween($contents, "define('VERSION', '", "');");


        if (!empty($version)) {
            return $version;
        }

        return false;
    }

}