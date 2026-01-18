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

class Magento2Helper implements CmsInterface
{

    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getName()
    {
        return "magento";
    }

    public function getVersion()
    {
        $magento_path = $this->path . 'vendor/magento/magento2-base/composer.json';

        if (!file_exists($magento_path)) {
            return false;
        }

        $contents = file_get_contents($magento_path);
        $version = StringHelper::getStringBetween($contents, '"version": "', '",');

        if (!empty($version)) {
            return $version;
        }

        return false;
    }

}