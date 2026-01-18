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

class Joomla3Helper implements CmsInterface
{

    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getName()
    {
        return "joomla";
    }

    public function getVersion()
    {

        $joomla_path = $this->path . 'libraries/src/Version.php';

        if (!file_exists($joomla_path)) {
            return false;
        }

        $contents = file_get_contents($joomla_path);

        $major = StringHelper::getStringBetween($contents, "const MAJOR_VERSION = ", ';');
        $minor = StringHelper::getStringBetween($contents, "const MINOR_VERSION = ", ';');
        $patch = StringHelper::getStringBetween($contents, "const PATCH_VERSION = ", ';');

        $version = "{$major}.{$minor}.{$patch}";

        if (!empty($version)) {
            return $version;
        }

        return false;
    }

}