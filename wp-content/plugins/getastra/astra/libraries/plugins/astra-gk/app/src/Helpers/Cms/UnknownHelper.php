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


class UnknownHelper implements CmsInterface
{
    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getName(){
        return false;
    }

    public function getVersion(){
        return false;
    }
}