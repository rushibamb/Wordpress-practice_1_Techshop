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

namespace GetAstra\Helpers;


class CommonHelper
{


    public static function bigRandomHex(){
        $bytes = openssl_random_pseudo_bytes(16);
        $hash = bin2hex($bytes);

        return $hash;
    }

}