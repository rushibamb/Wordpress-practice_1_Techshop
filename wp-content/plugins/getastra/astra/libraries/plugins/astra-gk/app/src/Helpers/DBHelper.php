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
 * @date   2019-03-25
 */

namespace GetAstra\Helpers;

use Illuminate\Database\Capsule\Manager as DB;

class DBHelper
{

    public static function vacuumDB()
    {

        if (defined('ASTRA_DB_DRIVER') && ASTRA_DB_DRIVER == 'sqlite') {
            DB::select(DB::raw('VACUUM;'));
        }

    }
}