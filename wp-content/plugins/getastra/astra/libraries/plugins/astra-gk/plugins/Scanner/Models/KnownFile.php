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
 * @date   2019-03-24
 */

namespace GetAstra\Plugins\Scanner\Models;

use Illuminate\Database\Eloquent\Model;

class KnownFile extends Model
{

    public $timestamps = false;
    protected $table = 'known_file_list';

}