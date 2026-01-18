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
 * @date   2019-03-18
 */

namespace GetAstra\Plugins\Scanner\Transformers;

use League\Fractal\TransformerAbstract;
use GetAstra\Plugins\Scanner\Models\ScanStatus;

class ScanStatusTransformer extends TransformerAbstract
{

    /**
     * OptionTransformer constructor.
     *
     */
    public function __construct()
    {
    }

    public function transform(ScanStatus $status)
    {
        return [
            "id" => $status->id,
            "ctime" => $status->ctime,
            "level" => $status->level,
            "type" => $status->type,
            "msg" => $status->msg,
        ];
    }


}